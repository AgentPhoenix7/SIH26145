"""Bounded capture-time state for source fanout detection."""

from __future__ import annotations

import math
from collections import Counter, OrderedDict, deque
from collections.abc import Hashable
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address
from typing import TypeVar

from sih26145.contracts.events import TcpSynAttemptV1

IPAddress = IPv4Address | IPv6Address
Endpoint = tuple[IPAddress, int]
CounterKey = TypeVar("CounterKey", bound=Hashable)


class TimestampRegressionError(ValueError):
    """An event timestamp was below the accepted capture-time watermark."""


class StateLimitExceeded(RuntimeError):
    """A new event would exceed a named hard state limit."""

    def __init__(self, limit_name: str) -> None:
        self.limit_name = limit_name
        super().__init__(f"state limit exceeded: {limit_name}")


@dataclass(frozen=True, slots=True)
class StateLimits:
    """Code-owned hard bounds for all scan-detector state."""

    max_active_sources: int = 4_096
    max_attempts_per_source: int = 4_096
    max_total_attempts: int = 100_000
    max_dedup_uids: int = 200_000
    max_cooldown_sources: int = 4_096
    dedup_ttl_seconds: float = 60.0

    def __post_init__(self) -> None:
        integer_limits = (
            "max_active_sources",
            "max_attempts_per_source",
            "max_total_attempts",
            "max_dedup_uids",
            "max_cooldown_sources",
        )
        for name in integer_limits:
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if not math.isfinite(self.dedup_ttl_seconds) or self.dedup_ttl_seconds <= 0:
            raise ValueError("dedup_ttl_seconds must be positive and finite")


@dataclass(frozen=True, slots=True)
class WindowSnapshot:
    """Post-insert measurements for one source in the active window."""

    source_ip: IPAddress
    start_ts: float
    end_ts: float
    attempts: int
    unique_hosts: int
    unique_ports: int
    unique_endpoints: int
    destination_samples: tuple[Endpoint, ...]


@dataclass(frozen=True, slots=True)
class _Attempt:
    ts: float
    source_ip: IPAddress
    destination_ip: IPAddress
    destination_port: int

    @property
    def endpoint(self) -> Endpoint:
        return self.destination_ip, self.destination_port


@dataclass(slots=True)
class _SourceState:
    attempts: deque[_Attempt] = field(default_factory=deque)
    destination_hosts: Counter[IPAddress] = field(default_factory=Counter)
    destination_ports: Counter[int] = field(default_factory=Counter)
    destination_endpoints: Counter[Endpoint] = field(default_factory=Counter)


class PortScanWindow:
    """Maintain deterministic, bounded rolling fanout evidence by source."""

    def __init__(
        self,
        *,
        window_seconds: float,
        limits: StateLimits | None = None,
    ) -> None:
        if not math.isfinite(window_seconds) or window_seconds <= 0:
            raise ValueError("window_seconds must be positive and finite")
        self.window_seconds = window_seconds
        self.limits = limits if limits is not None else StateLimits()
        self._watermark: float | None = None
        self._attempts: deque[_Attempt] = deque()
        self._sources: dict[IPAddress, _SourceState] = {}
        self._seen_uids: OrderedDict[str, float] = OrderedDict()

    @property
    def total_attempts(self) -> int:
        return len(self._attempts)

    @property
    def active_sources(self) -> int:
        return len(self._sources)

    @property
    def dedup_uids(self) -> int:
        return len(self._seen_uids)

    def debug_counts(self) -> dict[str, int]:
        """Return bounded aggregate counts without exposing observed values."""

        return {
            "active_sources": self.active_sources,
            "total_attempts": self.total_attempts,
            "dedup_uids": self.dedup_uids,
        }

    def observe(self, event: TcpSynAttemptV1) -> WindowSnapshot | None:
        """Accept one monotonic event and return its source's current evidence."""

        if self._watermark is not None and event.ts < self._watermark:
            raise TimestampRegressionError("event timestamp regressed below watermark")

        self._watermark = event.ts
        self._expire_attempts(event.ts)
        self._expire_uids(event.ts)

        if event.uid in self._seen_uids:
            return None

        source = event.src_ip
        state = self._sources.get(source)
        self._preflight_limits(state)

        if state is None:
            state = _SourceState()
            self._sources[source] = state

        attempt = _Attempt(
            ts=event.ts,
            source_ip=source,
            destination_ip=event.dst_ip,
            destination_port=event.dst_port,
        )
        self._attempts.append(attempt)
        state.attempts.append(attempt)
        state.destination_hosts[attempt.destination_ip] += 1
        state.destination_ports[attempt.destination_port] += 1
        state.destination_endpoints[attempt.endpoint] += 1
        self._seen_uids[event.uid] = event.ts
        return self._snapshot(source, state, event.ts)

    def _preflight_limits(self, state: _SourceState | None) -> None:
        if state is None and self.active_sources >= self.limits.max_active_sources:
            raise StateLimitExceeded("max_active_sources")
        if state is not None and len(state.attempts) >= self.limits.max_attempts_per_source:
            raise StateLimitExceeded("max_attempts_per_source")
        if self.total_attempts >= self.limits.max_total_attempts:
            raise StateLimitExceeded("max_total_attempts")
        if self.dedup_uids >= self.limits.max_dedup_uids:
            raise StateLimitExceeded("max_dedup_uids")

    def _expire_attempts(self, watermark: float) -> None:
        cutoff = watermark - self.window_seconds
        while self._attempts and self._attempts[0].ts < cutoff:
            expired = self._attempts.popleft()
            state = self._sources[expired.source_ip]
            source_expired = state.attempts.popleft()
            if source_expired is not expired:
                raise RuntimeError("scan state ordering invariant violated")
            self._decrement(state.destination_hosts, expired.destination_ip)
            self._decrement(state.destination_ports, expired.destination_port)
            self._decrement(state.destination_endpoints, expired.endpoint)
            if not state.attempts:
                del self._sources[expired.source_ip]

    def _expire_uids(self, watermark: float) -> None:
        cutoff = watermark - self.limits.dedup_ttl_seconds
        while self._seen_uids:
            _, first_seen = next(iter(self._seen_uids.items()))
            if first_seen >= cutoff:
                return
            self._seen_uids.popitem(last=False)

    @staticmethod
    def _decrement(counter: Counter[CounterKey], key: CounterKey) -> None:
        counter[key] -= 1
        if counter[key] == 0:
            del counter[key]

    @staticmethod
    def _endpoint_sort_key(endpoint: Endpoint) -> tuple[int, int, int]:
        ip, port = endpoint
        return ip.version, int(ip), port

    def _snapshot(
        self,
        source: IPAddress,
        state: _SourceState,
        end_ts: float,
    ) -> WindowSnapshot:
        samples = tuple(
            sorted(state.destination_endpoints, key=self._endpoint_sort_key)[:10]
        )
        return WindowSnapshot(
            source_ip=source,
            start_ts=state.attempts[0].ts,
            end_ts=end_ts,
            attempts=len(state.attempts),
            unique_hosts=len(state.destination_hosts),
            unique_ports=len(state.destination_ports),
            unique_endpoints=len(state.destination_endpoints),
            destination_samples=samples,
        )
