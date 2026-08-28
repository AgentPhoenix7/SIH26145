"""Bounded destination-centric SYN-flood detection and evidence."""

from __future__ import annotations

import math
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated

from pydantic import Field, StrictInt

from sih26145.contracts.alerts import (
    AlertSource,
    AlertWindow,
    DetectorIdentity,
    Severity,
    SynFloodAlertV1,
    SynFloodEvidence,
    SynFloodThresholdEvidence,
    TargetEndpoint,
)
from sih26145.contracts.events import StrictModel, TcpSynAttemptV1
from sih26145.detection.scan_window import (
    Endpoint,
    IPAddress,
    StateLimitExceeded,
    TimestampRegressionError,
)


@dataclass(frozen=True, slots=True)
class SynFloodStateLimits:
    """Code-owned hard bounds for all SYN-flood detector state."""

    max_active_targets: int = 4_096
    max_events_per_target: int = 8_192
    max_total_events: int = 100_000
    max_dedup_uids: int = 200_000
    max_cooldown_targets: int = 4_096
    dedup_ttl_seconds: float = 60.0

    def __post_init__(self) -> None:
        integer_limits = (
            "max_active_targets",
            "max_events_per_target",
            "max_total_events",
            "max_dedup_uids",
            "max_cooldown_targets",
        )
        for name in integer_limits:
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if not math.isfinite(self.dedup_ttl_seconds) or self.dedup_ttl_seconds <= 0:
            raise ValueError("dedup_ttl_seconds must be positive and finite")


@dataclass(frozen=True, slots=True)
class SynFloodSnapshot:
    """Post-insert measurements for one target in the active window."""

    target: Endpoint
    start_ts: float
    end_ts: float
    events: int
    unique_sources: int
    source_ip_entropy_bits: float
    source_samples: tuple[IPAddress, ...]


@dataclass(frozen=True, slots=True)
class _SynObservation:
    ts: float
    source_ip: IPAddress
    target: Endpoint


@dataclass(slots=True)
class _TargetState:
    observations: deque[_SynObservation] = field(default_factory=deque)
    sources: Counter[IPAddress] = field(default_factory=Counter)


class SynFloodWindow:
    """Maintain deterministic, bounded rolling SYN evidence by target."""

    def __init__(
        self,
        *,
        window_seconds: float,
        limits: SynFloodStateLimits | None = None,
    ) -> None:
        if not math.isfinite(window_seconds) or window_seconds <= 0:
            raise ValueError("window_seconds must be positive and finite")
        self.window_seconds = window_seconds
        self.limits = limits if limits is not None else SynFloodStateLimits()
        self._watermark: float | None = None
        self._observations: deque[_SynObservation] = deque()
        self._targets: dict[Endpoint, _TargetState] = {}
        self._seen_uids: OrderedDict[str, float] = OrderedDict()

    @property
    def total_events(self) -> int:
        return len(self._observations)

    @property
    def active_targets(self) -> int:
        return len(self._targets)

    @property
    def dedup_uids(self) -> int:
        return len(self._seen_uids)

    def debug_counts(self) -> dict[str, int]:
        """Return bounded aggregate counts without exposing observed values."""

        return {
            "active_targets": self.active_targets,
            "total_events": self.total_events,
            "dedup_uids": self.dedup_uids,
        }

    def observe(self, event: TcpSynAttemptV1) -> SynFloodSnapshot | None:
        """Accept one monotonic event and return its target's current evidence."""

        if self._watermark is not None and event.ts < self._watermark:
            raise TimestampRegressionError("event timestamp regressed below watermark")

        self._watermark = event.ts
        self._expire_observations(event.ts)
        self._expire_uids(event.ts)

        if event.uid in self._seen_uids:
            return None

        target = (event.dst_ip, event.dst_port)
        state = self._targets.get(target)
        self._preflight_limits(state)
        if state is None:
            state = _TargetState()
            self._targets[target] = state

        observation = _SynObservation(
            ts=event.ts,
            source_ip=event.src_ip,
            target=target,
        )
        self._observations.append(observation)
        state.observations.append(observation)
        state.sources[event.src_ip] += 1
        self._seen_uids[event.uid] = event.ts
        return self._snapshot(target, state, event.ts)

    def rollback_last_observation(self, event: TcpSynAttemptV1) -> None:
        """Undo the immediately preceding accepted event after detector rejection."""

        if not self._observations:
            raise RuntimeError("no SYN-flood observation available to roll back")
        target = (event.dst_ip, event.dst_port)
        observation = self._observations[-1]
        state = self._targets.get(target)
        last_uid = next(reversed(self._seen_uids), None)
        if (
            observation.ts != event.ts
            or observation.source_ip != event.src_ip
            or observation.target != target
            or state is None
            or not state.observations
            or state.observations[-1] is not observation
            or last_uid != event.uid
        ):
            raise RuntimeError("SYN-flood rollback ordering invariant violated")

        self._observations.pop()
        state.observations.pop()
        self._decrement(state.sources, observation.source_ip)
        if not state.observations:
            del self._targets[target]
        self._seen_uids.popitem(last=True)

    def _preflight_limits(self, state: _TargetState | None) -> None:
        if state is None and self.active_targets >= self.limits.max_active_targets:
            raise StateLimitExceeded("max_active_targets")
        if state is not None and len(state.observations) >= self.limits.max_events_per_target:
            raise StateLimitExceeded("max_events_per_target")
        if self.total_events >= self.limits.max_total_events:
            raise StateLimitExceeded("max_total_events")
        if self.dedup_uids >= self.limits.max_dedup_uids:
            raise StateLimitExceeded("max_dedup_uids")

    def _expire_observations(self, watermark: float) -> None:
        cutoff = watermark - self.window_seconds
        while self._observations and self._observations[0].ts < cutoff:
            expired = self._observations.popleft()
            state = self._targets[expired.target]
            target_expired = state.observations.popleft()
            if target_expired is not expired:
                raise RuntimeError("SYN-flood state ordering invariant violated")
            self._decrement(state.sources, expired.source_ip)
            if not state.observations:
                del self._targets[expired.target]

    def _expire_uids(self, watermark: float) -> None:
        cutoff = watermark - self.limits.dedup_ttl_seconds
        while self._seen_uids:
            _, first_seen = next(iter(self._seen_uids.items()))
            if first_seen >= cutoff:
                return
            self._seen_uids.popitem(last=False)

    @staticmethod
    def _decrement(counter: Counter[IPAddress], key: IPAddress) -> None:
        counter[key] -= 1
        if counter[key] == 0:
            del counter[key]

    @staticmethod
    def _ip_sort_key(address: IPAddress) -> tuple[int, int]:
        return address.version, int(address)

    def _snapshot(
        self,
        target: Endpoint,
        state: _TargetState,
        end_ts: float,
    ) -> SynFloodSnapshot:
        events = len(state.observations)
        entropy = -sum(
            (count / events) * math.log2(count / events) for count in state.sources.values()
        )
        samples = tuple(sorted(state.sources, key=self._ip_sort_key)[:10])
        return SynFloodSnapshot(
            target=target,
            start_ts=state.observations[0].ts,
            end_ts=end_ts,
            events=events,
            unique_sources=len(state.sources),
            source_ip_entropy_bits=entropy,
            source_samples=samples,
        )


class SynFloodConfig(StrictModel):
    """Validated user-facing SYN-flood rule configuration."""

    window_seconds: Annotated[float, Field(gt=0.0, allow_inf_nan=False)] = 10.0
    minimum_syn_events: Annotated[StrictInt, Field(gt=0)] = 100
    minimum_unique_sources: Annotated[StrictInt, Field(gt=0)] = 20
    cooldown_seconds: Annotated[float, Field(ge=0.0, allow_inf_nan=False)] = 30.0


class SynFloodDetector:
    """Apply the configured destination-rate rule and emit typed alerts."""

    def __init__(
        self,
        *,
        config: SynFloodConfig,
        limits: SynFloodStateLimits | None = None,
    ) -> None:
        effective_limits = limits if limits is not None else SynFloodStateLimits()
        effective_window_seconds = round(config.window_seconds, 6)
        max_target_events = min(
            effective_limits.max_events_per_target,
            effective_limits.max_total_events,
            effective_limits.max_dedup_uids,
        )
        if effective_window_seconds <= 0 or not math.isfinite(
            max_target_events / effective_window_seconds
        ):
            raise ValueError("window_seconds is too small for a finite SYN rate")
        if config.minimum_syn_events > max_target_events:
            raise ValueError("SYN event threshold exceeds effective state capacity")
        if config.minimum_unique_sources > max_target_events:
            raise ValueError("unique-source threshold exceeds effective state capacity")
        if effective_window_seconds > effective_limits.dedup_ttl_seconds:
            raise ValueError("window_seconds exceeds the UID deduplication TTL")

        self.config = config.model_copy(update={"window_seconds": effective_window_seconds})
        self.limits = effective_limits
        self._window = SynFloodWindow(
            window_seconds=self.config.window_seconds,
            limits=self.limits,
        )
        self._last_alert_by_target: OrderedDict[Endpoint, float] = OrderedDict()

    @property
    def cooldown_entries(self) -> int:
        return len(self._last_alert_by_target)

    def process(self, event: TcpSynAttemptV1) -> SynFloodAlertV1 | None:
        """Process one validated SYN event and possibly return one alert."""

        snapshot = self._window.observe(event)
        self._expire_cooldowns(event.ts)
        if snapshot is None or not self._crosses_threshold(snapshot):
            return None

        target = snapshot.target
        last_alert_ts = self._last_alert_by_target.get(target)
        if last_alert_ts is not None and event.ts - last_alert_ts < self.config.cooldown_seconds:
            return None

        if (
            target not in self._last_alert_by_target
            and self.cooldown_entries >= self.limits.max_cooldown_targets
        ):
            self._window.rollback_last_observation(event)
            raise StateLimitExceeded("max_cooldown_targets")

        alert = self._build_alert(event, snapshot)
        self._last_alert_by_target[target] = event.ts
        return alert

    def _expire_cooldowns(self, watermark: float) -> None:
        while self._last_alert_by_target:
            _, last_alert_ts = next(iter(self._last_alert_by_target.items()))
            if watermark - last_alert_ts < self.config.cooldown_seconds:
                return
            self._last_alert_by_target.popitem(last=False)

    def _crosses_threshold(self, snapshot: SynFloodSnapshot) -> bool:
        return (
            snapshot.events >= self.config.minimum_syn_events
            and snapshot.unique_sources >= self.config.minimum_unique_sources
        )

    def _build_alert(
        self,
        event: TcpSynAttemptV1,
        snapshot: SynFloodSnapshot,
    ) -> SynFloodAlertV1:
        confidence = self._confidence(snapshot)
        start = datetime.fromtimestamp(snapshot.start_ts, UTC)
        end = datetime.fromtimestamp(snapshot.end_ts, UTC)
        evidence = SynFloodEvidence(
            deduplicated_syn_events=snapshot.events,
            unique_sources=snapshot.unique_sources,
            source_ip_entropy_bits=snapshot.source_ip_entropy_bits,
            syn_rate_per_second=snapshot.events / self.config.window_seconds,
            observed_span_seconds=(end - start).total_seconds(),
            target=TargetEndpoint(ip=snapshot.target[0], port=snapshot.target[1]),
            thresholds=SynFloodThresholdEvidence(
                minimum_syn_events=self.config.minimum_syn_events,
                minimum_unique_sources=self.config.minimum_unique_sources,
            ),
            source_samples=list(snapshot.source_samples),
        )
        return SynFloodAlertV1(
            timestamp=end,
            flow_id=event.uid,
            threat_class="SYN_FLOOD",
            protocol="tcp",
            confidence=confidence,
            severity=self._severity(confidence),
            detector=DetectorIdentity(name="syn_flood_window", version="1.0.0"),
            source=AlertSource(ip=event.src_ip),
            window=AlertWindow(
                start=start,
                end=end,
                configured_seconds=self.config.window_seconds,
            ),
            evidence=evidence,
        )

    def _confidence(self, snapshot: SynFloodSnapshot) -> float:
        event_strength = min(
            snapshot.events / (2 * self.config.minimum_syn_events),
            1.0,
        )
        source_strength = min(
            snapshot.unique_sources / (2 * self.config.minimum_unique_sources),
            1.0,
        )
        return round(0.50 + 0.25 * event_strength + 0.25 * source_strength, 4)

    @staticmethod
    def _severity(confidence: float) -> Severity:
        if confidence < 0.85:
            return Severity.MEDIUM
        if confidence < 0.95:
            return Severity.HIGH
        return Severity.CRITICAL
