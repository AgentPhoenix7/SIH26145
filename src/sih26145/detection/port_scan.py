"""Evidence-first threshold detector for source fanout scans."""

from __future__ import annotations

import math
from collections import OrderedDict
from datetime import UTC, datetime
from typing import Annotated

from pydantic import Field, StrictInt

from sih26145.contracts.alerts import (
    AlertSource,
    AlertV1,
    AlertWindow,
    DestinationSample,
    DetectorIdentity,
    PortScanEvidence,
    ScanThresholdEvidence,
    Severity,
)
from sih26145.contracts.events import StrictModel, TcpSynAttemptV1
from sih26145.detection.scan_window import (
    IPAddress,
    PortScanWindow,
    StateLimitExceeded,
    StateLimits,
    WindowSnapshot,
)


class ScanConfig(StrictModel):
    """Validated user-facing scan rule configuration."""

    window_seconds: Annotated[float, Field(gt=0.0, allow_inf_nan=False)] = 10.0
    minimum_attempts: Annotated[StrictInt, Field(gt=0)] = 20
    minimum_unique_destination_ports: Annotated[StrictInt, Field(gt=0)] = 15
    minimum_unique_destination_hosts: Annotated[StrictInt, Field(gt=0)] = 15
    cooldown_seconds: Annotated[float, Field(ge=0.0, allow_inf_nan=False)] = 30.0


class PortScanDetector:
    """Apply the configured fanout rule and emit typed scan alerts."""

    def __init__(self, *, config: ScanConfig, limits: StateLimits | None = None) -> None:
        effective_limits = limits if limits is not None else StateLimits()
        effective_window_seconds = round(config.window_seconds, 6)
        max_source_attempts = min(
            effective_limits.max_attempts_per_source,
            effective_limits.max_total_attempts,
            effective_limits.max_dedup_uids,
        )
        if effective_window_seconds <= 0 or not math.isfinite(
            max_source_attempts / effective_window_seconds
        ):
            raise ValueError("window_seconds is too small for a finite attempt rate")
        thresholds = (
            config.minimum_attempts,
            config.minimum_unique_destination_ports,
            config.minimum_unique_destination_hosts,
        )
        if any(threshold > max_source_attempts for threshold in thresholds):
            raise ValueError("scan threshold exceeds effective state capacity")
        if effective_window_seconds > effective_limits.dedup_ttl_seconds:
            raise ValueError("window_seconds exceeds the UID deduplication TTL")

        self.config = config.model_copy(update={"window_seconds": effective_window_seconds})
        self.limits = effective_limits
        self._window = PortScanWindow(
            window_seconds=self.config.window_seconds,
            limits=self.limits,
        )
        self._last_alert_by_source: OrderedDict[IPAddress, float] = OrderedDict()

    @property
    def cooldown_entries(self) -> int:
        return len(self._last_alert_by_source)

    def process(self, event: TcpSynAttemptV1) -> AlertV1 | None:
        """Process one validated SYN event and possibly return one alert."""

        snapshot = self._window.observe(event)
        self._expire_cooldowns(event.ts)
        if snapshot is None or not self._crosses_threshold(snapshot):
            return None

        last_alert_ts = self._last_alert_by_source.get(event.src_ip)
        if last_alert_ts is not None and event.ts - last_alert_ts < self.config.cooldown_seconds:
            return None

        if (
            event.src_ip not in self._last_alert_by_source
            and self.cooldown_entries >= self.limits.max_cooldown_sources
        ):
            self._window.rollback_last_observation(event)
            raise StateLimitExceeded("max_cooldown_sources")

        alert = self._build_alert(event, snapshot)
        self._last_alert_by_source[event.src_ip] = event.ts
        return alert

    def _expire_cooldowns(self, watermark: float) -> None:
        while self._last_alert_by_source:
            _, last_alert_ts = next(iter(self._last_alert_by_source.items()))
            if watermark - last_alert_ts < self.config.cooldown_seconds:
                return
            self._last_alert_by_source.popitem(last=False)

    def _crosses_threshold(self, snapshot: WindowSnapshot) -> bool:
        return snapshot.attempts >= self.config.minimum_attempts and (
            snapshot.unique_ports >= self.config.minimum_unique_destination_ports
            or snapshot.unique_hosts >= self.config.minimum_unique_destination_hosts
        )

    def _build_alert(
        self,
        event: TcpSynAttemptV1,
        snapshot: WindowSnapshot,
    ) -> AlertV1:
        confidence = self._confidence(snapshot)
        severity = self._severity(confidence)
        start = datetime.fromtimestamp(snapshot.start_ts, UTC)
        end = datetime.fromtimestamp(snapshot.end_ts, UTC)
        thresholds = ScanThresholdEvidence(
            minimum_attempts=self.config.minimum_attempts,
            minimum_unique_destination_ports=(self.config.minimum_unique_destination_ports),
            minimum_unique_destination_hosts=self.config.minimum_unique_destination_hosts,
        )
        samples = [DestinationSample(ip=ip, port=port) for ip, port in snapshot.destination_samples]
        evidence = PortScanEvidence(
            deduplicated_attempts=snapshot.attempts,
            unique_destination_hosts=snapshot.unique_hosts,
            unique_destination_ports=snapshot.unique_ports,
            unique_destination_endpoints=snapshot.unique_endpoints,
            attempt_rate_per_second=snapshot.attempts / self.config.window_seconds,
            observed_span_seconds=(end - start).total_seconds(),
            thresholds=thresholds,
            destination_samples=samples,
        )
        return AlertV1(
            timestamp=end,
            flow_id=event.uid,
            threat_class="PORT_SCAN",
            protocol="tcp",
            confidence=confidence,
            severity=severity,
            detector=DetectorIdentity(name="port_scan_window", version="1.0.0"),
            source=AlertSource(ip=event.src_ip),
            window=AlertWindow(
                start=start,
                end=end,
                configured_seconds=self.config.window_seconds,
            ),
            evidence=evidence,
        )

    def _confidence(self, snapshot: WindowSnapshot) -> float:
        attempt_strength = min(
            snapshot.attempts / (2 * self.config.minimum_attempts),
            1.0,
        )
        fanout_strength = min(
            max(
                snapshot.unique_ports / self.config.minimum_unique_destination_ports,
                snapshot.unique_hosts / self.config.minimum_unique_destination_hosts,
            )
            / 2,
            1.0,
        )
        return round(0.50 + 0.25 * attempt_strength + 0.25 * fanout_strength, 4)

    @staticmethod
    def _severity(confidence: float) -> Severity:
        if confidence < 0.85:
            return Severity.MEDIUM
        if confidence < 0.95:
            return Severity.HIGH
        return Severity.CRITICAL
