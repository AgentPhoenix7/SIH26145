"""Typed common alert contract with port-scan evidence validation."""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    Field,
    IPvAnyAddress,
    StrictInt,
    field_serializer,
    field_validator,
    model_validator,
)

from sih26145.contracts.events import FlowUid, StrictModel, TransportPort

NonNegativeInt = Annotated[StrictInt, Field(ge=0)]
PositiveInt = Annotated[StrictInt, Field(gt=0)]
NonNegativeFloat = Annotated[float, Field(ge=0.0, allow_inf_nan=False)]
PositiveFloat = Annotated[float, Field(gt=0.0, allow_inf_nan=False)]


class Severity(StrEnum):
    """Severity values supported by the common alert schema."""

    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must use an explicit UTC offset")
    return value


def _serialize_utc(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class DetectorIdentity(StrictModel):
    """Identity of the detector that produced the alert."""

    name: Literal["port_scan_window"]
    version: Literal["1.0.0"]


class AlertSource(StrictModel):
    """Observed source associated with an alert."""

    ip: IPvAnyAddress


class AlertWindow(StrictModel):
    """Capture-time interval supporting an alert."""

    start: datetime
    end: datetime
    configured_seconds: PositiveFloat

    @field_validator("start", "end")
    @classmethod
    def validate_utc(cls, value: datetime) -> datetime:
        return _require_utc(value)

    @model_validator(mode="after")
    def validate_order_and_duration(self) -> Self:
        if self.start > self.end:
            raise ValueError("alert window start must not follow end")
        if (self.end - self.start).total_seconds() > self.configured_seconds:
            raise ValueError("observed window exceeds configured duration")
        return self

    @field_serializer("start", "end")
    def serialize_timestamps(self, value: datetime) -> str:
        return _serialize_utc(value)


class ScanThresholdEvidence(StrictModel):
    """Threshold values used by the scan rule for this alert."""

    minimum_attempts: PositiveInt
    minimum_unique_destination_ports: PositiveInt
    minimum_unique_destination_hosts: PositiveInt


class DestinationSample(StrictModel):
    """One deterministic destination endpoint sample."""

    ip: IPvAnyAddress
    port: TransportPort


def _sample_sort_key(sample: DestinationSample) -> tuple[int, int, int]:
    return sample.ip.version, int(sample.ip), sample.port


class PortScanEvidence(StrictModel):
    """Measured current-window evidence for the port-scan rule."""

    deduplicated_attempts: NonNegativeInt
    unique_destination_hosts: NonNegativeInt
    unique_destination_ports: NonNegativeInt
    unique_destination_endpoints: NonNegativeInt
    attempt_rate_per_second: NonNegativeFloat
    observed_span_seconds: NonNegativeFloat
    thresholds: ScanThresholdEvidence
    destination_samples: Annotated[list[DestinationSample], Field(max_length=10)]

    @model_validator(mode="after")
    def validate_counts_and_samples(self) -> Self:
        attempts = self.deduplicated_attempts
        counts = (
            self.unique_destination_hosts,
            self.unique_destination_ports,
            self.unique_destination_endpoints,
        )
        if any(count > attempts for count in counts):
            raise ValueError("unique evidence counts cannot exceed attempts")
        if self.unique_destination_endpoints < max(
            self.unique_destination_hosts,
            self.unique_destination_ports,
        ):
            raise ValueError("endpoint count must cover host and port counts")
        if len(self.destination_samples) > self.unique_destination_endpoints:
            raise ValueError("destination samples cannot exceed endpoint count")

        sample_keys = [_sample_sort_key(sample) for sample in self.destination_samples]
        if len(sample_keys) != len(set(sample_keys)):
            raise ValueError("destination samples must be unique")
        if sample_keys != sorted(sample_keys):
            raise ValueError("destination samples must be deterministically sorted")

        thresholds = self.thresholds
        if attempts < thresholds.minimum_attempts:
            raise ValueError("attempt count does not reach recorded threshold")
        if (
            self.unique_destination_ports
            < thresholds.minimum_unique_destination_ports
            and self.unique_destination_hosts
            < thresholds.minimum_unique_destination_hosts
        ):
            raise ValueError("fanout does not reach a recorded threshold")
        return self


class AlertV1(StrictModel):
    """Common alert schema specialized to the Milestone 1 scan detector."""

    schema_version: Literal["alert_v1"] = "alert_v1"
    timestamp: datetime
    flow_id: FlowUid
    threat_class: Literal["PORT_SCAN"]
    protocol: Literal["tcp"]
    confidence: Annotated[float, Field(ge=0.0, le=1.0, allow_inf_nan=False)]
    severity: Severity
    detector: DetectorIdentity
    source: AlertSource
    window: AlertWindow
    evidence: PortScanEvidence

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp_utc(cls, value: datetime) -> datetime:
        return _require_utc(value)

    @model_validator(mode="after")
    def validate_evidence_consistency(self) -> Self:
        if self.timestamp != self.window.end:
            raise ValueError("alert timestamp must equal triggering window end")

        observed_span = (self.window.end - self.window.start).total_seconds()
        if not math.isclose(
            self.evidence.observed_span_seconds,
            observed_span,
            rel_tol=1e-9,
            abs_tol=1e-9,
        ):
            raise ValueError("observed span is inconsistent with alert window")

        expected_rate = self.evidence.deduplicated_attempts / self.window.configured_seconds
        if not math.isclose(
            self.evidence.attempt_rate_per_second,
            expected_rate,
            rel_tol=1e-9,
            abs_tol=1e-9,
        ):
            raise ValueError("attempt rate is inconsistent with attempts and window")
        return self

    @field_serializer("timestamp")
    def serialize_timestamp(self, value: datetime) -> str:
        return _serialize_utc(value)
