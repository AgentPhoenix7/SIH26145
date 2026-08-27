from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from sih26145.contracts.alerts import AlertV1, Severity

ALERT_END = datetime(2026, 8, 26, 15, 0, 0, 123_456, tzinfo=UTC)
ALERT_START = datetime(2026, 8, 26, 14, 59, 51, tzinfo=UTC)


def valid_alert_payload() -> dict[str, Any]:
    return {
        "schema_version": "alert_v1",
        "timestamp": ALERT_END,
        "flow_id": "C9e2pMxSR3KXn846a",
        "threat_class": "PORT_SCAN",
        "protocol": "tcp",
        "confidence": 0.75,
        "severity": Severity.MEDIUM,
        "detector": {"name": "port_scan_window", "version": "1.0.0"},
        "source": {"ip": "192.0.2.10"},
        "window": {
            "start": ALERT_START,
            "end": ALERT_END,
            "configured_seconds": 10.0,
        },
        "evidence": {
            "deduplicated_attempts": 20,
            "unique_destination_hosts": 1,
            "unique_destination_ports": 15,
            "unique_destination_endpoints": 15,
            "attempt_rate_per_second": 2.0,
            "observed_span_seconds": 9.123456,
            "thresholds": {
                "minimum_attempts": 20,
                "minimum_unique_destination_ports": 15,
                "minimum_unique_destination_hosts": 15,
            },
            "destination_samples": [
                {"ip": "198.51.100.20", "port": 22},
                {"ip": "198.51.100.20", "port": 23},
            ],
        },
    }


def assert_invalid(payload: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        AlertV1.model_validate(payload)


def test_alert_v1_round_trips_with_typed_scan_evidence() -> None:
    alert = AlertV1.model_validate(valid_alert_payload())

    encoded = alert.model_dump_json()
    reparsed = AlertV1.model_validate_json(encoded)

    assert '"schema_version":"alert_v1"' in encoded
    assert '"timestamp":"2026-08-26T15:00:00.123456Z"' in encoded
    assert '"start":"2026-08-26T14:59:51.000000Z"' in encoded
    assert reparsed == alert


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("confidence", -0.01),
        ("confidence", 1.01),
        ("confidence", float("nan")),
        ("flow_id", ""),
        ("flow_id", "contains whitespace"),
        ("protocol", "udp"),
        ("threat_class", "SYN_FLOOD"),
        ("severity", "LOW"),
        ("unexpected", "field"),
    ],
)
def test_alert_rejects_invalid_common_values(field: str, value: object) -> None:
    payload = valid_alert_payload()
    payload[field] = value

    assert_invalid(payload)


@pytest.mark.parametrize("severity", list(Severity))
def test_alert_accepts_every_supported_severity(severity: Severity) -> None:
    payload = valid_alert_payload()
    payload["severity"] = severity

    assert AlertV1.model_validate(payload).severity is severity


@pytest.mark.parametrize(
    "timestamp",
    [
        datetime(2026, 8, 26, 15, 0),
        datetime(2026, 8, 26, 17, 0, tzinfo=timezone(timedelta(hours=2))),
    ],
)
def test_alert_timestamp_must_be_explicit_utc(timestamp: datetime) -> None:
    payload = valid_alert_payload()
    payload["timestamp"] = timestamp

    assert_invalid(payload)


def test_alert_timestamp_must_equal_triggering_window_end() -> None:
    payload = valid_alert_payload()
    payload["timestamp"] = ALERT_END - timedelta(microseconds=1)

    assert_invalid(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [("name", "other_detector"), ("version", "2.0.0"), ("extra", "field")],
)
def test_detector_identity_is_fixed_for_milestone_one(field: str, value: str) -> None:
    payload = valid_alert_payload()
    payload["detector"][field] = value

    assert_invalid(payload)


def test_alert_rejects_inverted_window() -> None:
    payload = valid_alert_payload()
    payload["window"]["start"] = ALERT_END + timedelta(seconds=1)

    assert_invalid(payload)


def test_alert_rejects_observed_window_longer_than_configuration() -> None:
    payload = valid_alert_payload()
    payload["window"]["start"] = ALERT_END - timedelta(seconds=10, microseconds=1)
    payload["evidence"]["observed_span_seconds"] = 10.000001

    assert_invalid(payload)


def test_alert_rejects_observed_span_inconsistent_with_window() -> None:
    payload = valid_alert_payload()
    payload["evidence"]["observed_span_seconds"] = 9.0

    assert_invalid(payload)


def test_alert_rejects_rate_inconsistent_with_attempts_and_window() -> None:
    payload = valid_alert_payload()
    payload["evidence"]["attempt_rate_per_second"] = 1.9

    assert_invalid(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("deduplicated_attempts", -1),
        ("unique_destination_hosts", 21),
        ("unique_destination_ports", 21),
        ("unique_destination_endpoints", 21),
        ("attempt_rate_per_second", -0.1),
        ("observed_span_seconds", -0.1),
    ],
)
def test_alert_rejects_negative_or_impossible_evidence(field: str, value: object) -> None:
    payload = valid_alert_payload()
    payload["evidence"][field] = value

    assert_invalid(payload)


def test_endpoint_count_must_cover_host_and_port_counts() -> None:
    payload = valid_alert_payload()
    payload["evidence"]["unique_destination_endpoints"] = 14

    assert_invalid(payload)


def test_evidence_attempts_must_reach_recorded_threshold() -> None:
    payload = valid_alert_payload()
    payload["evidence"]["deduplicated_attempts"] = 19
    payload["evidence"]["attempt_rate_per_second"] = 1.9

    assert_invalid(payload)


def test_evidence_fanout_must_reach_a_recorded_threshold() -> None:
    payload = valid_alert_payload()
    payload["evidence"]["unique_destination_ports"] = 14
    payload["evidence"]["unique_destination_hosts"] = 14
    payload["evidence"]["unique_destination_endpoints"] = 14

    assert_invalid(payload)


def test_destination_samples_must_be_unique() -> None:
    payload = valid_alert_payload()
    payload["evidence"]["destination_samples"] = [
        {"ip": "198.51.100.20", "port": 22},
        {"ip": "198.51.100.20", "port": 22},
    ]

    assert_invalid(payload)


def test_destination_samples_must_be_deterministically_sorted() -> None:
    payload = valid_alert_payload()
    payload["evidence"]["destination_samples"].reverse()

    assert_invalid(payload)


def test_destination_samples_are_limited_to_ten() -> None:
    payload = valid_alert_payload()
    payload["evidence"]["destination_samples"] = [
        {"ip": "198.51.100.20", "port": port} for port in range(11)
    ]

    assert_invalid(payload)


def test_destination_samples_cannot_exceed_unique_endpoint_count() -> None:
    payload = valid_alert_payload()
    payload["evidence"]["unique_destination_hosts"] = 1
    payload["evidence"]["unique_destination_ports"] = 2
    payload["evidence"]["unique_destination_endpoints"] = 2
    payload["evidence"]["destination_samples"] = [
        {"ip": "198.51.100.20", "port": port} for port in range(3)
    ]

    assert_invalid(payload)


def test_nested_unknown_fields_are_rejected() -> None:
    payload = deepcopy(valid_alert_payload())
    payload["evidence"]["thresholds"]["unknown"] = 1

    assert_invalid(payload)
