from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from sih26145.contracts.alerts import AlertV1, Severity

ALERT_END = datetime(2026, 8, 28, 12, 0, 9, tzinfo=UTC)
ALERT_START = datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC)


def valid_syn_flood_payload() -> dict[str, Any]:
    return {
        "schema_version": "alert_v1",
        "timestamp": ALERT_END,
        "flow_id": "trigger-uid",
        "threat_class": "SYN_FLOOD",
        "protocol": "tcp",
        "confidence": 0.75,
        "severity": Severity.MEDIUM,
        "detector": {"name": "syn_flood_window", "version": "1.0.0"},
        "source": {"ip": "192.0.2.20"},
        "window": {
            "start": ALERT_START,
            "end": ALERT_END,
            "configured_seconds": 10.0,
        },
        "evidence": {
            "deduplicated_syn_events": 100,
            "unique_sources": 20,
            "source_ip_entropy_bits": 4.321928,
            "syn_rate_per_second": 10.0,
            "observed_span_seconds": 9.0,
            "target": {"ip": "198.51.100.20", "port": 443},
            "thresholds": {
                "minimum_syn_events": 100,
                "minimum_unique_sources": 20,
            },
            "source_samples": [
                "192.0.2.1",
                "192.0.2.2",
                "192.0.2.10",
            ],
        },
    }


def test_syn_flood_alert_round_trips_with_typed_evidence() -> None:
    alert = AlertV1.model_validate(valid_syn_flood_payload())

    encoded = alert.model_dump_json()
    reparsed = AlertV1.model_validate_json(encoded)

    assert '"threat_class":"SYN_FLOOD"' in encoded
    assert '"name":"syn_flood_window"' in encoded
    assert reparsed == alert


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("deduplicated_syn_events", 99),
        ("unique_sources", 101),
        ("source_ip_entropy_bits", 4.4),
        ("syn_rate_per_second", 9.9),
        ("observed_span_seconds", 8.0),
    ],
)
def test_syn_flood_alert_rejects_inconsistent_measured_evidence(
    field: str,
    value: object,
) -> None:
    payload = valid_syn_flood_payload()
    payload["evidence"][field] = value

    with pytest.raises(ValidationError):
        AlertV1.model_validate(payload)


def test_syn_flood_source_samples_must_be_unique_and_sorted() -> None:
    payload = valid_syn_flood_payload()
    payload["evidence"]["source_samples"] = ["192.0.2.2", "192.0.2.1", "192.0.2.1"]

    with pytest.raises(ValidationError):
        AlertV1.model_validate(payload)


def test_syn_flood_alert_rejects_mismatched_detector_and_evidence() -> None:
    payload = deepcopy(valid_syn_flood_payload())
    payload["detector"] = {"name": "port_scan_window", "version": "1.0.0"}

    with pytest.raises(ValidationError):
        AlertV1.model_validate(payload)


def test_syn_flood_alert_rejects_unknown_nested_fields() -> None:
    payload = valid_syn_flood_payload()
    payload["evidence"]["target"]["unexpected"] = True

    with pytest.raises(ValidationError):
        AlertV1.model_validate(payload)


def test_syn_flood_window_still_rejects_duration_overrun() -> None:
    payload = valid_syn_flood_payload()
    payload["window"]["start"] = ALERT_END - timedelta(seconds=10, microseconds=1)
    payload["evidence"]["observed_span_seconds"] = 10.000001

    with pytest.raises(ValidationError):
        AlertV1.model_validate(payload)
