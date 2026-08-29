from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError

from sih26145.contracts.alerts import AlertV1, DgaEvidence


def dga_alert_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "alert_v1",
        "timestamp": "2026-08-29T06:00:00.000000Z",
        "flow_id": "CDnsQuery0000001",
        "threat_class": "DGA",
        "protocol": "udp",
        "confidence": 0.9,
        "severity": "HIGH",
        "detector": {"name": "dga_logistic_regression", "version": "1.0.0"},
        "source": {"ip": "192.0.2.10"},
        "window": {
            "start": "2026-08-29T06:00:00.000000Z",
            "end": "2026-08-29T06:00:00.000000Z",
            "configured_seconds": 0.0,
        },
        "evidence": {
            "query_name": "example.com",
            "query_type": 1,
            "dga_probability": 0.9,
            "decision_threshold": 0.5,
            "model_version": "dga_logreg_v1",
            "feature_schema_version": "dns_features_v1",
            "observed_span_seconds": 0.0,
            "lexical_features": {
                "domain_length": 10,
                "label_count": 2,
                "longest_label_length": 7,
                "mean_label_length": 5.0,
                "digit_ratio": 0.0,
                "hyphen_ratio": 0.0,
                "vowel_ratio": 0.4,
                "unique_character_ratio": 0.8,
                "character_entropy_bits": 2.9219280948873623,
                "unique_bigram_ratio": 1.0,
                "longest_consonant_run": 3,
                "longest_digit_run": 0,
            },
        },
    }
    payload.update(overrides)
    return payload


def test_valid_dga_alert_has_typed_lexical_model_evidence() -> None:
    alert = AlertV1.model_validate_json(json.dumps(dga_alert_payload()))

    assert alert.threat_class == "DGA"
    assert alert.protocol == "udp"
    assert isinstance(alert.evidence, DgaEvidence)
    assert alert.evidence.query_name == "example.com"
    assert alert.evidence.model_version == "dga_logreg_v1"
    assert alert.model_dump(mode="json") == dga_alert_payload()


def _reject(payload: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        AlertV1.model_validate_json(json.dumps(payload))


def test_dga_probability_must_reach_threshold() -> None:
    payload = dga_alert_payload(confidence=0.49, severity="MEDIUM")
    payload["evidence"]["dga_probability"] = 0.49

    _reject(payload)


def test_dga_confidence_must_equal_model_probability() -> None:
    _reject(dga_alert_payload(confidence=0.91))


def test_dga_severity_must_match_probability_band() -> None:
    _reject(dga_alert_payload(severity="MEDIUM"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("model_version", "unknown_model"),
        ("feature_schema_version", "dns_features_v2"),
        ("query_type", 0),
        ("query_name", "Example.COM"),
    ],
)
def test_dga_identity_and_query_fields_are_strict(field: str, value: object) -> None:
    payload = dga_alert_payload()
    payload["evidence"][field] = value

    _reject(payload)


def test_dga_lexical_evidence_must_match_query() -> None:
    payload = dga_alert_payload()
    payload["evidence"]["lexical_features"]["domain_length"] = 11

    _reject(payload)


def test_dga_detector_and_evidence_must_match_threat_class() -> None:
    payload = dga_alert_payload()
    payload["detector"] = {"name": "port_scan_window", "version": "1.0.0"}

    _reject(payload)


def test_dga_alert_is_exactly_one_event_window() -> None:
    payload = deepcopy(dga_alert_payload())
    payload["window"]["start"] = "2026-08-29T05:59:59.000000Z"
    payload["evidence"]["observed_span_seconds"] = 1.0

    _reject(payload)


def test_dga_alert_rejects_invented_configured_time_window() -> None:
    payload = dga_alert_payload()
    payload["window"]["configured_seconds"] = 1.0

    _reject(payload)
