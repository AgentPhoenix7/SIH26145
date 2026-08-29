from __future__ import annotations

import pytest

from sih26145.contracts.alerts import DgaEvidence, Severity
from sih26145.detection.dga import DgaDetector
from sih26145.ml.dga_model import DgaModel
from tests.factories import dns


@pytest.fixture(scope="module")
def detector() -> DgaDetector:
    return DgaDetector(model=DgaModel.load_packaged())


def test_benign_probability_below_threshold_emits_no_alert(detector: DgaDetector) -> None:
    assert detector.process(dns(query_name="example.com")) is None


@pytest.mark.parametrize(
    ("query_name", "expected_severity"),
    [
        ("64f30398ecda3bbf.example", Severity.HIGH),
        ("x9q7z8v6k5j4m3n2.example", Severity.CRITICAL),
    ],
)
def test_dga_alert_carries_model_and_recomputed_lexical_evidence(
    detector: DgaDetector,
    query_name: str,
    expected_severity: Severity,
) -> None:
    event = dns(
        ts=1_777_777_777.25,
        uid="CDnsQuery0000001",
        transport="tcp",
        query_name=query_name,
        query_type=28,
    )

    alert = detector.process(event)

    assert alert is not None
    assert alert.threat_class == "DGA"
    assert alert.flow_id == event.uid
    assert alert.protocol == "tcp"
    assert alert.source.ip == event.src_ip
    assert alert.severity is expected_severity
    assert alert.window.start == alert.window.end == alert.timestamp
    assert isinstance(alert.evidence, DgaEvidence)
    assert alert.evidence.query_name == query_name
    assert alert.evidence.query_type == 28
    assert alert.evidence.dga_probability == alert.confidence
    assert alert.evidence.decision_threshold == 0.5
    assert alert.evidence.model_version == "dga_logreg_v1"
    assert alert.evidence.feature_schema_version == "dns_features_v1"
    assert alert.evidence.lexical_features.domain_length == len(query_name.replace(".", ""))
