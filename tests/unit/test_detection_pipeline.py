from __future__ import annotations

from sih26145.detection.dga import DgaDetector
from sih26145.detection.pipeline import DetectionPipeline
from sih26145.detection.port_scan import PortScanDetector, ScanConfig
from sih26145.detection.syn_flood import SynFloodConfig, SynFloodDetector
from sih26145.ml.dga_model import DgaModel
from tests.factories import dns, syn


def pipeline(*, scan_attempts: int, flood_events: int) -> DetectionPipeline:
    return DetectionPipeline(
        port_scan=PortScanDetector(
            config=ScanConfig(
                minimum_attempts=scan_attempts,
                minimum_unique_destination_ports=1,
                minimum_unique_destination_hosts=1,
            )
        ),
        syn_flood=SynFloodDetector(
            config=SynFloodConfig(
                minimum_syn_events=flood_events,
                minimum_unique_sources=1,
            )
        ),
        dga=DgaDetector(model=DgaModel.load_packaged()),
    )


def test_one_event_can_emit_both_alerts_before_the_next_record() -> None:
    detector_pipeline = pipeline(scan_attempts=1, flood_events=1)

    alerts = detector_pipeline.process(syn(uid="both"))

    assert [alert.threat_class for alert in alerts] == ["PORT_SCAN", "SYN_FLOOD"]
    assert [str(alert.flow_id) for alert in alerts] == ["both", "both"]


def test_pipeline_returns_only_the_detector_that_crossed_its_threshold() -> None:
    detector_pipeline = pipeline(scan_attempts=2, flood_events=1)

    alerts = detector_pipeline.process(syn(uid="flood-only"))

    assert [alert.threat_class for alert in alerts] == ["SYN_FLOOD"]


def test_pipeline_returns_an_empty_batch_when_no_rule_crosses() -> None:
    detector_pipeline = pipeline(scan_attempts=2, flood_events=2)

    alerts = detector_pipeline.process(syn(uid="none"))

    assert alerts == ()


def test_dns_event_routes_only_to_dga_detector() -> None:
    detector_pipeline = pipeline(scan_attempts=1, flood_events=1)

    alerts = detector_pipeline.process(dns(query_name="x9q7z8v6k5j4m3n2.example"))

    assert [alert.threat_class for alert in alerts] == ["DGA"]


def test_benign_dns_event_returns_empty_without_mutating_syn_order() -> None:
    detector_pipeline = pipeline(scan_attempts=1, flood_events=1)

    assert detector_pipeline.process(dns(query_name="example.com")) == ()
    alerts = detector_pipeline.process(syn(uid="both-after-dns"))

    assert [alert.threat_class for alert in alerts] == ["PORT_SCAN", "SYN_FLOOD"]
