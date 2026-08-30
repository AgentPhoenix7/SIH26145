from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest

from sih26145.contracts.alerts import AlertV1
from sih26145.detection.dga import DgaDetector
from sih26145.detection.pipeline import DetectionPipeline
from sih26145.detection.port_scan import PortScanDetector, ScanConfig
from sih26145.detection.syn_flood import SynFloodConfig, SynFloodDetector
from sih26145.ml.dga_model import DgaModel
from tests.factories import dns, syn
from tools.run_benchmark import (
    EventSample,
    TimingPipeline,
    UnvalidatedPcapError,
    _EmissionClock,
    _make_emit_alert,
    _validate_pcap_against_manifest,
    percentile,
)


def test_percentile_matches_known_values() -> None:
    values = [10.0, 20.0, 30.0, 40.0]

    assert percentile(values, 0.0) == 10.0
    assert percentile(values, 1.0) == 40.0
    assert percentile(values, 0.5) == pytest.approx(25.0)


def test_percentile_rejects_empty_sequence() -> None:
    with pytest.raises(ValueError, match="empty"):
        percentile([], 0.5)


def test_percentile_single_value_is_that_value() -> None:
    assert percentile([7.0], 0.99) == 7.0


def _pipeline() -> DetectionPipeline:
    return DetectionPipeline(
        port_scan=PortScanDetector(config=ScanConfig()),
        syn_flood=SynFloodDetector(config=SynFloodConfig()),
        dga=DgaDetector(model=DgaModel.load_packaged()),
    )


def _timing_pipeline(samples: list[EventSample]) -> tuple[TimingPipeline, _EmissionClock]:
    clock = _EmissionClock()
    return TimingPipeline(_pipeline(), samples, clock), clock


def test_timing_pipeline_records_one_sample_per_event_with_alert_counts() -> None:
    samples: list[EventSample] = []
    timing_pipeline, _clock = _timing_pipeline(samples)

    benign_alerts = timing_pipeline.process(syn(ts=1_700_000_000.0, uid="c40000", src_port=40_000))
    dga_alerts = timing_pipeline.process(
        dns(ts=1_700_000_000.0, query_name="x9q7z8v6k5j4m3n2.example")
    )

    assert benign_alerts == ()
    assert len(dga_alerts) == 1
    assert len(samples) == 2
    assert samples[0].alert_count == 0
    assert samples[1].alert_count == 1
    assert all(sample.duration_seconds >= 0.0 for sample in samples)


def test_timing_pipeline_dispatches_dns_events_through_isinstance_check() -> None:
    """`run_command` only forwards DNS events when isinstance(detector, DetectionPipeline)."""

    timing_pipeline, _clock = _timing_pipeline([])

    assert isinstance(timing_pipeline, DetectionPipeline)


def test_timing_pipeline_preserves_alert_validity() -> None:
    samples: list[EventSample] = []
    timing_pipeline, _clock = _timing_pipeline(samples)

    alerts = timing_pipeline.process(dns(ts=1_700_000_000.0, query_name="x9q7z8v6k5j4m3n2.example"))

    assert len(alerts) == 1
    assert isinstance(alerts[0], AlertV1)


def test_emit_alert_measures_from_process_start_through_actual_serialization() -> None:
    """Alert latency must cover process()-start through real emit work, not just process()."""

    samples: list[EventSample] = []
    timing_pipeline, clock = _timing_pipeline(samples)
    collected_alerts: list[AlertV1] = []
    alert_latencies: list[float] = []
    sink = io.StringIO()
    emit_alert = _make_emit_alert(clock, collected_alerts, alert_latencies, sink)

    alerts = timing_pipeline.process(dns(ts=1_700_000_000.0, query_name="x9q7z8v6k5j4m3n2.example"))
    for alert in alerts:
        emit_alert(alert)

    assert len(alert_latencies) == 1
    # The emit callback actually serialized the alert (mirrors sih26145.cli.emit_alert).
    assert sink.getvalue() == alerts[0].model_dump_json() + "\n"
    # The measured interval starts at process() entry, so it is at least as long
    # as that event's own recorded processing duration.
    assert alert_latencies[0] >= samples[0].duration_seconds


def _write_manifest(manifest_path: Path, *, capture_sha256: str) -> None:
    manifest_path.write_text(json.dumps({"capture_sha256": capture_sha256}))


def test_validate_pcap_against_manifest_accepts_a_matching_capture(tmp_path: Path) -> None:
    pcap_path = tmp_path / "sustained_load.pcap"
    pcap_path.write_bytes(b"deterministic content")
    _write_manifest(
        pcap_path.with_suffix(".manifest.json"),
        capture_sha256=hashlib.sha256(pcap_path.read_bytes()).hexdigest(),
    )

    _validate_pcap_against_manifest(pcap_path)  # must not raise


def test_validate_pcap_against_manifest_rejects_a_tampered_or_arbitrary_capture(
    tmp_path: Path,
) -> None:
    pcap_path = tmp_path / "sustained_load.pcap"
    pcap_path.write_bytes(b"an arbitrary, potentially very large capture")
    _write_manifest(pcap_path.with_suffix(".manifest.json"), capture_sha256="0" * 64)

    with pytest.raises(UnvalidatedPcapError, match="capture_sha256"):
        _validate_pcap_against_manifest(pcap_path)


def test_validate_pcap_against_manifest_rejects_a_missing_manifest(tmp_path: Path) -> None:
    pcap_path = tmp_path / "no_manifest.pcap"
    pcap_path.write_bytes(b"anything")

    with pytest.raises(UnvalidatedPcapError, match="manifest"):
        _validate_pcap_against_manifest(pcap_path)


def test_emit_alert_without_a_preceding_process_call_records_nothing() -> None:
    clock = _EmissionClock()
    alert_latencies: list[float] = []
    sink = io.StringIO()
    emit_alert = _make_emit_alert(clock, [], alert_latencies, sink)

    alert = DgaDetector(model=DgaModel.load_packaged()).process(
        dns(ts=1_700_000_000.0, query_name="x9q7z8v6k5j4m3n2.example")
    )
    assert alert is not None
    emit_alert(alert)

    assert alert_latencies == []
