from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import tools.run_benchmark as run_benchmark_module
from sih26145.contracts.alerts import AlertV1
from sih26145.detection.dga import DgaDetector
from sih26145.detection.pipeline import DetectionPipeline
from sih26145.detection.port_scan import PortScanDetector, ScanConfig
from sih26145.detection.scan_window import StateLimitExceeded
from sih26145.detection.syn_flood import SynFloodConfig, SynFloodDetector
from sih26145.ml.dga_model import DgaModel
from sih26145.replay import ReplayResult
from tests.factories import dns, syn
from tools.generate_benchmark_fixture import _artifacts as _benchmark_artifacts
from tools.run_benchmark import (
    EventSample,
    TimingPipeline,
    UnexpectedReplayResultError,
    UnvalidatedPcapError,
    _EmissionClock,
    _make_emit_alert,
    _validate_pcap_matches_generated_fixture,
    _verify_replay_matches_manifest,
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


def test_timing_pipeline_enforces_a_hard_event_cap_regardless_of_manifest_trust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The --worker-manifest entry point trusts its manifest without re-deriving
    it from the generator (doing so would corrupt the isolated Zeek RSS/CPU
    measurement -- see the module docstring), so this cap must hold even for a
    direct invocation of that internal flag with an arbitrarily large pcap."""

    monkeypatch.setattr(run_benchmark_module, "_MAX_MEASURED_EVENTS", 2)
    samples: list[EventSample] = []
    timing_pipeline, _clock = _timing_pipeline(samples)

    timing_pipeline.process(syn(ts=1_700_000_000.0, uid="c1", src_port=40_001))
    timing_pipeline.process(syn(ts=1_700_000_000.0, uid="c2", src_port=40_002))

    with pytest.raises(StateLimitExceeded, match="benchmark_measured_events"):
        timing_pipeline.process(syn(ts=1_700_000_000.0, uid="c3", src_port=40_003))

    # The rejected event must not have been counted before the check tripped.
    assert len(samples) == 2


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


def test_validate_pcap_matches_generated_fixture_accepts_the_real_generated_bytes(
    tmp_path: Path,
) -> None:
    pcap_path = tmp_path / "sustained_load.pcap"
    pcap_path.write_bytes(_benchmark_artifacts()["sustained_load.pcap"])

    manifest_bytes = _validate_pcap_matches_generated_fixture(pcap_path)  # must not raise

    assert json.loads(manifest_bytes) == json.loads(
        _benchmark_artifacts()["sustained_load.manifest.json"]
    )


def test_validate_pcap_matches_generated_fixture_rejects_a_larger_arbitrary_capture(
    tmp_path: Path,
) -> None:
    """A large arbitrary capture (with or without a fabricated sidecar) must be rejected
    by size alone, before any of its bytes are read."""

    expected_size = len(_benchmark_artifacts()["sustained_load.pcap"])
    pcap_path = tmp_path / "sustained_load.pcap"
    pcap_path.write_bytes(b"\x00" * (expected_size + 1))

    with pytest.raises(UnvalidatedPcapError, match="bytes"):
        _validate_pcap_matches_generated_fixture(pcap_path)


def test_validate_pcap_matches_generated_fixture_rejects_same_size_wrong_content(
    tmp_path: Path,
) -> None:
    expected_bytes = _benchmark_artifacts()["sustained_load.pcap"]
    pcap_path = tmp_path / "sustained_load.pcap"
    # Same length as the real fixture, but not the same bytes.
    pcap_path.write_bytes(b"\xff" * len(expected_bytes))

    with pytest.raises(UnvalidatedPcapError, match="does not match"):
        _validate_pcap_matches_generated_fixture(pcap_path)


def test_validate_pcap_matches_generated_fixture_rejects_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(UnvalidatedPcapError, match="cannot stat"):
        _validate_pcap_matches_generated_fixture(tmp_path / "does_not_exist.pcap")


def test_run_benchmark_does_not_import_the_generator_object_graph_in_process() -> None:
    """Building the ~21,431-packet fixture must happen in a subprocess (see
    _generator_fixture_info), never in this process, so it cannot inflate the
    RUSAGE_SELF peak-RSS sample this tool reports as the detector replay's own
    memory footprint (see the module docstring and PR #5 review discussion)."""

    import ast

    tree = ast.parse(Path("tools/run_benchmark.py").read_text())
    imported_names = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }

    assert "_artifacts" not in imported_names
    assert "generate_benchmark_fixture" not in imported_names


def _dga_alert() -> AlertV1:
    alert = DgaDetector(model=DgaModel.load_packaged()).process(
        dns(ts=1_700_000_000.0, query_name="x9q7z8v6k5j4m3n2.example")
    )
    assert alert is not None
    return alert


def test_verify_replay_matches_manifest_accepts_the_expected_workload() -> None:
    manifest = {"expected_processed_events": 5, "expected_alert_count_by_class": {"DGA": 2}}
    result = ReplayResult(events_processed=5, alerts_emitted=2, last_event_ts=0.0)

    _verify_replay_matches_manifest(
        manifest, result=result, alerts=[_dga_alert(), _dga_alert()]
    )  # must not raise


def test_verify_replay_matches_manifest_rejects_a_wrong_event_count() -> None:
    manifest = {"expected_processed_events": 5, "expected_alert_count_by_class": {}}
    result = ReplayResult(events_processed=4, alerts_emitted=0, last_event_ts=0.0)

    with pytest.raises(UnexpectedReplayResultError, match="events"):
        _verify_replay_matches_manifest(manifest, result=result, alerts=[])


def test_verify_replay_matches_manifest_rejects_wrong_alert_counts_by_class() -> None:
    manifest = {"expected_processed_events": 1, "expected_alert_count_by_class": {"DGA": 1}}
    result = ReplayResult(events_processed=1, alerts_emitted=0, last_event_ts=0.0)

    with pytest.raises(UnexpectedReplayResultError, match="alerts"):
        _verify_replay_matches_manifest(manifest, result=result, alerts=[])


def test_verify_replay_matches_manifest_is_compatible_with_the_real_generated_manifest() -> None:
    """The real manifest's keys/shape must be exactly what this function expects."""

    manifest = json.loads(_benchmark_artifacts()["sustained_load.manifest.json"])
    result = ReplayResult(events_processed=0, alerts_emitted=0, last_event_ts=None)

    with pytest.raises(UnexpectedReplayResultError, match="events"):
        _verify_replay_matches_manifest(manifest, result=result, alerts=[])


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
