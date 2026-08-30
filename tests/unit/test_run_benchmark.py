from __future__ import annotations

import pytest

from sih26145.contracts.alerts import AlertV1
from sih26145.detection.dga import DgaDetector
from sih26145.detection.pipeline import DetectionPipeline
from sih26145.detection.port_scan import PortScanDetector, ScanConfig
from sih26145.detection.syn_flood import SynFloodConfig, SynFloodDetector
from sih26145.ml.dga_model import DgaModel
from tests.factories import dns, syn
from tools.run_benchmark import EventSample, TimingPipeline, percentile


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


def test_timing_pipeline_records_one_sample_per_event_with_alert_counts() -> None:
    samples: list[EventSample] = []
    timing_pipeline = TimingPipeline(_pipeline(), samples)

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

    timing_pipeline = TimingPipeline(_pipeline(), [])

    assert isinstance(timing_pipeline, DetectionPipeline)


def test_timing_pipeline_preserves_alert_validity() -> None:
    samples: list[EventSample] = []
    timing_pipeline = TimingPipeline(_pipeline(), samples)

    alerts = timing_pipeline.process(dns(ts=1_700_000_000.0, query_name="x9q7z8v6k5j4m3n2.example"))

    assert len(alerts) == 1
    assert isinstance(alerts[0], AlertV1)
