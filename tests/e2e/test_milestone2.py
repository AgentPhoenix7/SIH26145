from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import pytest

import sih26145.cli as cli
import sih26145.replay as replay
from sih26145.contracts.alerts import AlertV1, SynFloodEvidence
from sih26145.contracts.events import EndOfStreamV1, parse_stream_line
from sih26145.detection.pipeline import DetectionPipeline
from sih26145.detection.port_scan import PortScanDetector, ScanConfig
from sih26145.detection.syn_flood import SynFloodConfig, SynFloodDetector
from sih26145.replay import ReplayResult, run_replay

FIXTURES = Path("tests/fixtures/milestone2").resolve()


def detector_pipeline() -> DetectionPipeline:
    return DetectionPipeline(
        port_scan=PortScanDetector(config=ScanConfig()),
        syn_flood=SynFloodDetector(config=SynFloodConfig()),
    )


def collect_native_alerts(fixture_name: str) -> tuple[ReplayResult, list[AlertV1]]:
    alerts: list[AlertV1] = []
    result = run_replay(
        FIXTURES / fixture_name,
        detector_pipeline(),
        alerts.append,
    )
    return result, alerts


@pytest.mark.e2e
def test_native_syn_flood_replay_alerts_at_exact_threshold() -> None:
    result, alerts = collect_native_alerts("syn_flood_at_threshold.pcap")

    assert result.events_processed == 100
    assert result.alerts_emitted == 1
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.threat_class == "SYN_FLOOD"
    assert isinstance(alert.evidence, SynFloodEvidence)
    assert alert.evidence.deduplicated_syn_events == 100
    assert alert.evidence.unique_sources == 20
    assert math.isclose(alert.evidence.source_ip_entropy_bits, math.log2(20))
    assert alert.evidence.syn_rate_per_second == 10.0
    assert alert.evidence.observed_span_seconds == 4.95
    assert str(alert.evidence.target.ip) == "198.51.100.20"
    assert alert.evidence.target.port == 443


@pytest.mark.e2e
@pytest.mark.parametrize(
    ("fixture_name", "expected_events"),
    [("syn_flood_below.pcap", 99), ("benign_distributed.pcap", 100)],
)
def test_native_non_flood_replay_emits_no_alerts(
    fixture_name: str,
    expected_events: int,
) -> None:
    result, alerts = collect_native_alerts(fixture_name)

    assert result.events_processed == expected_events
    assert result.alerts_emitted == 0
    assert alerts == []


@pytest.mark.e2e
def test_native_syn_flood_alert_is_emitted_before_eos(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observations: list[str] = []
    real_parse = parse_stream_line

    def observe_parse(raw: bytes) -> Any:
        record = real_parse(raw)
        if isinstance(record, EndOfStreamV1):
            observations.append("end_of_stream")
        return record

    def observe_alert(_alert: AlertV1) -> None:
        observations.append("alert")

    monkeypatch.setattr(replay, "parse_stream_line", observe_parse)
    result = run_replay(
        FIXTURES / "syn_flood_at_threshold.pcap",
        detector_pipeline(),
        observe_alert,
    )

    assert result.alerts_emitted == 1
    assert observations == ["alert", "end_of_stream"]


@pytest.mark.e2e
def test_cli_syn_flood_replay_outputs_one_canonical_alert(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli.main([str(FIXTURES / "syn_flood_at_threshold.pcap")])

    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert exit_code == 0
    assert captured.err == ""
    assert len(lines) == 1
    alert = AlertV1.model_validate_json(lines[0])
    assert alert.threat_class == "SYN_FLOOD"
    assert lines[0] == alert.model_dump_json()


def test_cli_rejects_invalid_syn_flood_configuration_before_replay(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def unexpected_replay(*_args: object, **_kwargs: object) -> ReplayResult:
        pytest.fail("run_replay must not start for invalid SYN-flood configuration")

    monkeypatch.setattr(cli, "run_replay", unexpected_replay)

    exit_code = cli.main([str(FIXTURES / "benign_distributed.pcap"), "--min-syn-events", "0"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert captured.err == "configuration_error: invalid_syn_flood_configuration\n"


def test_cli_help_documents_syn_flood_thresholds(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as captured_exit:
        cli.main(["--help"])

    captured = capsys.readouterr()
    assert captured_exit.value.code == 0
    assert captured.err == ""
    assert "--syn-flood-window-seconds" in captured.out
    assert "--min-syn-events" in captured.out
    assert "--min-syn-sources" in captured.out
    assert "--syn-flood-cooldown-seconds" in captured.out
