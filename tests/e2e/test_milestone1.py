from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from sih26145 import cli, replay
from sih26145.contracts.alerts import AlertV1
from sih26145.contracts.events import EndOfStreamV1, StreamRecord, parse_stream_line
from sih26145.detection.port_scan import PortScanDetector, ScanConfig
from sih26145.detection.scan_window import StateLimitExceeded
from sih26145.replay import ReplayError, ReplayResult
from tests.factories import vertical_events

pytestmark = pytest.mark.e2e

FIXTURES = Path("tests/fixtures/milestone1").resolve()


class _RecordingStdout:
    def __init__(self) -> None:
        self.operations: list[tuple[str, str]] = []

    def write(self, value: str) -> int:
        self.operations.append(("write", value))
        return len(value)

    def flush(self) -> None:
        self.operations.append(("flush", ""))


def _unexpected_replay(*_args: object, **_kwargs: object) -> ReplayResult:
    pytest.fail("run_replay must not start for invalid user input")


def _collect_native_alerts(fixture_name: str) -> tuple[ReplayResult, list[AlertV1]]:
    alerts: list[AlertV1] = []
    result = replay.run_replay(
        FIXTURES / fixture_name,
        PortScanDetector(config=ScanConfig()),
        alerts.append,
    )
    return result, alerts


@pytest.mark.parametrize("path_kind", ["missing", "directory"])
def test_cli_rejects_non_file_pcap_before_replay(
    path_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pcap = tmp_path / "capture.pcap"
    if path_kind == "directory":
        pcap.mkdir()
    monkeypatch.setattr(cli, "run_replay", _unexpected_replay)

    exit_code = cli.main([str(pcap)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert captured.err == "input_error: pcap_not_regular_file\n"


@pytest.mark.parametrize(
    "arguments",
    [
        ["--window-seconds", "0"],
        ["--window-seconds", "nan"],
        ["--min-attempts", "0"],
        ["--min-unique-ports", "0"],
        ["--min-unique-hosts", "0"],
        ["--cooldown-seconds", "-1"],
        ["--cooldown-seconds", "inf"],
    ],
)
def test_cli_rejects_invalid_configuration_before_replay(
    arguments: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "run_replay", _unexpected_replay)

    exit_code = cli.main([str(FIXTURES / "benign.pcap"), *arguments])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert captured.err == "configuration_error: invalid_scan_configuration\n"


@pytest.mark.parametrize(
    ("failure", "expected_diagnostic"),
    [
        (
            ReplayError("invalid_stream_record"),
            "replay_error: invalid_stream_record\n",
        ),
        (
            StateLimitExceeded("max_total_attempts"),
            "state_limit_exceeded: max_total_attempts\n",
        ),
    ],
)
def test_cli_maps_runtime_failures_to_exit_one_without_stdout(
    failure: Exception,
    expected_diagnostic: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_replay(*_args: object, **_kwargs: object) -> ReplayResult:
        raise failure

    monkeypatch.setattr(cli, "run_replay", fail_replay)

    exit_code = cli.main([str(FIXTURES / "benign.pcap")])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == expected_diagnostic


def test_cli_help_documents_defaults_and_uncalibrated_status(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as captured_exit:
        cli.main(["--help"])

    captured = capsys.readouterr()
    assert captured_exit.value.code == 0
    assert captured.err == ""
    assert "--window-seconds" in captured.out
    assert "(default: 10.0)" in captured.out
    assert "--min-attempts" in captured.out
    assert "(default: 20)" in captured.out
    assert "--min-unique-ports" in captured.out
    assert "--min-unique-hosts" in captured.out
    assert "(default: 15)" in captured.out
    assert "--cooldown-seconds" in captured.out
    assert "(default: 30.0)" in captured.out
    assert "heuristic" in captured.out.lower()
    assert "unvalidated" in captured.out.lower()


def test_emit_alert_writes_one_canonical_json_line_then_flushes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detector = PortScanDetector(config=ScanConfig())
    alerts = [detector.process(event) for event in vertical_events(attempts=20, ports=15)]
    alert = next(item for item in alerts if item is not None)
    stdout = _RecordingStdout()
    monkeypatch.setattr(sys, "stdout", stdout)

    cli.emit_alert(alert)

    assert stdout.operations == [
        ("write", alert.model_dump_json() + "\n"),
        ("flush", ""),
    ]


def test_cli_benign_replay_exits_zero_with_empty_stdout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli.main([str(FIXTURES / "benign.pcap")])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == ""
    assert captured.err == ""


def test_cli_scan_replay_outputs_only_canonical_alert_jsonl(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli.main([str(FIXTURES / "vertical_at_threshold.pcap")])

    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert exit_code == 0
    assert captured.err == ""
    assert len(lines) == 1
    alert = AlertV1.model_validate_json(lines[0])
    assert lines[0] == alert.model_dump_json()


@pytest.mark.parametrize(
    (
        "fixture_name",
        "expected_flow_id",
        "expected_unique_hosts",
        "expected_unique_ports",
        "expected_samples",
    ),
    [
        (
            "vertical_at_threshold.pcap",
            "CNG7101ClFJPhG5ukb",
            1,
            15,
            [
                {"ip": "198.51.100.20", "port": 20},
                {"ip": "198.51.100.20", "port": 21},
                {"ip": "198.51.100.20", "port": 22},
                {"ip": "198.51.100.20", "port": 23},
                {"ip": "198.51.100.20", "port": 24},
                {"ip": "198.51.100.20", "port": 25},
                {"ip": "198.51.100.20", "port": 26},
                {"ip": "198.51.100.20", "port": 27},
                {"ip": "198.51.100.20", "port": 28},
                {"ip": "198.51.100.20", "port": 29},
            ],
        ),
        (
            "horizontal_at_threshold.pcap",
            "CNG7101ClFJPhG5ukb",
            15,
            1,
            [
                {"ip": "198.51.100.20", "port": 20},
                {"ip": "198.51.100.21", "port": 20},
                {"ip": "198.51.100.22", "port": 20},
                {"ip": "198.51.100.23", "port": 20},
                {"ip": "198.51.100.24", "port": 20},
                {"ip": "198.51.100.25", "port": 20},
                {"ip": "198.51.100.26", "port": 20},
                {"ip": "198.51.100.27", "port": 20},
                {"ip": "198.51.100.28", "port": 20},
                {"ip": "198.51.100.29", "port": 20},
            ],
        ),
    ],
)
def test_native_scan_replay_emits_exact_deterministic_evidence_before_eos(
    fixture_name: str,
    expected_flow_id: str,
    expected_unique_hosts: int,
    expected_unique_ports: int,
    expected_samples: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observations: list[str] = []

    def observing_parse_stream_line(raw: bytes) -> StreamRecord:
        record = parse_stream_line(raw)
        if isinstance(record, EndOfStreamV1):
            observations.append("end_of_stream")
        return record

    monkeypatch.setattr(replay, "parse_stream_line", observing_parse_stream_line)

    first_alerts: list[AlertV1] = []

    def observe_alert(alert: AlertV1) -> None:
        observations.append("alert")
        first_alerts.append(alert)

    first_result = replay.run_replay(
        FIXTURES / fixture_name,
        PortScanDetector(config=ScanConfig()),
        observe_alert,
    )
    first_observations = observations.copy()
    observations.clear()
    second_alerts: list[AlertV1] = []
    second_result = replay.run_replay(
        FIXTURES / fixture_name,
        PortScanDetector(config=ScanConfig()),
        second_alerts.append,
    )

    assert first_result == ReplayResult(
        events_processed=20,
        alerts_emitted=1,
        last_event_ts=1_700_000_004.75,
    )
    assert second_result == first_result
    assert len(first_alerts) == 1
    assert len(second_alerts) == 1
    alert = first_alerts[0]
    assert alert.flow_id == expected_flow_id
    assert alert.evidence.model_dump(mode="json") == {
        "deduplicated_attempts": 20,
        "unique_destination_hosts": expected_unique_hosts,
        "unique_destination_ports": expected_unique_ports,
        "unique_destination_endpoints": 15,
        "attempt_rate_per_second": 2.0,
        "observed_span_seconds": 4.75,
        "thresholds": {
            "minimum_attempts": 20,
            "minimum_unique_destination_ports": 15,
            "minimum_unique_destination_hosts": 15,
        },
        "destination_samples": expected_samples,
    }
    assert alert.model_dump_json() == second_alerts[0].model_dump_json()
    assert first_observations == ["alert", "end_of_stream"]


@pytest.mark.parametrize(
    ("fixture_name", "expected_events", "expected_last_event_ts"),
    [
        ("benign.pcap", 10, 1_700_000_002.25),
        ("retransmitted_syn.pcap", 20, 1_700_000_004.75),
    ],
)
def test_native_non_scan_replay_does_not_alert(
    fixture_name: str,
    expected_events: int,
    expected_last_event_ts: float,
) -> None:
    result, alerts = _collect_native_alerts(fixture_name)

    assert result == ReplayResult(
        events_processed=expected_events,
        alerts_emitted=0,
        last_event_ts=expected_last_event_ts,
    )
    assert alerts == []
