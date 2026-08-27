from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

import sih26145.replay as replay
from sih26145.contracts.alerts import AlertV1
from sih26145.contracts.events import EndOfStreamV1, parse_stream_line
from sih26145.detection.port_scan import PortScanDetector, ScanConfig
from sih26145.replay import ReplayError, ReplayResult, run_command, run_replay

FAKE_ZEEK = Path("tests/helpers/fake_zeek.py").resolve()
UNTRUSTED_MARKERS = ("203.0.113.244", "untrusted data after eos")


def _command(mode: str, pid_path: Path) -> tuple[str, ...]:
    return sys.executable, str(FAKE_ZEEK), mode, str(pid_path)


def _detector() -> PortScanDetector:
    return PortScanDetector(config=ScanConfig())


def _pid(pid_path: Path) -> int:
    return int(pid_path.read_text(encoding="ascii"))


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _stderr_threads() -> list[threading.Thread]:
    return [
        thread
        for thread in threading.enumerate()
        if thread.name.startswith("sih26145-stderr-")
    ]


@pytest.mark.integration
def test_processes_events_and_emits_alert_before_accepting_eos(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    observations: list[str] = []
    alert_output: list[str] = []
    real_parse = parse_stream_line

    def observe_parse(raw: bytes) -> Any:
        record = real_parse(raw)
        if isinstance(record, EndOfStreamV1):
            observations.append("eos")
        return record

    def emit_alert(alert: AlertV1) -> None:
        observations.append("alert")
        alert_output.append(alert.model_dump_json())

    monkeypatch.setattr(replay, "parse_stream_line", observe_parse)
    result = run_command(_command("happy", tmp_path / "pid"), _detector(), emit_alert)

    assert result == ReplayResult(
        events_processed=20,
        alerts_emitted=1,
        last_event_ts=101.9,
    )
    assert observations == ["alert", "eos"]
    assert len(alert_output) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "fake child diagnostic" in captured.err
    assert "fake child diagnostic" not in alert_output[0]


@pytest.mark.integration
def test_uses_argument_sequence_no_shell_and_isolated_temporary_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_popen = subprocess.Popen
    observed: dict[str, Any] = {}

    def popen_spy(args: Sequence[str], *popen_args: Any, **kwargs: Any) -> Any:
        observed["args"] = args
        observed["kwargs"] = kwargs.copy()
        observed["cwd_exists"] = Path(kwargs["cwd"]).is_dir()
        return real_popen(args, *popen_args, **kwargs)

    monkeypatch.setattr("sih26145.replay.subprocess.Popen", popen_spy)
    command = _command("happy", tmp_path / "pid")

    run_command(command, _detector(), lambda _alert: None)

    assert observed["args"] == list(command)
    kwargs = observed["kwargs"]
    assert kwargs["shell"] is False
    assert kwargs["bufsize"] == 0
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["stdout"] is subprocess.PIPE
    assert kwargs["stderr"] is subprocess.PIPE
    assert "start_new_session" not in kwargs
    assert "process_group" not in kwargs
    assert observed["cwd_exists"] is True
    assert Path(kwargs["cwd"]) != Path.cwd()
    assert not Path(kwargs["cwd"]).exists()


@pytest.mark.integration
@pytest.mark.parametrize(
    ("mode", "diagnostic"),
    [
        ("blank", "blank_stream_line"),
        ("oversized", "stream_line_too_long"),
        ("invalid-utf8", "invalid_stream_record"),
        ("malformed-json", "invalid_stream_record"),
        ("unknown-record", "invalid_stream_record"),
        ("regression", "timestamp_regression"),
        ("missing-eos", "missing_end_of_stream"),
        ("duplicate-eos", "duplicate_end_of_stream"),
        ("premature-eos", "end_of_stream_count_mismatch"),
        ("count-mismatch", "end_of_stream_count_mismatch"),
        ("timestamp-mismatch", "end_of_stream_timestamp_mismatch"),
        ("data-after-eos", "data_after_end_of_stream"),
        ("nonzero", "child_exit_nonzero"),
    ],
)
def test_stream_and_process_failures_are_safe_and_reaped(
    mode: str,
    diagnostic: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pid_path = tmp_path / "pid"

    with pytest.raises(ReplayError) as captured:
        run_command(_command(mode, pid_path), _detector(), lambda _alert: None)

    assert captured.value.diagnostic == diagnostic
    assert str(captured.value) == f"replay_error: {diagnostic}"
    assert captured.value.__cause__ is None
    combined_diagnostics = str(captured.value) + capsys.readouterr().err
    assert all(marker not in combined_diagnostics for marker in UNTRUSTED_MARKERS)
    assert not _process_exists(_pid(pid_path))
    assert _stderr_threads() == []


@pytest.mark.integration
def test_failed_child_that_ignores_sigterm_is_killed_and_reaped(tmp_path: Path) -> None:
    pid_path = tmp_path / "pid"
    started = time.monotonic()

    with pytest.raises(ReplayError) as captured:
        run_command(_command("ignore-sigterm", pid_path), _detector(), lambda _alert: None)

    elapsed = time.monotonic() - started
    assert captured.value.diagnostic == "invalid_stream_record"
    assert elapsed >= 2.0
    assert elapsed < 4.0
    assert not _process_exists(_pid(pid_path))
    assert _stderr_threads() == []


@pytest.mark.integration
def test_stderr_is_drained_without_deadlock_and_retains_only_latest_64_kib(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pid_path = tmp_path / "pid"

    with pytest.raises(ReplayError) as captured:
        run_command(_command("stderr-flood", pid_path), _detector(), lambda _alert: None)

    assert captured.value.diagnostic == "child_exit_nonzero"
    assert captured.value.stderr_tail == b"B" * 65_536
    assert len(captured.value.stderr_tail) == 65_536
    assert len(capsys.readouterr().err.encode()) == 81_920
    assert not _process_exists(_pid(pid_path))
    assert _stderr_threads() == []


@pytest.mark.integration
def test_child_must_exit_within_two_seconds_after_eos(tmp_path: Path) -> None:
    pid_path = tmp_path / "pid"
    started = time.monotonic()

    with pytest.raises(ReplayError) as captured:
        run_command(_command("hang-after-eos", pid_path), _detector(), lambda _alert: None)

    elapsed = time.monotonic() - started
    assert captured.value.diagnostic == "post_end_of_stream_timeout"
    assert elapsed >= 2.0
    assert elapsed < 4.0
    assert not _process_exists(_pid(pid_path))
    assert _stderr_threads() == []


def test_run_replay_resolves_exact_native_zeek_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pcap = tmp_path / "capture with spaces.pcap"
    pcap.write_bytes(b"pcap placeholder")
    observed: list[tuple[str, ...]] = []

    def fake_run_command(
        command: Sequence[str],
        detector: PortScanDetector,
        emit_alert: Callable[[AlertV1], None],
    ) -> ReplayResult:
        del detector, emit_alert
        observed.append(tuple(command))
        return ReplayResult(0, 0, None)

    monkeypatch.setattr(replay, "run_command", fake_run_command)

    result = run_replay(pcap, _detector(), lambda _alert: None)

    assert result == ReplayResult(0, 0, None)
    assert len(observed) == 1
    command = observed[0]
    assert command[:4] == ("zeek", "-b", "-r", str(pcap))
    assert len(command) == 5
    assert command[4].endswith("/sih26145/zeek/emit_syn_attempts.zeek")


@pytest.mark.parametrize("path_kind", ["missing", "directory"])
def test_run_replay_rejects_non_file_before_process_creation(
    path_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pcap = tmp_path / "capture.pcap"
    if path_kind == "directory":
        pcap.mkdir()

    def unexpected_run_command(*_args: Any, **_kwargs: Any) -> ReplayResult:
        pytest.fail("run_command must not start for an invalid PCAP path")

    monkeypatch.setattr(replay, "run_command", unexpected_run_command)

    with pytest.raises(ReplayError) as captured:
        run_replay(pcap, _detector(), lambda _alert: None)

    assert captured.value.diagnostic == "pcap_not_regular_file"
    assert str(pcap) not in str(captured.value)
