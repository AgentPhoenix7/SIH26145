from __future__ import annotations

import os
import signal
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
from sih26145.detection.pipeline import DetectionPipeline
from sih26145.detection.port_scan import PortScanDetector, ScanConfig
from sih26145.detection.scan_window import StateLimitExceeded, StateLimits
from sih26145.detection.syn_flood import SynFloodConfig, SynFloodDetector
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
        thread for thread in threading.enumerate() if thread.name.startswith("sih26145-stderr-")
    ]


def _terminate_fixture_process(pid: int) -> None:
    if not _process_exists(pid):
        return
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 1.0
    while _process_exists(pid) and time.monotonic() < deadline:
        time.sleep(0.01)


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
    assert captured.err == ""
    assert "fake child diagnostic" not in alert_output[0]


@pytest.mark.integration
def test_processes_every_pipeline_alert_before_accepting_eos(tmp_path: Path) -> None:
    alerts: list[AlertV1] = []
    detector_pipeline = DetectionPipeline(
        port_scan=PortScanDetector(
            config=ScanConfig(
                minimum_attempts=1,
                minimum_unique_destination_ports=1,
                minimum_unique_destination_hosts=1,
            )
        ),
        syn_flood=SynFloodDetector(
            config=SynFloodConfig(minimum_syn_events=1, minimum_unique_sources=1)
        ),
    )

    result = run_command(
        _command("one-event", tmp_path / "pid"),
        detector_pipeline,
        alerts.append,
    )

    assert result == ReplayResult(
        events_processed=1,
        alerts_emitted=2,
        last_event_ts=100.0,
    )
    assert [alert.threat_class for alert in alerts] == ["PORT_SCAN", "SYN_FLOOD"]


@pytest.mark.integration
def test_state_limit_failure_keeps_its_named_invariant_and_reaps_child(
    tmp_path: Path,
) -> None:
    pid_path = tmp_path / "pid"
    detector = PortScanDetector(
        config=ScanConfig(
            minimum_attempts=2,
            minimum_unique_destination_ports=2,
            minimum_unique_destination_hosts=2,
        ),
        limits=StateLimits(
            max_active_sources=2,
            max_attempts_per_source=2,
            max_total_attempts=4,
            max_dedup_uids=4,
            max_cooldown_sources=2,
            dedup_ttl_seconds=60.0,
        ),
    )

    with pytest.raises(StateLimitExceeded) as captured:
        run_command(_command("happy", pid_path), detector, lambda _alert: None)

    assert captured.value.limit_name == "max_attempts_per_source"
    assert not _process_exists(_pid(pid_path))
    assert _stderr_threads() == []


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
def test_partial_pre_eos_record_times_out_and_reaps_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pid_path = tmp_path / "pid"
    captured: list[BaseException] = []
    monkeypatch.setattr(replay, "PROCESS_WAIT_SECONDS", 0.5)

    def invoke_replay() -> None:
        try:
            run_command(
                _command("partial-line-hang", pid_path),
                _detector(),
                lambda _alert: None,
            )
        except BaseException as exc:
            captured.append(exc)

    thread = threading.Thread(target=invoke_replay, daemon=True)
    thread.start()
    thread.join(timeout=1.5)
    completed_within_bound = not thread.is_alive()

    try:
        assert completed_within_bound, "replay remained blocked on a partial pre-EOS record"
    finally:
        if thread.is_alive() and pid_path.exists():
            _terminate_fixture_process(_pid(pid_path))
        thread.join(timeout=1.0)

    assert len(captured) == 1
    assert isinstance(captured[0], ReplayError)
    assert captured[0].diagnostic == "pre_end_of_stream_timeout"
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
    assert capsys.readouterr().err == ""
    assert not _process_exists(_pid(pid_path))
    assert _stderr_threads() == []


@pytest.mark.integration
def test_untrusted_child_stderr_is_retained_but_not_echoed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pid_path = tmp_path / "pid"

    with pytest.raises(ReplayError) as captured:
        run_command(
            _command("stderr-untrusted", pid_path),
            _detector(),
            lambda _alert: None,
        )

    assert captured.value.diagnostic == "child_exit_nonzero"
    assert captured.value.stderr_tail == (b"untrusted child stderr endpoint=203.0.113.244:443\n")
    assert capsys.readouterr().err == ""
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


@pytest.mark.integration
def test_post_eos_sigterm_resistant_child_gets_no_fresh_cleanup_budget(
    tmp_path: Path,
) -> None:
    pid_path = tmp_path / "pid"
    started = time.monotonic()

    with pytest.raises(ReplayError) as captured:
        run_command(
            _command("ignore-sigterm-after-eos", pid_path),
            _detector(),
            lambda _alert: None,
        )

    elapsed = time.monotonic() - started
    assert captured.value.diagnostic == "post_end_of_stream_timeout"
    assert elapsed >= 2.0
    assert elapsed < 2.75
    assert not _process_exists(_pid(pid_path))
    assert _stderr_threads() == []


@pytest.mark.integration
def test_post_eos_deadline_covers_descendant_inherited_stdout_and_stderr(
    tmp_path: Path,
) -> None:
    pid_path = tmp_path / "pid"
    descendant_pid_path = tmp_path / "pid.descendant"
    started = time.monotonic()

    try:
        with pytest.raises(ReplayError) as captured:
            run_command(
                _command("inherited-pipes-after-eos", pid_path),
                _detector(),
                lambda _alert: None,
            )

        elapsed = time.monotonic() - started
        descendant_pid = _pid(descendant_pid_path)
        assert captured.value.diagnostic == "post_end_of_stream_timeout"
        assert elapsed >= 1.8
        assert elapsed < 2.5
        assert not _process_exists(_pid(pid_path))
        assert _process_exists(descendant_pid)
        assert _stderr_threads() == []
    finally:
        if descendant_pid_path.exists():
            _terminate_fixture_process(_pid(descendant_pid_path))


@pytest.mark.integration
def test_post_eos_failure_cleanup_does_not_start_a_fresh_join_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pid_path = tmp_path / "pid"
    descendant_pid_path = tmp_path / "pid.descendant"
    release_drain = threading.Event()

    def deliberately_stubborn_drain(*_args: Any) -> None:
        release_drain.wait(timeout=6.0)

    monkeypatch.setattr(replay, "_drain_stderr", deliberately_stubborn_drain)
    started = time.monotonic()

    try:
        with pytest.raises(ReplayError) as captured:
            run_command(
                _command("inherited-pipes-after-eos", pid_path),
                _detector(),
                lambda _alert: None,
            )

        elapsed = time.monotonic() - started
        assert captured.value.diagnostic == "post_end_of_stream_timeout"
        assert elapsed >= 2.0
        assert elapsed < 2.75
        assert not _process_exists(_pid(pid_path))
    finally:
        release_drain.set()
        if descendant_pid_path.exists():
            _terminate_fixture_process(_pid(descendant_pid_path))
        for thread in _stderr_threads():
            thread.join(timeout=1.0)

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
    assert command[:5] == ("zeek", "-D", "-b", "-r", str(pcap))
    assert len(command) == 6
    assert command[5].endswith("/sih26145/zeek/emit_syn_attempts.zeek")


def test_run_replay_canonicalizes_relative_pcap_before_isolated_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    relative_pcap = Path("relative-capture.pcap")
    relative_pcap.write_bytes(b"pcap placeholder")
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

    run_replay(relative_pcap, _detector(), lambda _alert: None)

    assert observed[0][4] == str(relative_pcap.resolve())
    assert Path(observed[0][4]).is_absolute()


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
