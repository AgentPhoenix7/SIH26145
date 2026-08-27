"""Incremental native-Zeek replay and subprocess failure handling."""

from __future__ import annotations

import os
import selectors
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import BinaryIO, cast

from sih26145.contracts.alerts import AlertV1
from sih26145.contracts.events import (
    MAX_LINE_BYTES,
    EndOfStreamV1,
    StreamContractError,
    TcpSynAttemptV1,
    parse_stream_line,
)
from sih26145.detection.port_scan import PortScanDetector
from sih26145.detection.scan_window import TimestampRegressionError

STDERR_TAIL_BYTES = 65_536
PROCESS_WAIT_SECONDS = 2.0
STDERR_SHUTDOWN_RESERVE_SECONDS = 0.05


@dataclass(frozen=True, slots=True)
class ReplayResult:
    """Accounting for one successfully validated replay stream."""

    events_processed: int
    alerts_emitted: int
    last_event_ts: float | None


class _StderrTail:
    """Thread-safe byte-exact tail buffer."""

    def __init__(self) -> None:
        self._chunks: deque[bytes] = deque()
        self._size = 0
        self._lock = threading.Lock()

    def append(self, chunk: bytes) -> None:
        with self._lock:
            self._chunks.append(chunk)
            self._size += len(chunk)
            while self._size > STDERR_TAIL_BYTES:
                excess = self._size - STDERR_TAIL_BYTES
                oldest = self._chunks.popleft()
                if len(oldest) > excess:
                    self._chunks.appendleft(oldest[excess:])
                    self._size -= excess
                    break
                self._size -= len(oldest)

    def snapshot(self) -> bytes:
        with self._lock:
            return b"".join(self._chunks)


class ReplayError(RuntimeError):
    """A replay failed with a safe, machine-readable diagnostic name."""

    def __init__(self, diagnostic: str, stderr_tail: _StderrTail | None = None) -> None:
        self.diagnostic = diagnostic
        self._stderr_tail = stderr_tail
        super().__init__(f"replay_error: {diagnostic}")

    @property
    def stderr_tail(self) -> bytes:
        """Return at most the latest 64 KiB written by the child to stderr."""

        if self._stderr_tail is None:
            return b""
        return self._stderr_tail.snapshot()


def _drain_stderr(
    pipe: BinaryIO,
    tail: _StderrTail,
    stop: threading.Event,
) -> None:
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(pipe, selectors.EVENT_READ)
            while not stop.is_set():
                if not selector.select(timeout=0.05):
                    continue
                chunk = os.read(pipe.fileno(), 8_192)
                if not chunk:
                    return
                tail.append(chunk)
                sys.stderr.write(chunk.decode("utf-8", errors="replace"))
                sys.stderr.flush()
    except (OSError, ValueError):
        return


def _read_bounded_line(stdout: BinaryIO, tail: _StderrTail) -> bytes | None:
    raw = stdout.readline(MAX_LINE_BYTES + 1)
    if raw == b"":
        return None
    if raw == b"\n":
        raise ReplayError("blank_stream_line", tail)
    if len(raw) > MAX_LINE_BYTES:
        raise ReplayError("stream_line_too_long", tail)
    return raw


def _parse_record(raw: bytes, tail: _StderrTail) -> TcpSynAttemptV1 | EndOfStreamV1:
    try:
        return parse_stream_line(raw)
    except StreamContractError:
        raise ReplayError("invalid_stream_record", tail) from None


def _after_eos_diagnostic(raw: bytes) -> str:
    first_line = raw.splitlines(keepends=True)[0]
    try:
        record = parse_stream_line(first_line)
    except StreamContractError:
        return "data_after_end_of_stream"
    if isinstance(record, EndOfStreamV1):
        return "duplicate_end_of_stream"
    return "data_after_end_of_stream"


def _remaining_post_eos_time(deadline: float, tail: _StderrTail) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0.0:
        raise ReplayError("post_end_of_stream_timeout", tail)
    return remaining


def _wait_for_post_eos_stdout(
    stdout: BinaryIO,
    deadline: float,
    tail: _StderrTail,
) -> None:
    with selectors.DefaultSelector() as selector:
        selector.register(stdout, selectors.EVENT_READ)
        remaining = _remaining_post_eos_time(deadline, tail)
        events = selector.select(
            max(0.0, remaining - STDERR_SHUTDOWN_RESERVE_SECONDS)
        )
        if not events:
            raise ReplayError("post_end_of_stream_timeout", tail)
        post_eos_bytes = os.read(stdout.fileno(), MAX_LINE_BYTES + 1)
    if post_eos_bytes:
        raise ReplayError(_after_eos_diagnostic(post_eos_bytes), tail)


def _join_stderr_before_deadline(
    thread: threading.Thread,
    deadline: float,
    tail: _StderrTail,
) -> None:
    thread.join(timeout=_remaining_post_eos_time(deadline, tail))
    if thread.is_alive():
        raise ReplayError("post_end_of_stream_timeout", tail)


def _stop_and_reap(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        process.wait()
        return
    process.terminate()
    try:
        process.wait(timeout=PROCESS_WAIT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def run_command(
    command: Sequence[str],
    detector: PortScanDetector,
    emit_alert: Callable[[AlertV1], None],
) -> ReplayResult:
    """Consume one bounded JSONL stream from a direct child process."""

    stderr_tail = _StderrTail()
    stderr_stop = threading.Event()
    process: subprocess.Popen[bytes] | None = None
    stderr_thread: threading.Thread | None = None
    post_eos_deadline: float | None = None

    with tempfile.TemporaryDirectory(prefix="sih26145-replay-") as working_directory:
        try:
            try:
                process = subprocess.Popen(
                    list(command),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=working_directory,
                    shell=False,
                    bufsize=0,
                )
            except OSError:
                raise ReplayError("child_start_failed", stderr_tail) from None

            if process.stdout is None or process.stderr is None:
                raise ReplayError("child_pipe_unavailable", stderr_tail)
            stdout = cast(BinaryIO, process.stdout)
            stderr = cast(BinaryIO, process.stderr)

            stderr_thread = threading.Thread(
                target=_drain_stderr,
                args=(stderr, stderr_tail, stderr_stop),
                name=f"sih26145-stderr-{process.pid}",
                daemon=True,
            )
            stderr_thread.start()

            events_processed = 0
            alerts_emitted = 0
            last_event_ts: float | None = None

            while True:
                raw = _read_bounded_line(stdout, stderr_tail)
                if raw is None:
                    raise ReplayError("missing_end_of_stream", stderr_tail)
                record = _parse_record(raw, stderr_tail)
                if isinstance(record, EndOfStreamV1):
                    eos = record
                    post_eos_deadline = time.monotonic() + PROCESS_WAIT_SECONDS
                    break

                try:
                    alert = detector.process(record)
                except TimestampRegressionError:
                    raise ReplayError("timestamp_regression", stderr_tail) from None
                except Exception:
                    raise ReplayError("event_processing_failed", stderr_tail) from None

                events_processed += 1
                last_event_ts = record.ts
                if alert is not None:
                    try:
                        emit_alert(alert)
                    except Exception:
                        raise ReplayError("alert_callback_failed", stderr_tail) from None
                    alerts_emitted += 1

            if eos.emitted_events != events_processed:
                raise ReplayError("end_of_stream_count_mismatch", stderr_tail)
            if eos.last_event_ts != last_event_ts:
                raise ReplayError("end_of_stream_timestamp_mismatch", stderr_tail)

            try:
                return_code = process.wait(
                    timeout=_remaining_post_eos_time(post_eos_deadline, stderr_tail)
                )
            except subprocess.TimeoutExpired:
                raise ReplayError("post_end_of_stream_timeout", stderr_tail) from None

            _wait_for_post_eos_stdout(stdout, post_eos_deadline, stderr_tail)
            _join_stderr_before_deadline(
                stderr_thread,
                post_eos_deadline,
                stderr_tail,
            )
            if return_code != 0:
                raise ReplayError("child_exit_nonzero", stderr_tail)

            return ReplayResult(
                events_processed=events_processed,
                alerts_emitted=alerts_emitted,
                last_event_ts=last_event_ts,
            )
        finally:
            if process is not None:
                _stop_and_reap(process)
                if process.stdout is not None:
                    process.stdout.close()
            if stderr_thread is not None:
                stderr_stop.set()
                join_timeout = PROCESS_WAIT_SECONDS
                if post_eos_deadline is not None:
                    join_timeout = max(0.0, post_eos_deadline - time.monotonic())
                stderr_thread.join(timeout=join_timeout)
            if process is not None and process.stderr is not None:
                process.stderr.close()


def run_replay(
    pcap_path: Path,
    detector: PortScanDetector,
    emit_alert: Callable[[AlertV1], None],
) -> ReplayResult:
    """Replay one existing regular PCAP through the packaged native-Zeek policy."""

    if not pcap_path.is_file():
        raise ReplayError("pcap_not_regular_file")
    try:
        resolved_pcap = pcap_path.resolve(strict=True)
    except OSError:
        raise ReplayError("pcap_not_regular_file") from None
    if not resolved_pcap.is_file():
        raise ReplayError("pcap_not_regular_file")

    policy_resource = resources.files("sih26145").joinpath(
        "zeek/emit_syn_attempts.zeek"
    )
    with resources.as_file(policy_resource) as policy_path:
        command = ("zeek", "-b", "-r", str(resolved_pcap), str(policy_path))
        return run_command(command, detector, emit_alert)
