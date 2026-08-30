"""Measure real end-to-end throughput, alert latency, CPU, and memory.

This tool replays one deterministic PCAP through the existing (frozen)
three-detector pipeline exactly as ``sih26145-replay`` does, adding only
wall-clock timing around each event, around alert emission, and around the
whole run. It changes no detector, model, or contract behavior.

Two latency samples are reported:

- "event processing latency": wall-clock time for ``DetectionPipeline.process``
  to return for one validated event (Python-side detector work only, no I/O).
- "alert latency": wall-clock time from the start of that same ``process``
  call to the moment the alert has actually been serialized and
  written+flushed by an emit callback that performs the identical work as
  the real CLI's ``sih26145.cli.emit_alert`` (JSON serialization, then a
  write and flush) into a real OS pipe drained by a background reader
  thread (see ``_ConsumedPipe``) -- the same kernel write/consume path
  (including finite-buffer backpressure) as the real CLI's ``sys.stdout``
  when redirected to a consuming process, which is how ``sih26145-replay``
  is actually used, rather than ``os.devnull``'s always-instant sink.
  Because ``run_command`` calls the emit callback immediately after
  ``process`` returns for the causing event, and processes one event fully
  (including all of its emits) before reading the next line, this covers
  everything from the start of detector work through actual alert
  emission -- but it is **not** the full event-acceptance-to-alert-
  availability interval: ``run_command`` (the frozen, unmodified replay
  path this benchmark deliberately does not alter) has already read the
  raw JSONL line and completed ``_parse_record``'s JSON decode and
  Pydantic contract validation before this timer starts, so "alert
  latency" here is post-validation detector-to-emission latency, not
  end-to-end from raw record availability. On inputs where line-read or
  parse/validation cost is material, add that separately measured cost
  before treating this as a full operational bound.

CPU time and peak resident set size are read from ``resource.getrusage``
separately for the process actually performing the replay (``RUSAGE_SELF``)
and for the native Zeek child it spawns and fully waits for
(``RUSAGE_CHILDREN``). That process is a dedicated worker subprocess (see
``run_benchmark`` and ``_measure_replay``) that spawns no child other than
Zeek and calls the fixture generator itself for nothing, so its
``RUSAGE_CHILDREN`` reliably isolates Zeek's own contribution with no other
reaped child to conflate it with, and its ``RUSAGE_SELF`` reflects only its
own replay work, not the fixture generator's. Combined CPU seconds are a
straightforward sum; combined peak RSS is a conservative upper bound (the
two processes' peaks are not necessarily simultaneous, so the true combined
peak can only be lower).

Per-event bookkeeping (processing-duration samples, emitted alerts, alert
latencies) is kept in plain lists that grow with the input's event count,
which would be unbounded for an arbitrary ``--pcap``. To keep this bounded
by a known, fixed size rather than accepting arbitrary large input, the
supplied PCAP is validated against a size and SHA-256 digest the
deterministic generator function itself produces right now -- not a
co-located manifest file, which would be just as caller-controlled as the
PCAP -- and its size is checked before any of its bytes are read, so an
arbitrarily large capture is never loaded into memory here; its digest is
computed by streaming fixed-size chunks rather than loading the whole file
at once. The completed replay's event count and per-class alert counts are
then checked against that same generated fixture's own recorded
expectations, so a fixture that no longer produces its expected workload
(e.g. because Zeek, a detector default, or the packaged DGA model changed)
cannot silently yield benchmark figures for a different workload than the
one being reported.

The generator itself builds a ~21,431-packet object graph and the full
encoded capture to compute that expected size/digest/manifest. That work
runs in its own throwaway subprocess (see ``_generator_fixture_info``),
separate from the worker subprocess that performs and measures the actual
replay, so it never counts toward either the driver's or the worker's
``resource.getrusage`` samples -- neither the reported Python figures nor
the reported Zeek figures (which would otherwise be polluted by way of the
driver's ``RUSAGE_CHILDREN`` if both ran in one process) reflect the
fixture generator's own memory or CPU footprint.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import resource
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any, TextIO

from sih26145.contracts.alerts import AlertV1
from sih26145.detection.pipeline import DetectionPipeline
from sih26145.detection.port_scan import PortScanDetector, ScanConfig
from sih26145.detection.scan_window import StateLimitExceeded
from sih26145.detection.syn_flood import SynFloodConfig, SynFloodDetector
from sih26145.replay import ReplayError, ReplayResult, run_replay
from sih26145.runtime import build_detection_pipeline

DEFAULT_PCAP = Path("tests/fixtures/benchmark/sustained_load.pcap")

# Invoked as a script path (not `-m`) so this works regardless of the
# caller's own working directory or package context, matching how the
# generator is already exercised as a direct script elsewhere.
_GENERATOR_SCRIPT = Path(__file__).resolve().parent / "generate_benchmark_fixture.py"

_READ_CHUNK_BYTES = 1_048_576


class UnvalidatedPcapError(ValueError):
    """The supplied PCAP does not match the currently generated benchmark fixture."""


class UnexpectedReplayResultError(ValueError):
    """The completed replay did not match the generated fixture's own expectations."""


def _generator_fixture_info() -> dict[str, Any]:
    """Query the generator's current pcap size/digest/manifest in a fresh subprocess.

    Building the ~21,431-packet object graph and the full encoded capture
    happens inside that subprocess, not here, so it never counts toward
    this process's own ``resource.getrusage(RUSAGE_SELF)`` peak-RSS sample
    -- which ``run_benchmark`` reports as the detector replay's memory
    footprint, not the fixture generator's.
    """

    result = subprocess.run(
        [sys.executable, str(_GENERATOR_SCRIPT), "--fixture-info"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=120.0,
    )
    if result.returncode != 0:
        raise UnvalidatedPcapError(
            "could not query tools/generate_benchmark_fixture.py for its current "
            f"output: exit {result.returncode}: {result.stderr.strip()}"
        )
    info: dict[str, Any] = json.loads(result.stdout)
    return info


def _validate_pcap_matches_generated_fixture(pcap_path: Path, dest_path: Path) -> bytes:
    """Reject any PCAP that isn't exactly what the generator currently produces.

    Trust is anchored to the deterministic generator's own current output,
    not a co-located manifest file the caller could fabricate to match an
    arbitrary large capture. This does not use a preliminary ``stat()`` size
    check followed by a separate, unbounded read loop: a pathname could be
    replaced, retargeted, or appended between that check and the read that
    follows it, so a growing regular file, or a FIFO/character device
    swapped in afterward, could make an unbounded loop copy/hash until EOF
    (or block forever) despite the claimed fixed input bound. Instead, the
    candidate is opened once, that open descriptor's own ``fstat`` rejects
    anything that isn't a regular file (closing the specific "size lies,
    e.g. reports 0" failure mode of special files -- a plain, non-race FIFO
    supplied directly is separately rejected by an ``is_file()`` pre-check,
    which never opens the path and so cannot itself block on a FIFO with no
    writer), and the read loop stops after at most ``expected_size + 1``
    bytes regardless of what the file claims or how large it grows, so
    hashing/copying more than one byte past the expected size is
    structurally impossible.

    Every chunk read from ``pcap_path`` while computing that digest is also
    written to ``dest_path``, so ``dest_path`` ends up holding exactly the
    bytes this function validated -- not merely "whatever is at
    ``pcap_path`` right now". Without this, ``pcap_path`` could be replaced
    (a retargeted symlink, a swapped file) after this function returns but
    before the worker subprocess later opens it for replay, letting an
    alternate capture that happens to match the fixture's event/alert
    counts pass verification while its Mbps is computed from the *original*
    fixture's ``total_captured_bytes`` -- invalid benchmark evidence.
    Callers must replay ``dest_path``, not ``pcap_path``, for this guarantee
    to hold.

    Returns the manifest JSON bytes (re-serialized from the generator's
    subprocess output) for the caller to parse.
    """

    info = _generator_fixture_info()
    expected_size: int = info["pcap_size"]
    expected_sha256: str = info["pcap_sha256"]

    if not pcap_path.is_file():
        raise UnvalidatedPcapError(f"{pcap_path} is not a regular file")

    try:
        source = pcap_path.open("rb")
    except OSError as exc:
        raise UnvalidatedPcapError(f"cannot open {pcap_path}: {exc}") from exc

    digest = hashlib.sha256()
    total_read = 0
    read_limit = expected_size + 1
    with source, dest_path.open("wb") as dest:
        try:
            descriptor_mode = os.fstat(source.fileno()).st_mode
        except OSError as exc:
            raise UnvalidatedPcapError(f"cannot stat {pcap_path}: {exc}") from exc
        if not stat.S_ISREG(descriptor_mode):
            raise UnvalidatedPcapError(f"{pcap_path} is not a regular file")

        while total_read < read_limit:
            chunk = source.read(min(_READ_CHUNK_BYTES, read_limit - total_read))
            if not chunk:
                break
            total_read += len(chunk)
            digest.update(chunk)
            dest.write(chunk)

    if total_read != expected_size:
        raise UnvalidatedPcapError(
            f"{pcap_path} is {'more than ' if total_read >= read_limit else ''}"
            f"{total_read} bytes; tools.generate_benchmark_fixture currently "
            f"produces exactly {expected_size} bytes. Regenerate it with "
            "tools/generate_benchmark_fixture.py."
        )
    if digest.hexdigest() != expected_sha256:
        raise UnvalidatedPcapError(
            f"{pcap_path} does not match the bytes tools.generate_benchmark_fixture "
            "currently produces. Regenerate it with tools/generate_benchmark_fixture.py."
        )

    return json.dumps(info["manifest"], sort_keys=True).encode("utf-8")


# Matches this codebase's own largest existing hard state cap (SynFloodState's
# global event limit, see docs/architecture.md). Bounds the per-event bookkeeping
# lists below regardless of how a candidate pcap/manifest reached this process --
# including the internal ``--worker-manifest`` entry point, which trusts the
# manifest it is given without re-deriving it from the generator itself (doing so
# would require spawning that generator as a reaped child of this same worker,
# which would corrupt the Zeek RSS/CPU figures measured via RUSAGE_CHILDREN; see
# run_benchmark's docstring). A caller invoking that internal flag directly with
# an arbitrarily large pcap and a matching but unvalidated manifest is therefore
# still bounded here, independent of manifest trust.
_MAX_MEASURED_EVENTS = 100_000

# The real manifest run_benchmark() writes for its own worker re-invocation is
# ~16 KiB for the committed benchmark fixture. This bound is generous headroom
# above that, not a tuned production limit: its purpose is to stop a direct
# ``--worker-manifest`` invocation from reading and json.loads()-ing an
# arbitrarily large caller-supplied file into memory before _MAX_MEASURED_EVENTS
# above ever gets a chance to bound anything -- the same "still bounded here,
# independent of manifest trust" guarantee the event cap gives replay accounting,
# applied to the manifest read itself.
_MAX_WORKER_MANIFEST_BYTES = 1_048_576


@dataclass(slots=True)
class EventSample:
    """One event's processing duration and the alerts it produced."""

    duration_seconds: float
    alert_count: int


@dataclass(slots=True)
class _EmissionClock:
    """Shared correlation point between an event's ``process`` start and its emit."""

    pending_start: float | None = None


class TimingPipeline(DetectionPipeline):
    """``DetectionPipeline`` subclass that records per-event wall-clock time.

    Subclassing (rather than wrapping) is required because the replay
    boundary only routes DNS events to a detector that is actually an
    instance of ``DetectionPipeline`` (see ``sih26145.replay.run_command``).
    The parent dataclass is frozen and uses ``__slots__``, so the extra
    ``_samples``/``_clock`` attributes are attached with ``object.__setattr__``
    the same way frozen dataclasses are normally extended.

    ``_clock.pending_start`` is set to this call's start time so the emit
    callback constructed by ``_make_emit_alert`` below can measure the
    detector-to-emission interval, not detector time alone -- this call's
    start is already after ``run_command`` has read and parsed/validated
    the record (see the module docstring), so it is post-validation
    latency, not the full event-acceptance-to-alert-availability interval.
    """

    _samples: list[EventSample]
    _clock: _EmissionClock

    def __init__(
        self,
        inner: DetectionPipeline,
        samples: list[EventSample],
        clock: _EmissionClock,
    ) -> None:
        object.__setattr__(self, "port_scan", inner.port_scan)
        object.__setattr__(self, "syn_flood", inner.syn_flood)
        object.__setattr__(self, "dga", inner.dga)
        object.__setattr__(self, "_samples", samples)
        object.__setattr__(self, "_clock", clock)

    def process(self, event: Any) -> tuple[AlertV1, ...]:
        if len(self._samples) >= _MAX_MEASURED_EVENTS:
            raise StateLimitExceeded("benchmark_measured_events")
        start = time.perf_counter()
        self._clock.pending_start = start
        alerts = super().process(event)
        duration = time.perf_counter() - start
        self._samples.append(EventSample(duration_seconds=duration, alert_count=len(alerts)))
        return alerts


class _ConsumedPipe:
    """A real OS pipe whose write end is drained by a background thread.

    Writing to and flushing this pipe's write end exercises the same
    kernel write path -- including finite-buffer backpressure -- as the
    real CLI's ``sys.stdout`` when redirected to a consuming process (the
    README's actual demo usage), unlike ``os.devnull``, which always
    accepts a write instantly regardless of any downstream reader.
    """

    def __init__(self) -> None:
        read_fd, write_fd = os.pipe()
        self._read_file = os.fdopen(read_fd, "rb")
        self.write_file: TextIO = os.fdopen(write_fd, "w", encoding="utf-8")
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def _drain(self) -> None:
        while self._read_file.read(65_536):
            pass

    def __enter__(self) -> TextIO:
        return self.write_file

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.write_file.close()
        self._thread.join(timeout=5.0)
        self._read_file.close()


def _make_emit_alert(
    clock: _EmissionClock,
    alerts: list[AlertV1],
    alert_latencies: list[float],
    sink: TextIO,
) -> Any:
    """Build an emit callback that performs the CLI's real emission work.

    Mirrors ``sih26145.cli.emit_alert`` (JSON serialization, then write and
    flush) so timed "alert latency" reflects actual emission cost, not just
    detector processing. ``sink`` should be a ``_ConsumedPipe``'s write end
    (a real, actively drained OS pipe) rather than the terminal, to keep
    benchmark output clean while still exercising a real consumed-write path.
    """

    def emit_alert(alert: AlertV1) -> None:
        sink.write(alert.model_dump_json() + "\n")
        sink.flush()
        end = time.perf_counter()
        if clock.pending_start is not None:
            alert_latencies.append(end - clock.pending_start)
        alerts.append(alert)

    return emit_alert


def percentile(values: Sequence[float], fraction: float) -> float:
    """Return the linear-interpolated percentile of a non-empty sequence."""

    if not values:
        raise ValueError("percentile of an empty sequence is undefined")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = fraction * (len(ordered) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * weight


@dataclass(slots=True)
class LatencyStats:
    count: int
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float

    def as_dict(self) -> dict[str, float | int]:
        return {
            "count": self.count,
            "mean_ms": self.mean_ms,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
            "max_ms": self.max_ms,
        }


def _latency_stats(durations_seconds: Sequence[float]) -> LatencyStats | None:
    if not durations_seconds:
        return None
    millis = [value * 1_000.0 for value in durations_seconds]
    return LatencyStats(
        count=len(millis),
        mean_ms=sum(millis) / len(millis),
        p50_ms=percentile(millis, 0.50),
        p95_ms=percentile(millis, 0.95),
        p99_ms=percentile(millis, 0.99),
        max_ms=max(millis),
    )


def _zeek_version() -> str | None:
    try:
        result = subprocess.run(
            ["zeek", "-version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() or None


@dataclass(slots=True)
class BenchmarkReport:
    """Everything needed to reproduce and cite one benchmark run."""

    pcap_path: str
    pcap_bytes: int
    traffic_bytes: int
    events_processed: int
    alerts_emitted: int
    wall_clock_seconds: float
    events_per_second: float
    megabits_per_second: float
    event_latency: LatencyStats
    alert_latency: LatencyStats | None
    python_cpu_user_seconds: float
    python_cpu_system_seconds: float
    python_peak_rss_kib: int
    zeek_cpu_user_seconds: float
    zeek_cpu_system_seconds: float
    zeek_peak_rss_kib: int
    environment: dict[str, str | int | None]

    def as_dict(self) -> dict[str, Any]:
        combined_cpu_seconds = (
            self.python_cpu_user_seconds
            + self.python_cpu_system_seconds
            + self.zeek_cpu_user_seconds
            + self.zeek_cpu_system_seconds
        )
        return {
            "schema_version": "benchmark_report_v1",
            "pcap_path": self.pcap_path,
            "pcap_bytes": self.pcap_bytes,
            "traffic_bytes": self.traffic_bytes,
            "events_processed": self.events_processed,
            "alerts_emitted": self.alerts_emitted,
            "wall_clock_seconds": self.wall_clock_seconds,
            "throughput": {
                "events_per_second": self.events_per_second,
                # Computed from `traffic_bytes` (summed captured Ethernet frame
                # lengths from the fixture's own manifest), not `pcap_bytes` (the
                # pcap *file* size), which also counts the 24-byte global header
                # plus a 16-byte record header per packet -- capture-format
                # overhead unrelated to network traffic volume.
                "megabits_per_second": self.megabits_per_second,
            },
            "event_processing_latency": self.event_latency.as_dict(),
            "alert_latency": (self.alert_latency.as_dict() if self.alert_latency else None),
            "cpu": {
                "python_user_seconds": self.python_cpu_user_seconds,
                "python_system_seconds": self.python_cpu_system_seconds,
                "zeek_user_seconds": self.zeek_cpu_user_seconds,
                "zeek_system_seconds": self.zeek_cpu_system_seconds,
                "combined_seconds": combined_cpu_seconds,
            },
            "memory": {
                "python_peak_rss_kib": self.python_peak_rss_kib,
                "zeek_peak_rss_kib": self.zeek_peak_rss_kib,
                "combined_peak_rss_kib_upper_bound": (
                    self.python_peak_rss_kib + self.zeek_peak_rss_kib
                ),
            },
            "environment": self.environment,
        }


@dataclass(slots=True)
class _Collected:
    samples: list[EventSample] = field(default_factory=list)
    alerts: list[AlertV1] = field(default_factory=list)
    alert_latencies_seconds: list[float] = field(default_factory=list)


def _verify_replay_matches_manifest(
    manifest: dict[str, Any],
    *,
    result: ReplayResult,
    alerts: list[AlertV1],
) -> None:
    """Fail loudly if the completed replay didn't produce the expected workload.

    A regressed fixture (Zeek output behavior, a detector default, or the
    packaged DGA model changing without the PCAP bytes changing) could
    otherwise let this command exit successfully while silently reporting
    benchmark figures for a different workload than the one being cited.
    """

    expected_events = manifest["expected_processed_events"]
    if result.events_processed != expected_events:
        raise UnexpectedReplayResultError(
            f"replay processed {result.events_processed} events; "
            f"the generated fixture's manifest expects {expected_events}"
        )

    expected_by_class: dict[str, int] = manifest["expected_alert_count_by_class"]
    actual_by_class = dict(Counter(alert.threat_class for alert in alerts))
    if actual_by_class != expected_by_class:
        raise UnexpectedReplayResultError(
            f"replay produced alerts {actual_by_class}; "
            f"the generated fixture's manifest expects {expected_by_class}"
        )


def _measure_replay(pcap_path: Path, manifest: dict[str, Any]) -> BenchmarkReport:
    """Perform the actual measured replay and return its report.

    Callers must have already validated (in a separate process) that
    ``pcap_path`` is byte-identical to the generator's current output and
    that ``manifest`` is that same generator run's own recorded
    expectations; this function trusts both without re-deriving them. It
    spawns no child process other than the native Zeek child ``run_replay``
    starts and fully waits for, so ``RUSAGE_CHILDREN`` cleanly isolates
    Zeek's own CPU/RSS with no other reaped child to conflate it with, and
    its own ``RUSAGE_SELF`` reflects only this replay's Python-side work,
    not the fixture generator's (see ``run_benchmark`` and the module
    docstring for why that separation matters).
    """

    detector_pipeline = build_detection_pipeline(
        port_scan=PortScanDetector(config=ScanConfig()),
        syn_flood=SynFloodDetector(config=SynFloodConfig()),
    )
    collected = _Collected()
    clock = _EmissionClock()
    timing_pipeline = TimingPipeline(detector_pipeline, collected.samples, clock)

    self_before = resource.getrusage(resource.RUSAGE_SELF)
    children_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    with _ConsumedPipe() as sink:
        emit_alert = _make_emit_alert(
            clock, collected.alerts, collected.alert_latencies_seconds, sink
        )
        start = time.perf_counter()
        result: ReplayResult = run_replay(pcap_path, timing_pipeline, emit_alert)
        elapsed = time.perf_counter() - start
    self_after = resource.getrusage(resource.RUSAGE_SELF)
    children_after = resource.getrusage(resource.RUSAGE_CHILDREN)

    pcap_bytes = pcap_path.stat().st_size
    # `pcap_bytes` (the pcap *file* size) includes the 24-byte global header plus
    # a 16-byte record header per packet -- capture-format overhead, not network
    # traffic. `traffic_bytes` is the fixture's own manifest-recorded sum of
    # captured Ethernet frame lengths, computed once by the trusted generator
    # (see tools/generate_benchmark_fixture.py's `_manifest`), and is what Mbps
    # is actually computed from.
    traffic_bytes: int = manifest["total_captured_bytes"]
    event_durations = [sample.duration_seconds for sample in collected.samples]
    event_latency = _latency_stats(event_durations)
    if event_latency is None:
        raise ValueError("replay processed zero events; nothing to measure")

    _verify_replay_matches_manifest(manifest, result=result, alerts=collected.alerts)

    return BenchmarkReport(
        pcap_path=str(pcap_path),
        pcap_bytes=pcap_bytes,
        traffic_bytes=traffic_bytes,
        events_processed=result.events_processed,
        alerts_emitted=result.alerts_emitted,
        wall_clock_seconds=elapsed,
        events_per_second=result.events_processed / elapsed if elapsed > 0 else float("inf"),
        megabits_per_second=(
            (traffic_bytes * 8 / 1_000_000) / elapsed if elapsed > 0 else float("inf")
        ),
        event_latency=event_latency,
        alert_latency=_latency_stats(collected.alert_latencies_seconds),
        python_cpu_user_seconds=self_after.ru_utime - self_before.ru_utime,
        python_cpu_system_seconds=self_after.ru_stime - self_before.ru_stime,
        python_peak_rss_kib=self_after.ru_maxrss,
        zeek_cpu_user_seconds=children_after.ru_utime - children_before.ru_utime,
        zeek_cpu_system_seconds=children_after.ru_stime - children_before.ru_stime,
        zeek_peak_rss_kib=children_after.ru_maxrss,
        environment={
            "python_version": sys.version.split()[0],
            "platform": platform.platform(),
            "cpu_count": os.cpu_count(),
            "zeek_version": _zeek_version(),
        },
    )


_WORKER_TIMEOUT_SECONDS = 600.0


def run_benchmark(pcap_path: Path) -> dict[str, Any]:
    """Validate ``pcap_path``, then measure its replay in an isolated worker subprocess.

    Two separate subprocesses do the memory/CPU-heavy work, and neither
    result the caller reports is contaminated by the other:

    1. ``_validate_pcap_matches_generated_fixture`` runs the fixture
       generator in its own throwaway subprocess to get a trusted
       size/digest/manifest for ``pcap_path``, and copies the exact bytes
       it validates into a private temporary file as it streams them for
       hashing (see that function).
    2. This function then spawns a second, fresh worker subprocess (this
       same script, re-invoked with ``--worker-manifest``) that performs
       only ``_measure_replay`` -- it never calls the generator itself, so
       its own ``RUSAGE_SELF``/``RUSAGE_CHILDREN`` samples cannot be
       polluted by the generator's ~21,431-packet object graph the way a
       single shared process would be.

    Critically, that worker subprocess is pointed at the private validated
    copy, not at the original ``pcap_path``: if it replayed ``pcap_path``
    directly, a caller-controlled path could be replaced (a retargeted
    symlink, a swapped file) after validation completes but before the
    worker opens it, letting an alternate capture with the same event and
    per-class alert counts pass the result checks while its Mbps is still
    computed from the *original* fixture's ``total_captured_bytes`` --
    invalid benchmark evidence. Copying the validated bytes into a path
    only this process created closes that window entirely: what was
    validated and what gets replayed are, by construction, the same bytes.
    """

    with tempfile.TemporaryDirectory() as tmp_dir:
        validated_pcap_path = Path(tmp_dir) / "validated.pcap"
        manifest_bytes = _validate_pcap_matches_generated_fixture(pcap_path, validated_pcap_path)
        manifest = json.loads(manifest_bytes.decode("utf-8"))

        manifest_path = Path(tmp_dir) / "manifest.json"
        manifest_path.write_text(json.dumps(manifest))
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--pcap",
                str(validated_pcap_path),
                "--worker-manifest",
                str(manifest_path),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=_WORKER_TIMEOUT_SECONDS,
        )

    if result.returncode != 0:
        stderr = result.stderr.strip()
        prefix = "replay_error: "
        if stderr.startswith(prefix):
            raise UnexpectedReplayResultError(stderr.removeprefix(prefix))
        raise UnexpectedReplayResultError(
            f"benchmark worker subprocess exited {result.returncode}: {stderr}"
        )
    payload: dict[str, Any] = json.loads(result.stdout)
    # Report the path the caller supplied, not the private validated copy the
    # worker actually replayed internally -- they hold identical bytes (see
    # _validate_pcap_matches_generated_fixture), so this is purely cosmetic.
    payload["pcap_path"] = str(pcap_path)
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, default=DEFAULT_PCAP)
    parser.add_argument("--output", type=Path, default=None, help="write the JSON report here")
    parser.add_argument(
        "--worker-manifest",
        type=Path,
        default=None,
        help=argparse.SUPPRESS,  # internal: used by run_benchmark's own re-invocation
    )
    return parser


def _run_worker(pcap_path: Path, manifest_path: Path) -> int:
    """Entry point for the isolated worker subprocess ``run_benchmark`` spawns.

    Trusts ``manifest_path`` and ``pcap_path`` as already validated by its
    caller rather than re-deriving them from the generator itself (which
    would corrupt the Zeek RSS/CPU figures this process measures -- see the
    module docstring). ``TimingPipeline.process`` still enforces a hard
    ``_MAX_MEASURED_EVENTS`` cap regardless of that trust, so a direct
    invocation of this internal flag with an arbitrarily large pcap and an
    unvalidated but matching manifest cannot grow this process's bookkeeping
    lists without bound. The manifest file itself is size-bounded before it
    is read or parsed, for the same reason: an oversized ``--worker-manifest``
    argument must not be able to exhaust memory in ``read_text``/``json.loads``
    before that per-event cap ever gets a chance to run. That bound is
    enforced by reading at most one byte over the limit, not by trusting
    ``stat().st_size`` -- a non-regular path (a FIFO, a character device such
    as ``/dev/zero``, ...) can report a misleading size (commonly ``0``)
    while still supplying unbounded or blocking bytes on read, so non-regular
    manifest paths are rejected outright before any read is attempted.
    """

    if not manifest_path.is_file():
        print(
            f"worker_manifest_error: manifest_not_regular_file: {manifest_path}",
            file=sys.stderr,
        )
        return 1
    with manifest_path.open("rb") as handle:
        raw_manifest = handle.read(_MAX_WORKER_MANIFEST_BYTES + 1)
    if len(raw_manifest) > _MAX_WORKER_MANIFEST_BYTES:
        print(
            "worker_manifest_error: manifest_too_large: "
            f"exceeds {_MAX_WORKER_MANIFEST_BYTES} byte limit",
            file=sys.stderr,
        )
        return 1
    manifest = json.loads(raw_manifest.decode("utf-8"))
    try:
        report = _measure_replay(pcap_path, manifest)
    except UnexpectedReplayResultError as exc:
        print(f"replay_error: {exc}", file=sys.stderr)
        return 1
    except ReplayError as exc:
        print(f"replay_error: {exc.diagnostic}", file=sys.stderr)
        return 1
    except StateLimitExceeded as exc:
        print(f"state_limit_exceeded: {exc.limit_name}", file=sys.stderr)
        return 1
    print(json.dumps(report.as_dict()))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.worker_manifest is not None:
        return _run_worker(args.pcap, args.worker_manifest)

    if not args.pcap.is_file():
        print(f"input_error: pcap_not_regular_file: {args.pcap}", file=sys.stderr)
        return 2

    try:
        report_dict = run_benchmark(args.pcap)
    except UnvalidatedPcapError as exc:
        print(f"input_error: {exc}", file=sys.stderr)
        return 2
    except UnexpectedReplayResultError as exc:
        print(f"replay_error: {exc}", file=sys.stderr)
        return 1
    payload = json.dumps(report_dict, indent=2, sort_keys=True)
    if args.output is not None:
        args.output.write_text(payload + "\n")
    print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
