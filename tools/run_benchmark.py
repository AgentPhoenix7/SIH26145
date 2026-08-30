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
  write and flush), except the write target is ``os.devnull`` instead of a
  terminal/pipe so the benchmark's own output stays uncluttered. Because
  ``run_command`` calls the emit callback immediately after ``process``
  returns for the causing event, and processes one event fully (including
  all of its emits) before reading the next line, this is the actual
  time from event acceptance to alert availability, not detector time alone.

CPU time and peak resident set size are read from ``resource.getrusage`` for
this process only (``RUSAGE_SELF``); they exclude the separate native Zeek
child process, which is measured only by its contribution to wall-clock
throughput.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import resource
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from sih26145.contracts.alerts import AlertV1
from sih26145.detection.pipeline import DetectionPipeline
from sih26145.detection.port_scan import PortScanDetector, ScanConfig
from sih26145.detection.syn_flood import SynFloodConfig, SynFloodDetector
from sih26145.replay import ReplayResult, run_replay
from sih26145.runtime import build_detection_pipeline

DEFAULT_PCAP = Path("tests/fixtures/benchmark/sustained_load.pcap")


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
    callback constructed by ``_make_emit_alert`` below can measure the full
    event-acceptance-to-alert-availability interval, not detector time alone.
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
        start = time.perf_counter()
        self._clock.pending_start = start
        alerts = super().process(event)
        duration = time.perf_counter() - start
        self._samples.append(EventSample(duration_seconds=duration, alert_count=len(alerts)))
        return alerts


def _make_emit_alert(
    clock: _EmissionClock,
    alerts: list[AlertV1],
    alert_latencies: list[float],
    sink: TextIO,
) -> Any:
    """Build an emit callback that performs the CLI's real emission work.

    Mirrors ``sih26145.cli.emit_alert`` (JSON serialization, then write and
    flush) so timed "alert latency" reflects actual emission cost, not just
    detector processing. Writes to ``sink`` (``os.devnull``) instead of the
    terminal to keep benchmark output clean.
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
    events_processed: int
    alerts_emitted: int
    wall_clock_seconds: float
    events_per_second: float
    megabits_per_second: float
    event_latency: LatencyStats
    alert_latency: LatencyStats | None
    cpu_user_seconds: float
    cpu_system_seconds: float
    peak_rss_kib: int
    environment: dict[str, str | int | None]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "benchmark_report_v1",
            "pcap_path": self.pcap_path,
            "pcap_bytes": self.pcap_bytes,
            "events_processed": self.events_processed,
            "alerts_emitted": self.alerts_emitted,
            "wall_clock_seconds": self.wall_clock_seconds,
            "throughput": {
                "events_per_second": self.events_per_second,
                "megabits_per_second": self.megabits_per_second,
            },
            "event_processing_latency": self.event_latency.as_dict(),
            "alert_latency": (self.alert_latency.as_dict() if self.alert_latency else None),
            "cpu": {
                "user_seconds": self.cpu_user_seconds,
                "system_seconds": self.cpu_system_seconds,
            },
            "peak_rss_kib": self.peak_rss_kib,
            "environment": self.environment,
        }


@dataclass(slots=True)
class _Collected:
    samples: list[EventSample] = field(default_factory=list)
    alerts: list[AlertV1] = field(default_factory=list)
    alert_latencies_seconds: list[float] = field(default_factory=list)


def run_benchmark(pcap_path: Path) -> BenchmarkReport:
    """Replay ``pcap_path`` once and return measured throughput/latency/CPU/RSS."""

    detector_pipeline = build_detection_pipeline(
        port_scan=PortScanDetector(config=ScanConfig()),
        syn_flood=SynFloodDetector(config=SynFloodConfig()),
    )
    collected = _Collected()
    clock = _EmissionClock()
    timing_pipeline = TimingPipeline(detector_pipeline, collected.samples, clock)

    usage_before = resource.getrusage(resource.RUSAGE_SELF)
    with open(os.devnull, "w", encoding="utf-8") as sink:
        emit_alert = _make_emit_alert(
            clock, collected.alerts, collected.alert_latencies_seconds, sink
        )
        start = time.perf_counter()
        result: ReplayResult = run_replay(pcap_path, timing_pipeline, emit_alert)
        elapsed = time.perf_counter() - start
    usage_after = resource.getrusage(resource.RUSAGE_SELF)

    pcap_bytes = pcap_path.stat().st_size
    event_durations = [sample.duration_seconds for sample in collected.samples]
    event_latency = _latency_stats(event_durations)
    if event_latency is None:
        raise ValueError("replay processed zero events; nothing to measure")

    cpu_user = usage_after.ru_utime - usage_before.ru_utime
    cpu_system = usage_after.ru_stime - usage_before.ru_stime
    peak_rss = usage_after.ru_maxrss

    return BenchmarkReport(
        pcap_path=str(pcap_path),
        pcap_bytes=pcap_bytes,
        events_processed=result.events_processed,
        alerts_emitted=result.alerts_emitted,
        wall_clock_seconds=elapsed,
        events_per_second=result.events_processed / elapsed if elapsed > 0 else float("inf"),
        megabits_per_second=(pcap_bytes * 8 / 1_000_000) / elapsed if elapsed > 0 else float("inf"),
        event_latency=event_latency,
        alert_latency=_latency_stats(collected.alert_latencies_seconds),
        cpu_user_seconds=cpu_user,
        cpu_system_seconds=cpu_system,
        peak_rss_kib=peak_rss,
        environment={
            "python_version": sys.version.split()[0],
            "platform": platform.platform(),
            "cpu_count": os.cpu_count(),
            "zeek_version": _zeek_version(),
        },
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, default=DEFAULT_PCAP)
    parser.add_argument("--output", type=Path, default=None, help="write the JSON report here")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.pcap.is_file():
        print(f"input_error: pcap_not_regular_file: {args.pcap}", file=sys.stderr)
        return 2

    report = run_benchmark(args.pcap)
    payload = json.dumps(report.as_dict(), indent=2, sort_keys=True)
    if args.output is not None:
        args.output.write_text(payload + "\n")
    print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
