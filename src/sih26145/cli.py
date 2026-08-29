"""Command-line boundary for deterministic native-Zeek PCAP replay."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from sih26145.contracts.alerts import AlertV1
from sih26145.detection.dga import DgaDetector
from sih26145.detection.pipeline import DetectionPipeline
from sih26145.detection.port_scan import PortScanDetector, ScanConfig
from sih26145.detection.scan_window import StateLimitExceeded
from sih26145.detection.syn_flood import SynFloodConfig, SynFloodDetector
from sih26145.ml.dga_model import DgaModel, DgaModelError
from sih26145.replay import ReplayError, run_replay


def build_parser() -> argparse.ArgumentParser:
    """Build the public replay command parser."""

    parser = argparse.ArgumentParser(
        prog="sih26145-replay",
        description=(
            "Replay a PCAP passively through native Zeek and emit PORT_SCAN, "
            "SYN_FLOOD, or local ML DGA alerts. Scan and flood thresholds and "
            "confidence scores are heuristic and unvalidated."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("pcap", type=Path, help="existing regular PCAP file")
    parser.add_argument(
        "--window-seconds",
        type=float,
        default=10.0,
        help="capture-time scan window in seconds",
    )
    parser.add_argument(
        "--min-attempts",
        type=int,
        default=20,
        help="minimum deduplicated SYN attempts",
    )
    parser.add_argument(
        "--min-unique-ports",
        type=int,
        default=15,
        help="minimum unique destination ports",
    )
    parser.add_argument(
        "--min-unique-hosts",
        type=int,
        default=15,
        help="minimum unique destination hosts",
    )
    parser.add_argument(
        "--cooldown-seconds",
        type=float,
        default=30.0,
        help="per-source alert cooldown in seconds",
    )
    parser.add_argument(
        "--syn-flood-window-seconds",
        type=float,
        default=10.0,
        help="capture-time SYN-flood window in seconds",
    )
    parser.add_argument(
        "--min-syn-events",
        type=int,
        default=100,
        help="minimum deduplicated SYN events to one target",
    )
    parser.add_argument(
        "--min-syn-sources",
        type=int,
        default=20,
        help="minimum unique sources sending SYNs to one target",
    )
    parser.add_argument(
        "--syn-flood-cooldown-seconds",
        type=float,
        default=30.0,
        help="per-target SYN-flood alert cooldown in seconds",
    )
    return parser


def emit_alert(alert: AlertV1) -> None:
    """Write one validated canonical alert line and flush it immediately."""

    sys.stdout.write(alert.model_dump_json() + "\n")
    sys.stdout.flush()


def safe_diagnostic(
    exc: ValidationError | ValueError | ReplayError | StateLimitExceeded,
) -> str:
    """Describe a trusted failure invariant without echoing untrusted input."""

    if isinstance(exc, (ValidationError, ValueError)):
        return "configuration_error: invalid_scan_configuration"
    if isinstance(exc, ReplayError):
        return f"replay_error: {exc.diagnostic}"
    return f"state_limit_exceeded: {exc.limit_name}"


def main(argv: Sequence[str] | None = None) -> int:
    """Run one replay and return the documented process exit status."""

    args = build_parser().parse_args(argv)
    if not args.pcap.is_file():
        print("input_error: pcap_not_regular_file", file=sys.stderr, flush=True)
        return 2

    try:
        config = ScanConfig(
            window_seconds=args.window_seconds,
            minimum_attempts=args.min_attempts,
            minimum_unique_destination_ports=args.min_unique_ports,
            minimum_unique_destination_hosts=args.min_unique_hosts,
            cooldown_seconds=args.cooldown_seconds,
        )
        detector = PortScanDetector(config=config)
    except (ValidationError, ValueError) as exc:
        print(safe_diagnostic(exc), file=sys.stderr, flush=True)
        return 2

    try:
        syn_flood_config = SynFloodConfig(
            window_seconds=args.syn_flood_window_seconds,
            minimum_syn_events=args.min_syn_events,
            minimum_unique_sources=args.min_syn_sources,
            cooldown_seconds=args.syn_flood_cooldown_seconds,
        )
        syn_flood_detector = SynFloodDetector(config=syn_flood_config)
    except (ValidationError, ValueError):
        print(
            "configuration_error: invalid_syn_flood_configuration",
            file=sys.stderr,
            flush=True,
        )
        return 2

    try:
        dga_detector = DgaDetector(model=DgaModel.load_packaged())
    except DgaModelError:
        print(
            "configuration_error: invalid_dga_model",
            file=sys.stderr,
            flush=True,
        )
        return 2

    detector_pipeline = DetectionPipeline(
        port_scan=detector,
        syn_flood=syn_flood_detector,
        dga=dga_detector,
    )

    try:
        run_replay(args.pcap, detector_pipeline, emit_alert)
    except ReplayError as exc:
        if exc.diagnostic == "pcap_not_regular_file":
            print("input_error: pcap_not_regular_file", file=sys.stderr, flush=True)
            return 2
        print(safe_diagnostic(exc), file=sys.stderr, flush=True)
        return 1
    except StateLimitExceeded as exc:
        print(safe_diagnostic(exc), file=sys.stderr, flush=True)
        return 1
    return 0
