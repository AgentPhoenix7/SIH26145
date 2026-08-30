from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from sih26145.detection.port_scan import PortScanDetector, ScanConfig
from sih26145.detection.syn_flood import SynFloodConfig, SynFloodDetector
from tests.factories import syn
from tests.unit.test_fixture_generator import parse_packets
from tools.generate_benchmark_fixture import (
    BASE_TIMESTAMP,
    PORT_SCAN_INCIDENTS,
    SYN_FLOOD_INCIDENTS,
    _artifacts,
    _fixture_info,
    _load_syn_packets,
    check_all,
    generate_all,
)


def test_benchmark_fixture_generation_is_byte_deterministic(tmp_path: Path) -> None:
    first = generate_all(tmp_path / "first")
    second = generate_all(tmp_path / "second")

    assert {path.name: path.read_bytes() for path in first} == {
        path.name: path.read_bytes() for path in second
    }
    assert check_all(tmp_path / "first")


def test_benchmark_manifest_matches_capture(tmp_path: Path) -> None:
    captures = generate_all(tmp_path)
    assert [path.stem for path in captures] == ["sustained_load"]
    capture = captures[0]
    manifest = json.loads(capture.with_suffix(".manifest.json").read_text())

    packets = parse_packets(capture.read_bytes())
    assert manifest["capture_sha256"] == hashlib.sha256(capture.read_bytes()).hexdigest()
    assert manifest["packet_count"] == len(packets)
    assert manifest["expected_processed_events"] == len(packets)
    by_class = manifest["expected_alert_count_by_class"]
    assert by_class["PORT_SCAN"] == PORT_SCAN_INCIDENTS
    assert by_class["SYN_FLOOD"] == SYN_FLOOD_INCIDENTS
    assert by_class["DGA"] >= 1  # at least the already-verified Milestone 3 domain
    assert manifest["expected_alert_count"] == sum(by_class.values())
    # Alert-latency percentiles need more than a handful of independent alerts per class.
    assert PORT_SCAN_INCIDENTS >= 10
    assert SYN_FLOOD_INCIDENTS >= 10
    assert set(manifest["expected_threat_classes"]) == {"PORT_SCAN", "SYN_FLOOD", "DGA"}
    assert manifest["provenance"] == {
        "address_standards": ["RFC 5737"],
        "domain_standards": ["RFC 2606"],
        "kind": "locally_generated_documentation_ranges",
        "network_activity": "none",
    }


def test_benchmark_load_syn_traffic_stays_below_both_detectors_measured_against_reality() -> None:
    """Pin the actual measured reason the background load never alerts.

    Reasoning about thresholds by hand has been wrong twice already in
    this fixture's history (see its docstrings/commit history): once by
    assuming attempt/event counts alone stayed under the configured
    minimums, and once by assuming a target's rolling-window event count
    equalled its total generated event count. Both mistakes are only
    caught by actually running the real detectors, so this test does
    exactly that and pins the measured numbers documented in
    ``docs/evaluation.md`` and this module's docstrings.
    """

    packets = _load_syn_packets(start_ts=BASE_TIMESTAMP)

    scan_detector = PortScanDetector(config=ScanConfig())
    flood_detector = SynFloodDetector(config=SynFloodConfig())
    max_attempts = max_ports = max_hosts = 0
    max_events = max_sources = 0
    for index, packet in enumerate(packets):
        event = syn(
            ts=packet.timestamp,
            uid=f"load-{index}",
            src_ip=packet.source_ip,
            src_port=packet.source_port,
            dst_ip=packet.destination_ip,
            dst_port=packet.destination_port,
        )
        assert scan_detector.process(event) is None
        assert flood_detector.process(event) is None
        for source_state in scan_detector._window._sources.values():
            max_attempts = max(max_attempts, len(source_state.attempts))
            max_ports = max(max_ports, len(source_state.destination_ports))
            max_hosts = max(max_hosts, len(source_state.destination_hosts))
        for target_state in flood_detector._window._targets.values():
            max_events = max(max_events, len(target_state.observations))
            max_sources = max(max_sources, len(target_state.sources))

    scan_config = ScanConfig()
    # The rolling-window attempt count exceeds the port-scan minimum; only the
    # unique-port/unique-host monoculture keeps this traffic from alerting.
    assert max_attempts == 26
    assert max_attempts > scan_config.minimum_attempts
    assert max_ports == 1 < scan_config.minimum_unique_destination_ports
    assert max_hosts == 1 < scan_config.minimum_unique_destination_hosts

    flood_config = SynFloodConfig()
    # Both halves of the flood's AND condition fail: the 10-second window
    # only ever holds part of one target's traffic across the ~20-second
    # background block, and source diversity per target is also low.
    assert max_events == 51 < flood_config.minimum_syn_events
    assert max_sources == 2 < flood_config.minimum_unique_sources


def test_benchmark_fixture_timestamps_are_non_decreasing(tmp_path: Path) -> None:
    capture = generate_all(tmp_path)[0]
    previous: tuple[int, int] | None = None
    for seconds, micros, _frame in parse_packets(capture.read_bytes()):
        assert previous is None or previous <= (seconds, micros)
        previous = (seconds, micros)


def test_benchmark_generator_has_no_network_or_process_imports() -> None:
    tree = ast.parse(Path("tools/generate_benchmark_fixture.py").read_text())
    imported_roots = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_roots.update(
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )

    assert imported_roots.isdisjoint({"socket", "subprocess", "scapy", "dpkt", "pyshark"})


def test_benchmark_check_detects_capture_drift(tmp_path: Path) -> None:
    captures = generate_all(tmp_path)
    captures[0].write_bytes(captures[0].read_bytes() + b"drift")

    assert not check_all(tmp_path)


def test_benchmark_generator_runs_as_a_direct_script(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "tools/generate_benchmark_fixture.py",
            "--output",
            str(tmp_path),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert check_all(tmp_path)


def test_benchmark_fixture_info_matches_the_generated_artifacts() -> None:
    artifacts = _artifacts()
    info = json.loads(_fixture_info())

    assert info["pcap_size"] == len(artifacts["sustained_load.pcap"])
    assert info["pcap_sha256"] == hashlib.sha256(artifacts["sustained_load.pcap"]).hexdigest()
    assert info["manifest"] == json.loads(artifacts["sustained_load.manifest.json"])


def test_benchmark_fixture_info_runs_as_a_direct_script() -> None:
    """tools/run_benchmark.py queries this exact CLI mode in a fresh subprocess so
    that building the fixture's object graph never counts toward its own
    RUSAGE_SELF peak-RSS sample; this flag itself must therefore work standalone."""

    result = subprocess.run(
        [sys.executable, "tools/generate_benchmark_fixture.py", "--fixture-info"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    info = json.loads(result.stdout)
    artifacts = _artifacts()
    assert info["pcap_size"] == len(artifacts["sustained_load.pcap"])
    assert info["pcap_sha256"] == hashlib.sha256(artifacts["sustained_load.pcap"]).hexdigest()


def test_benchmark_generator_requires_output_unless_fixture_info(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "tools/generate_benchmark_fixture.py"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "--output is required" in result.stderr
