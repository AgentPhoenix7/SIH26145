from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from tests.unit.test_fixture_generator import parse_packets
from tools.generate_benchmark_fixture import check_all, generate_all


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
    assert manifest["expected_alert_count"] == 3
    assert set(manifest["expected_threat_classes"]) == {"PORT_SCAN", "SYN_FLOOD", "DGA"}
    assert manifest["provenance"] == {
        "address_standards": ["RFC 5737"],
        "domain_standards": ["RFC 2606"],
        "kind": "locally_generated_documentation_ranges",
        "network_activity": "none",
    }


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
