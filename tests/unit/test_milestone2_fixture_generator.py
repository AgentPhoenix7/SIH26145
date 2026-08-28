from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from tests.unit.test_fixture_generator import parse_packets
from tools.generate_milestone2_fixtures import check_all, generate_all


def test_milestone2_generation_is_byte_deterministic(tmp_path: Path) -> None:
    first = generate_all(tmp_path / "first")
    second = generate_all(tmp_path / "second")

    assert {path.name: path.read_bytes() for path in first} == {
        path.name: path.read_bytes() for path in second
    }
    assert check_all(tmp_path / "first")


def test_milestone2_manifests_match_captures_and_expected_outcomes(tmp_path: Path) -> None:
    captures = generate_all(tmp_path)
    manifests = {
        path.stem: json.loads(path.with_suffix(".manifest.json").read_text()) for path in captures
    }

    assert set(manifests) == {"benign_distributed", "syn_flood_below", "syn_flood_at_threshold"}
    for capture in captures:
        manifest = manifests[capture.stem]
        assert manifest["capture_sha256"] == hashlib.sha256(capture.read_bytes()).hexdigest()
        assert manifest["packet_count"] == len(parse_packets(capture.read_bytes()))
        assert manifest["provenance"] == {
            "address_standards": ["RFC 5737"],
            "kind": "locally_generated_documentation_ranges",
            "network_activity": "none",
        }

    assert manifests["benign_distributed"]["expected_alert_count"] == 0
    assert manifests["benign_distributed"]["parameters"] == {
        "syn_events": 100,
        "unique_sources": 20,
        "unique_targets": 10,
    }
    assert manifests["syn_flood_below"]["expected_alert_count"] == 0
    assert manifests["syn_flood_below"]["parameters"]["syn_events"] == 99
    assert manifests["syn_flood_at_threshold"]["expected_alert_count"] == 1
    assert manifests["syn_flood_at_threshold"]["parameters"] == {
        "syn_events": 100,
        "unique_sources": 20,
        "unique_targets": 1,
    }


def test_milestone2_generator_has_no_network_or_process_imports() -> None:
    tree = ast.parse(Path("tools/generate_milestone2_fixtures.py").read_text())
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


def test_milestone2_check_detects_capture_drift(tmp_path: Path) -> None:
    captures = generate_all(tmp_path)
    captures[0].write_bytes(captures[0].read_bytes() + b"drift")

    assert not check_all(tmp_path)


def test_milestone2_generator_runs_as_a_direct_script(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "tools/generate_milestone2_fixtures.py",
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
