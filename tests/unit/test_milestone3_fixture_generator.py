from __future__ import annotations

import ast
import hashlib
import json
import socket
import struct
from pathlib import Path

import pytest

from tests.unit.test_fixture_generator import checksum, parse_packets
from tools.generate_milestone3_fixtures import check_all, generate_all


def test_milestone3_generation_is_byte_deterministic_and_offline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_socket(*_args: object, **_kwargs: object) -> socket.socket:
        pytest.fail("DNS fixture generation attempted network access")

    monkeypatch.setattr(socket, "socket", fail_socket)
    first = generate_all(tmp_path / "first")
    second = generate_all(tmp_path / "second")

    assert {path.name: path.read_bytes() for path in first} == {
        path.name: path.read_bytes() for path in second
    }
    assert check_all(tmp_path / "first")


def test_milestone3_manifests_match_captures_model_and_expected_outcomes(tmp_path: Path) -> None:
    captures = generate_all(tmp_path)
    manifests = {
        path.stem: json.loads(path.with_suffix(".manifest.json").read_text()) for path in captures
    }

    assert set(manifests) == {"benign_dns", "dga_dns"}
    for capture in captures:
        manifest = manifests[capture.stem]
        assert manifest["capture_sha256"] == hashlib.sha256(capture.read_bytes()).hexdigest()
        assert manifest["packet_count"] == 1
        assert manifest["model"]["version"] == "dga_logreg_v1"
        assert len(manifest["model"]["artifact_sha256"]) == 64
        assert 0.0 <= manifest["model"]["probability"] <= 1.0
        assert manifest["provenance"] == {
            "address_standards": ["RFC 5737"],
            "domain_standards": ["RFC 2606"],
            "kind": "locally_generated_documentation_ranges",
            "network_activity": "none",
        }

    assert manifests["benign_dns"]["query_name"] == "example.com"
    assert manifests["benign_dns"]["expected_alert_count"] == 0
    assert manifests["benign_dns"]["model"]["probability"] < 0.5
    assert manifests["dga_dns"]["query_name"] == "x9q7z8v6k5j4m3n2.example"
    assert manifests["dga_dns"]["expected_alert_count"] == 1
    assert manifests["dga_dns"]["model"]["probability"] >= 0.5


def test_generated_dns_frames_have_valid_ipv4_udp_checksums_and_questions(
    tmp_path: Path,
) -> None:
    expected_names = {"example.com", "x9q7z8v6k5j4m3n2.example"}
    observed_names: set[str] = set()

    for capture in generate_all(tmp_path):
        [(seconds, micros, frame)] = parse_packets(capture.read_bytes())
        assert (seconds, micros) == (1_700_000_000, 250_000)
        assert frame[12:14] == b"\x08\x00"
        ipv4 = frame[14:34]
        udp = frame[34:]
        assert ipv4[0] == 0x45
        assert ipv4[9] == 17
        assert struct.unpack("!H", ipv4[2:4])[0] == len(ipv4) + len(udp)
        assert checksum(ipv4) == 0
        assert struct.unpack("!H", udp[4:6])[0] == len(udp)
        pseudo_header = ipv4[12:20] + b"\x00\x11" + struct.pack("!H", len(udp))
        assert checksum(pseudo_header + udp) == 0

        dns = udp[8:]
        assert struct.unpack("!H", dns[4:6])[0] == 1
        offset = 12
        labels: list[str] = []
        while dns[offset] != 0:
            length = dns[offset]
            offset += 1
            labels.append(dns[offset : offset + length].decode("ascii"))
            offset += length
        offset += 1
        assert struct.unpack("!HH", dns[offset : offset + 4]) == (1, 1)
        observed_names.add(".".join(labels))

    assert observed_names == expected_names


def test_milestone3_generator_has_no_network_or_process_imports() -> None:
    tree = ast.parse(Path("tools/generate_milestone3_fixtures.py").read_text())
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

    assert imported_roots.isdisjoint(
        {"socket", "subprocess", "scapy", "dpkt", "pyshark", "requests", "urllib"}
    )


def test_milestone3_check_detects_capture_drift(tmp_path: Path) -> None:
    captures = generate_all(tmp_path)
    captures[0].write_bytes(captures[0].read_bytes() + b"drift")

    assert not check_all(tmp_path)
