from __future__ import annotations

import ast
import hashlib
import json
import struct
from pathlib import Path
from typing import cast

from tools.generate_milestone1_fixtures import check_all, generate_all


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    words = cast(tuple[int, ...], struct.unpack(f"!{len(data) // 2}H", data))
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def parse_packets(pcap: bytes) -> list[tuple[int, int, bytes]]:
    magic, major, minor, _, _, snaplen, linktype = struct.unpack("<IHHIIII", pcap[:24])
    assert magic == 0xA1B2C3D4
    assert (major, minor) == (2, 4)
    assert snaplen == 65_535
    assert linktype == 1

    packets: list[tuple[int, int, bytes]] = []
    offset = 24
    while offset < len(pcap):
        seconds, micros, captured, original = struct.unpack("<IIII", pcap[offset : offset + 16])
        offset += 16
        assert captured == original
        frame = pcap[offset : offset + captured]
        assert len(frame) == captured
        packets.append((seconds, micros, frame))
        offset += captured
    assert offset == len(pcap)
    return packets


def test_generation_is_byte_deterministic(tmp_path: Path) -> None:
    first = generate_all(tmp_path / "first")
    second = generate_all(tmp_path / "second")

    assert {path.name: path.read_bytes() for path in first} == {
        path.name: path.read_bytes() for path in second
    }
    assert check_all(tmp_path / "first")


def test_manifest_hash_and_packet_count_match_capture(tmp_path: Path) -> None:
    pcap_paths = generate_all(tmp_path)

    for pcap in pcap_paths:
        manifest = json.loads(pcap.with_suffix(".manifest.json").read_text())
        assert manifest["capture_sha256"] == hashlib.sha256(pcap.read_bytes()).hexdigest()
        assert manifest["packet_count"] == len(parse_packets(pcap.read_bytes()))
        assert manifest["provenance"]["kind"] == "locally_generated_documentation_ranges"


def test_generated_frames_have_valid_ipv4_and_tcp_checksums(tmp_path: Path) -> None:
    for pcap_path in generate_all(tmp_path):
        previous_timestamp: tuple[int, int] | None = None
        for seconds, micros, frame in parse_packets(pcap_path.read_bytes()):
            assert previous_timestamp is None or previous_timestamp <= (seconds, micros)
            previous_timestamp = (seconds, micros)
            assert frame[12:14] == b"\x08\x00"

            ipv4 = frame[14:34]
            tcp = frame[34:54]
            assert ipv4[0] == 0x45
            assert struct.unpack("!H", ipv4[2:4])[0] == 40
            assert ipv4[9] == 6
            assert checksum(ipv4) == 0

            offset_and_flags = struct.unpack("!H", tcp[12:14])[0]
            assert offset_and_flags >> 12 == 5
            assert offset_and_flags & 0x01FF == 0x002
            pseudo_header = ipv4[12:20] + b"\x00\x06" + struct.pack("!H", len(tcp))
            assert checksum(pseudo_header + tcp) == 0


def test_scenarios_record_exact_expected_outcomes(tmp_path: Path) -> None:
    pcap_paths = generate_all(tmp_path)
    manifests = {
        path.stem: json.loads(path.with_suffix(".manifest.json").read_text())
        for path in pcap_paths
    }

    assert set(manifests) == {
        "benign",
        "vertical_below",
        "vertical_at_threshold",
        "horizontal_at_threshold",
        "retransmitted_syn",
    }
    assert manifests["benign"]["parameters"] == {
        "attempts": 10,
        "unique_destination_hosts": 1,
        "unique_destination_ports": 10,
    }
    assert manifests["vertical_below"]["expected_alert_count"] == 0
    assert manifests["vertical_below"]["parameters"]["unique_destination_ports"] == 14
    assert manifests["vertical_at_threshold"]["expected_alert_count"] == 1
    assert manifests["vertical_at_threshold"]["parameters"]["unique_destination_ports"] == 15
    assert manifests["horizontal_at_threshold"]["expected_alert_count"] == 1
    assert manifests["horizontal_at_threshold"]["parameters"]["unique_destination_hosts"] == 15
    assert manifests["retransmitted_syn"]["expected_alert_count"] == 0
    assert manifests["retransmitted_syn"]["parameters"]["expected_deduplicated_attempts"] == 1


def test_generator_has_no_network_or_process_imports() -> None:
    generator_path = Path("tools/generate_milestone1_fixtures.py")
    tree = ast.parse(generator_path.read_text())
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


def test_check_detects_capture_drift(tmp_path: Path) -> None:
    captures = generate_all(tmp_path)
    captures[0].write_bytes(captures[0].read_bytes() + b"drift")

    assert not check_all(tmp_path)
