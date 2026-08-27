"""Generate deterministic, offline Milestone 1 PCAP fixtures and manifests."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

GENERATOR_VERSION = "1.0.0"
BASE_TIMESTAMP = 1_700_000_000.0
SOURCE_MAC = bytes.fromhex("020000000001")
DESTINATION_MAC = bytes.fromhex("020000000002")
PCAP_GLOBAL_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)


@dataclass(frozen=True, slots=True)
class SynPacket:
    timestamp: float
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    sequence: int
    ip_identification: int


@dataclass(frozen=True, slots=True)
class Scenario:
    scenario_id: str
    label: str
    expected_alert_count: int
    parameters: dict[str, int]
    packets: tuple[SynPacket, ...]


def internet_checksum(data: bytes) -> int:
    """Return the RFC 1071 one's-complement checksum."""

    if len(data) % 2:
        data += b"\x00"
    words = cast(tuple[int, ...], struct.unpack(f"!{len(data) // 2}H", data))
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet_ipv4_tcp_syn(packet: SynPacket) -> bytes:
    """Encode one valid Ethernet/IPv4/TCP SYN frame without transmitting it."""

    source_ip = ipaddress.IPv4Address(packet.source_ip).packed
    destination_ip = ipaddress.IPv4Address(packet.destination_ip).packed

    tcp_without_checksum = struct.pack(
        "!HHIIHHHH",
        packet.source_port,
        packet.destination_port,
        packet.sequence,
        0,
        (5 << 12) | 0x002,
        64_240,
        0,
        0,
    )
    pseudo_header = (
        source_ip
        + destination_ip
        + b"\x00\x06"
        + struct.pack("!H", len(tcp_without_checksum))
    )
    tcp_checksum = internet_checksum(pseudo_header + tcp_without_checksum)
    tcp_header = struct.pack(
        "!HHIIHHHH",
        packet.source_port,
        packet.destination_port,
        packet.sequence,
        0,
        (5 << 12) | 0x002,
        64_240,
        tcp_checksum,
        0,
    )

    ipv4_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40,
        packet.ip_identification,
        0x4000,
        64,
        6,
        0,
        source_ip,
        destination_ip,
    )
    ipv4_checksum = internet_checksum(ipv4_without_checksum)
    ipv4_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40,
        packet.ip_identification,
        0x4000,
        64,
        6,
        ipv4_checksum,
        source_ip,
        destination_ip,
    )
    ethernet_header = DESTINATION_MAC + SOURCE_MAC + struct.pack("!H", 0x0800)
    return ethernet_header + ipv4_header + tcp_header


def pcap_bytes(packets: Sequence[SynPacket]) -> bytes:
    """Encode an ordered packet sequence as little-endian microsecond PCAP."""

    output = bytearray(PCAP_GLOBAL_HEADER)
    for packet in packets:
        frame = ethernet_ipv4_tcp_syn(packet)
        seconds = int(packet.timestamp)
        microseconds = round((packet.timestamp - seconds) * 1_000_000)
        if microseconds == 1_000_000:
            seconds += 1
            microseconds = 0
        output.extend(struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)))
        output.extend(frame)
    return bytes(output)


def _scan_packets(
    *,
    attempts: int,
    unique_ports: int,
    unique_hosts: int,
    retransmitted: bool = False,
) -> tuple[SynPacket, ...]:
    packets: list[SynPacket] = []
    for index in range(attempts):
        if retransmitted:
            source_port = 40_000
            destination_port = 443
            destination_ip = "198.51.100.20"
            sequence = 1_000
        else:
            source_port = 40_000 + index
            destination_port = 20 + (index % unique_ports)
            destination_ip = f"198.51.100.{20 + (index % unique_hosts)}"
            sequence = 1_000 + index
        packets.append(
            SynPacket(
                timestamp=BASE_TIMESTAMP + index * 0.25,
                source_ip="192.0.2.10",
                source_port=source_port,
                destination_ip=destination_ip,
                destination_port=destination_port,
                sequence=sequence,
                ip_identification=index + 1,
            )
        )
    return tuple(packets)


def scenarios() -> tuple[Scenario, ...]:
    """Return the five code-owned deterministic Milestone 1 scenarios."""

    return (
        Scenario(
            scenario_id="benign",
            label="BENIGN",
            expected_alert_count=0,
            parameters={
                "attempts": 10,
                "unique_destination_hosts": 1,
                "unique_destination_ports": 10,
            },
            packets=_scan_packets(attempts=10, unique_ports=10, unique_hosts=1),
        ),
        Scenario(
            scenario_id="vertical_below",
            label="PORT_SCAN_BELOW_THRESHOLD",
            expected_alert_count=0,
            parameters={
                "attempts": 20,
                "unique_destination_hosts": 1,
                "unique_destination_ports": 14,
            },
            packets=_scan_packets(attempts=20, unique_ports=14, unique_hosts=1),
        ),
        Scenario(
            scenario_id="vertical_at_threshold",
            label="PORT_SCAN_VERTICAL",
            expected_alert_count=1,
            parameters={
                "attempts": 20,
                "unique_destination_hosts": 1,
                "unique_destination_ports": 15,
            },
            packets=_scan_packets(attempts=20, unique_ports=15, unique_hosts=1),
        ),
        Scenario(
            scenario_id="horizontal_at_threshold",
            label="PORT_SCAN_HORIZONTAL",
            expected_alert_count=1,
            parameters={
                "attempts": 20,
                "unique_destination_hosts": 15,
                "unique_destination_ports": 1,
            },
            packets=_scan_packets(attempts=20, unique_ports=1, unique_hosts=15),
        ),
        Scenario(
            scenario_id="retransmitted_syn",
            label="BENIGN_RETRANSMISSION",
            expected_alert_count=0,
            parameters={
                "attempts": 20,
                "unique_destination_hosts": 1,
                "unique_destination_ports": 1,
                "expected_deduplicated_attempts": 1,
            },
            packets=_scan_packets(
                attempts=20,
                unique_ports=1,
                unique_hosts=1,
                retransmitted=True,
            ),
        ),
    )


def _utc_string(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _manifest(scenario: Scenario, capture: bytes) -> bytes:
    source_ips = sorted({packet.source_ip for packet in scenario.packets})
    destination_ips = sorted(
        {packet.destination_ip for packet in scenario.packets},
        key=lambda value: int(ipaddress.IPv4Address(value)),
    )
    destination_ports = sorted({packet.destination_port for packet in scenario.packets})
    manifest: dict[str, Any] = {
        "schema_version": "fixture_manifest_v1",
        "generator": "tools/generate_milestone1_fixtures.py",
        "generator_version": GENERATOR_VERSION,
        "scenario_id": scenario.scenario_id,
        "label": scenario.label,
        "parameters": scenario.parameters,
        "expected_alert_count": scenario.expected_alert_count,
        "timestamp_range": {
            "start": _utc_string(scenario.packets[0].timestamp),
            "end": _utc_string(scenario.packets[-1].timestamp),
        },
        "endpoints": {
            "source_ips": source_ips,
            "destination_ips": destination_ips,
            "destination_ports": destination_ports,
        },
        "packet_count": len(scenario.packets),
        "capture_sha256": hashlib.sha256(capture).hexdigest(),
        "provenance": {
            "kind": "locally_generated_documentation_ranges",
            "address_standards": ["RFC 5737"],
            "network_activity": "none",
        },
    }
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()


def _artifacts() -> dict[str, bytes]:
    artifacts: dict[str, bytes] = {}
    for scenario in scenarios():
        capture = pcap_bytes(scenario.packets)
        artifacts[f"{scenario.scenario_id}.pcap"] = capture
        artifacts[f"{scenario.scenario_id}.manifest.json"] = _manifest(scenario, capture)
    return artifacts


def generate_all(output: Path) -> list[Path]:
    """Write all deterministic fixtures and return their PCAP paths."""

    output.mkdir(parents=True, exist_ok=True)
    artifacts = _artifacts()
    for name, data in artifacts.items():
        (output / name).write_bytes(data)
    return [output / f"{scenario.scenario_id}.pcap" for scenario in scenarios()]


def check_all(output: Path) -> bool:
    """Return whether every existing fixture byte matches regenerated output."""

    return all(
        (output / name).is_file() and (output / name).read_bytes() == expected
        for name, expected in _artifacts().items()
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.check:
        return 0 if check_all(args.output) else 1
    generate_all(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
