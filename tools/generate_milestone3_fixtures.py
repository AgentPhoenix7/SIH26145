"""Generate deterministic, offline Milestone 3 DNS/DGA PCAP fixtures."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sih26145.ml.dga_model import DgaModel

if TYPE_CHECKING or __package__:
    from tools.generate_milestone1_fixtures import (
        DESTINATION_MAC,
        PCAP_GLOBAL_HEADER,
        SOURCE_MAC,
        internet_checksum,
    )
else:
    from generate_milestone1_fixtures import (  # type: ignore[no-redef]
        DESTINATION_MAC,
        PCAP_GLOBAL_HEADER,
        SOURCE_MAC,
        internet_checksum,
    )

GENERATOR_VERSION = "1.0.0"
BASE_TIMESTAMP = 1_700_000_000.25


@dataclass(frozen=True, slots=True)
class DnsQueryPacket:
    timestamp: float
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    transaction_id: int
    query_name: str
    query_type: int
    query_class: int
    ip_identification: int


@dataclass(frozen=True, slots=True)
class Scenario:
    scenario_id: str
    label: str
    expected_alert_count: int
    query_origin: str
    packet: DnsQueryPacket


def scenarios() -> tuple[Scenario, ...]:
    """Return one controlled benign and one synthetic DGA-like query."""

    return (
        Scenario(
            scenario_id="benign_dns",
            label="BENIGN_DNS",
            expected_alert_count=0,
            query_origin="hand-authored RFC 2606 example domain",
            packet=DnsQueryPacket(
                timestamp=BASE_TIMESTAMP,
                source_ip="192.0.2.10",
                source_port=53_000,
                destination_ip="198.51.100.53",
                destination_port=53,
                transaction_id=0x2614,
                query_name="example.com",
                query_type=1,
                query_class=1,
                ip_identification=2_000,
            ),
        ),
        Scenario(
            scenario_id="dga_dns",
            label="DGA_SYNTHETIC",
            expected_alert_count=1,
            query_origin="hand-authored synthetic label under the RFC 2606 example TLD",
            packet=DnsQueryPacket(
                timestamp=BASE_TIMESTAMP,
                source_ip="192.0.2.10",
                source_port=53_001,
                destination_ip="198.51.100.53",
                destination_port=53,
                transaction_id=0x2615,
                query_name="x9q7z8v6k5j4m3n2.example",
                query_type=1,
                query_class=1,
                ip_identification=2_001,
            ),
        ),
    )


def _dns_query_bytes(packet: DnsQueryPacket) -> bytes:
    labels = packet.query_name.encode("ascii").split(b".")
    question_name = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
    return (
        struct.pack("!HHHHHH", packet.transaction_id, 0x0100, 1, 0, 0, 0)
        + question_name
        + struct.pack("!HH", packet.query_type, packet.query_class)
    )


def ethernet_ipv4_udp_dns(packet: DnsQueryPacket) -> bytes:
    """Encode one valid Ethernet/IPv4/UDP DNS query without transmitting it."""

    dns = _dns_query_bytes(packet)
    source_ip = ipaddress.IPv4Address(packet.source_ip).packed
    destination_ip = ipaddress.IPv4Address(packet.destination_ip).packed
    udp_length = 8 + len(dns)
    udp_without_checksum = struct.pack(
        "!HHHH",
        packet.source_port,
        packet.destination_port,
        udp_length,
        0,
    )
    pseudo_header = source_ip + destination_ip + b"\x00\x11" + struct.pack("!H", udp_length)
    udp_checksum = internet_checksum(pseudo_header + udp_without_checksum + dns)
    if udp_checksum == 0:
        udp_checksum = 0xFFFF
    udp = (
        struct.pack(
            "!HHHH",
            packet.source_port,
            packet.destination_port,
            udp_length,
            udp_checksum,
        )
        + dns
    )

    ip_length = 20 + len(udp)
    ipv4_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_length,
        packet.ip_identification,
        0x4000,
        64,
        17,
        0,
        source_ip,
        destination_ip,
    )
    ipv4_checksum = internet_checksum(ipv4_without_checksum)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_length,
        packet.ip_identification,
        0x4000,
        64,
        17,
        ipv4_checksum,
        source_ip,
        destination_ip,
    )
    ethernet = DESTINATION_MAC + SOURCE_MAC + struct.pack("!H", 0x0800)
    return ethernet + ipv4 + udp


def pcap_bytes(packet: DnsQueryPacket) -> bytes:
    """Encode one DNS query frame as little-endian microsecond PCAP."""

    frame = ethernet_ipv4_udp_dns(packet)
    seconds = int(packet.timestamp)
    microseconds = round((packet.timestamp - seconds) * 1_000_000)
    record = struct.pack("<IIII", seconds, microseconds, len(frame), len(frame))
    return PCAP_GLOBAL_HEADER + record + frame


def _utc_string(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _model_facts() -> tuple[DgaModel, str]:
    model = DgaModel.load_packaged()
    metadata_resource = files("sih26145").joinpath("artifacts/dga_logreg_v1.metadata.json")
    metadata = json.loads(metadata_resource.read_text(encoding="utf-8"))
    return model, str(metadata["artifact"]["sha256"])


def _manifest(
    scenario: Scenario,
    capture: bytes,
    *,
    probability: float,
    artifact_sha256: str,
) -> bytes:
    packet = scenario.packet
    manifest: dict[str, Any] = {
        "schema_version": "fixture_manifest_v1",
        "generator": "tools/generate_milestone3_fixtures.py",
        "generator_version": GENERATOR_VERSION,
        "scenario_id": scenario.scenario_id,
        "label": scenario.label,
        "query_name": packet.query_name,
        "query_type": packet.query_type,
        "query_class": packet.query_class,
        "query_origin": scenario.query_origin,
        "expected_alert_count": scenario.expected_alert_count,
        "expected_threat_class": "DGA",
        "timestamp_range": {
            "start": _utc_string(packet.timestamp),
            "end": _utc_string(packet.timestamp),
        },
        "endpoints": {
            "source_ips": [packet.source_ip],
            "destination_ips": [packet.destination_ip],
            "destination_ports": [packet.destination_port],
        },
        "packet_count": 1,
        "capture_sha256": hashlib.sha256(capture).hexdigest(),
        "model": {
            "version": "dga_logreg_v1",
            "artifact_sha256": artifact_sha256,
            "decision_threshold": 0.5,
            "probability": probability,
        },
        "provenance": {
            "kind": "locally_generated_documentation_ranges",
            "address_standards": ["RFC 5737"],
            "domain_standards": ["RFC 2606"],
            "network_activity": "none",
        },
    }
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()


def _artifacts() -> dict[str, bytes]:
    model, artifact_sha256 = _model_facts()
    artifacts: dict[str, bytes] = {}
    for scenario in scenarios():
        capture = pcap_bytes(scenario.packet)
        probability = model.predict_probability(scenario.packet.query_name)
        artifacts[f"{scenario.scenario_id}.pcap"] = capture
        artifacts[f"{scenario.scenario_id}.manifest.json"] = _manifest(
            scenario,
            capture,
            probability=probability,
            artifact_sha256=artifact_sha256,
        )
    return artifacts


def generate_all(output: Path) -> list[Path]:
    """Write both deterministic fixtures and return their PCAP paths."""

    output.mkdir(parents=True, exist_ok=True)
    for name, data in _artifacts().items():
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
