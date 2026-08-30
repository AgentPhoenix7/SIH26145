"""Generate one deterministic, offline Milestone 5 sustained-load PCAP fixture.

This fixture exists only to measure throughput, alert latency, CPU, and
memory for the existing (frozen) three-detector pipeline. It reuses the same
locally generated documentation-range packet encoders as Milestones 1-3 and
introduces no new detector, model, or protocol behavior.

The capture mixes:

- a large background of benign, widely fanned-out SYN traffic that stays
  under every configured port-scan and SYN-flood threshold, to give a
  meaningful sustained-rate sample;
- a background of distinct benign DNS queries, to give a meaningful sample
  of stateless DGA-path latency;
- one exact copy of the Milestone 1 vertical port-scan threshold pattern;
- one exact copy of the Milestone 2 SYN-flood threshold pattern; and
- one exact copy of the Milestone 3 benign/DGA DNS pair,

so that replaying it deterministically reproduces exactly three known
alerts (PORT_SCAN, SYN_FLOOD, DGA) inside a much larger volume of benign
traffic, which is what makes both throughput and alert-latency percentiles
measurable from one capture.
"""

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
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING or __package__:
    from tools.generate_milestone1_fixtures import (
        PCAP_GLOBAL_HEADER,
        SynPacket,
        ethernet_ipv4_tcp_syn,
    )
    from tools.generate_milestone3_fixtures import (
        DnsQueryPacket,
        ethernet_ipv4_udp_dns,
    )
else:
    from generate_milestone1_fixtures import (  # type: ignore[no-redef]
        PCAP_GLOBAL_HEADER,
        SynPacket,
        ethernet_ipv4_tcp_syn,
    )
    from generate_milestone3_fixtures import (  # type: ignore[no-redef]
        DnsQueryPacket,
        ethernet_ipv4_udp_dns,
    )

GENERATOR_VERSION = "1.0.0"
BASE_TIMESTAMP = 1_700_000_000.0

LOAD_SYN_EVENTS = 20_000
LOAD_SOURCE_POOL = 400
LOAD_TARGET_POOL = 200
LOAD_DESTINATION_PORT = 8080
LOAD_INTERVAL_SECONDS = 0.001

LOAD_DNS_EVENTS = 199

Packet = SynPacket | DnsQueryPacket


def _load_source_ip(index: int) -> str:
    slot = index % LOAD_SOURCE_POOL
    if slot < 200:
        return f"192.0.2.{2 + slot}"
    return f"203.0.113.{2 + (slot - 200)}"


def _load_target_ip(index: int) -> str:
    return f"198.51.100.{2 + (index % LOAD_TARGET_POOL)}"


def _load_syn_packets(*, start_ts: float) -> tuple[SynPacket, ...]:
    """Benign background SYN traffic: stays below every configured threshold.

    Per source: ``LOAD_SYN_EVENTS / LOAD_SOURCE_POOL`` attempts, all to one
    fixed port and (because ``LOAD_SOURCE_POOL`` is an exact multiple of
    ``LOAD_TARGET_POOL``) exactly one destination host, so neither the
    unique-port nor the unique-host port-scan condition can be reached.
    Per target: ``LOAD_SYN_EVENTS / LOAD_TARGET_POOL`` events from exactly
    two distinct sources, both below the SYN-flood event and source minimums.
    """

    return tuple(
        SynPacket(
            timestamp=start_ts + index * LOAD_INTERVAL_SECONDS,
            source_ip=_load_source_ip(index),
            source_port=40_000 + (index % 20_000),
            destination_ip=_load_target_ip(index),
            destination_port=LOAD_DESTINATION_PORT,
            sequence=1_000 + index,
            ip_identification=1 + (index % 65_000),
        )
        for index in range(LOAD_SYN_EVENTS)
    )


def _load_dns_packets(*, start_ts: float) -> tuple[DnsQueryPacket, ...]:
    """Benign background DNS queries with distinct benign hostnames."""

    return tuple(
        DnsQueryPacket(
            timestamp=start_ts + index * LOAD_INTERVAL_SECONDS,
            source_ip="192.0.2.10",
            source_port=53_100 + index,
            destination_ip="198.51.100.53",
            destination_port=53,
            transaction_id=0x3000 + index,
            query_name=f"benign-host-{index:05d}.example",
            query_type=1,
            query_class=1,
            ip_identification=3_000 + index,
        )
        for index in range(LOAD_DNS_EVENTS)
    )


def _port_scan_packets(*, start_ts: float) -> tuple[SynPacket, ...]:
    """Exact copy of the Milestone 1 vertical-threshold pattern (1 alert)."""

    return tuple(
        SynPacket(
            timestamp=start_ts + index * 0.25,
            source_ip="192.0.2.250",
            source_port=41_000 + index,
            destination_ip="198.51.100.250",
            destination_port=20 + index,
            sequence=5_000 + index,
            ip_identification=6_000 + index,
        )
        for index in range(20)
    )


def _syn_flood_packets(*, start_ts: float) -> tuple[SynPacket, ...]:
    """Exact copy of the Milestone 2 exact-threshold pattern (1 alert).

    Uses 20 unique sources outside the load-block address pool
    (``203.0.113.2``-``203.0.113.201``), so this block cannot share
    per-source or per-target state with the background load traffic.
    """

    return tuple(
        SynPacket(
            timestamp=start_ts + index * 0.05,
            source_ip=f"203.0.113.{210 + (index % 20)}",
            source_port=42_000 + index,
            destination_ip="198.51.100.220",
            destination_port=443,
            sequence=7_000 + index,
            ip_identification=8_000 + index,
        )
        for index in range(100)
    )


def _benign_dns_packet(*, ts: float) -> DnsQueryPacket:
    return DnsQueryPacket(
        timestamp=ts,
        source_ip="192.0.2.10",
        source_port=53_000,
        destination_ip="198.51.100.53",
        destination_port=53,
        transaction_id=0x2614,
        query_name="example.com",
        query_type=1,
        query_class=1,
        ip_identification=2_000,
    )


def _dga_dns_packet(*, ts: float) -> DnsQueryPacket:
    return DnsQueryPacket(
        timestamp=ts,
        source_ip="192.0.2.10",
        source_port=53_001,
        destination_ip="198.51.100.53",
        destination_port=53,
        transaction_id=0x2615,
        query_name="x9q7z8v6k5j4m3n2.example",
        query_type=1,
        query_class=1,
        ip_identification=2_001,
    )


def build_packets() -> tuple[Packet, ...]:
    """Return every packet for the fixture, already in non-decreasing time order."""

    load_syn = _load_syn_packets(start_ts=BASE_TIMESTAMP)
    load_syn_end = load_syn[-1].timestamp

    load_dns = _load_dns_packets(start_ts=load_syn_end + 1.0)
    load_dns_end = load_dns[-1].timestamp if load_dns else load_syn_end

    port_scan_start = load_dns_end + 30.0
    port_scan = _port_scan_packets(start_ts=port_scan_start)
    port_scan_end = port_scan[-1].timestamp

    syn_flood_start = port_scan_end + 30.0
    syn_flood = _syn_flood_packets(start_ts=syn_flood_start)
    syn_flood_end = syn_flood[-1].timestamp

    dns_pair_start = syn_flood_end + 5.0
    dns_pair: tuple[DnsQueryPacket, ...] = (
        _benign_dns_packet(ts=dns_pair_start),
        _dga_dns_packet(ts=dns_pair_start + 0.1),
    )

    return (*load_syn, *load_dns, *port_scan, *syn_flood, *dns_pair)


def _frame(packet: Packet) -> bytes:
    if isinstance(packet, SynPacket):
        return ethernet_ipv4_tcp_syn(packet)
    return ethernet_ipv4_udp_dns(packet)


def pcap_bytes(packets: Sequence[Packet]) -> bytes:
    """Encode a mixed, already time-ordered packet sequence as microsecond PCAP."""

    output = bytearray(PCAP_GLOBAL_HEADER)
    for packet in packets:
        frame = _frame(packet)
        seconds = int(packet.timestamp)
        microseconds = round((packet.timestamp - seconds) * 1_000_000)
        if microseconds == 1_000_000:
            seconds += 1
            microseconds = 0
        output.extend(struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)))
        output.extend(frame)
    return bytes(output)


def _utc_string(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _ip_sort_key(value: str) -> tuple[int, int]:
    address = ipaddress.ip_address(value)
    return address.version, int(address)


@dataclass(frozen=True, slots=True)
class _Counts:
    syn_events: int
    dns_events: int


def _counts(packets: Sequence[Packet]) -> _Counts:
    syn_events = sum(1 for packet in packets if isinstance(packet, SynPacket))
    dns_events = len(packets) - syn_events
    return _Counts(syn_events=syn_events, dns_events=dns_events)


def _manifest(packets: Sequence[Packet], capture: bytes) -> bytes:
    counts = _counts(packets)
    source_ips = sorted({packet.source_ip for packet in packets}, key=_ip_sort_key)
    destination_ips = sorted({packet.destination_ip for packet in packets}, key=_ip_sort_key)
    destination_ports = sorted({packet.destination_port for packet in packets})
    manifest: dict[str, Any] = {
        "schema_version": "fixture_manifest_v1",
        "generator": "tools/generate_benchmark_fixture.py",
        "generator_version": GENERATOR_VERSION,
        "scenario_id": "sustained_load",
        "label": "MILESTONE5_SUSTAINED_LOAD",
        "purpose": (
            "throughput/alert-latency/CPU/memory measurement only; "
            "no new detector or model behavior"
        ),
        "parameters": {
            "load_syn_events": LOAD_SYN_EVENTS,
            "load_syn_source_pool": LOAD_SOURCE_POOL,
            "load_syn_target_pool": LOAD_TARGET_POOL,
            "load_dns_events": LOAD_DNS_EVENTS,
            "embedded_port_scan_attempts": 20,
            "embedded_syn_flood_events": 100,
            "embedded_dns_pair_events": 2,
        },
        "expected_alert_count": 3,
        "expected_threat_classes": ["PORT_SCAN", "SYN_FLOOD", "DGA"],
        "expected_processed_events": counts.syn_events + counts.dns_events,
        "packet_count_by_type": {
            "tcp_syn": counts.syn_events,
            "dns_query": counts.dns_events,
        },
        "timestamp_range": {
            "start": _utc_string(packets[0].timestamp),
            "end": _utc_string(packets[-1].timestamp),
        },
        "endpoints": {
            "source_ips": source_ips,
            "destination_ips": destination_ips,
            "destination_ports": destination_ports,
        },
        "packet_count": len(packets),
        "capture_sha256": hashlib.sha256(capture).hexdigest(),
        "provenance": {
            "kind": "locally_generated_documentation_ranges",
            "address_standards": ["RFC 5737"],
            "domain_standards": ["RFC 2606"],
            "network_activity": "none",
        },
    }
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()


def _artifacts() -> dict[str, bytes]:
    packets = build_packets()
    capture = pcap_bytes(packets)
    return {
        "sustained_load.pcap": capture,
        "sustained_load.manifest.json": _manifest(packets, capture),
    }


def generate_all(output: Path) -> list[Path]:
    """Write the deterministic fixture and return its PCAP path."""

    output.mkdir(parents=True, exist_ok=True)
    for name, data in _artifacts().items():
        (output / name).write_bytes(data)
    return [output / "sustained_load.pcap"]


def check_all(output: Path) -> bool:
    """Return whether the existing fixture bytes match regenerated output."""

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
