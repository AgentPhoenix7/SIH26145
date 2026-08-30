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
- ``PORT_SCAN_INCIDENTS`` independent copies of the Milestone 1
  vertical-threshold pattern (20 attempts, 15 unique ports), each from its
  own unused source address so every incident triggers its own alert
  without depending on cooldown expiry;
- ``SYN_FLOOD_INCIDENTS`` independent copies of the Milestone 2
  exact-threshold pattern (100 events, 20 unique sources), each against its
  own unused target address; and
- the verified Milestone 3 DGA query plus additional deterministic
  high-entropy candidate domains, each accepted only if the packaged
  ``dga_logreg_v1`` model actually scores it above its decision threshold,
  alongside one benign control query,

so that replaying it deterministically reproduces many independent alerts
per threat class inside a much larger volume of benign traffic. Multiple
independent alert observations (rather than one alert per class) are what
make alert-latency percentiles meaningful evidence instead of an
interpolation over a handful of points.
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
from random import Random
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

GENERATOR_VERSION = "2.0.0"
BASE_TIMESTAMP = 1_700_000_000.0

LOAD_SYN_EVENTS = 20_000
LOAD_SOURCE_POOL = 400
LOAD_TARGET_POOL = 200
LOAD_DESTINATION_PORT = 8080
LOAD_INTERVAL_SECONDS = 0.001

LOAD_DNS_EVENTS = 199

PORT_SCAN_INCIDENTS = 10
PORT_SCAN_ATTEMPTS = 20
PORT_SCAN_UNIQUE_PORTS = 15  # matches the Milestone 1 vertical_at_threshold fixture exactly

SYN_FLOOD_INCIDENTS = 10
SYN_FLOOD_EVENTS = 100
SYN_FLOOD_UNIQUE_SOURCES = 20  # matches the Milestone 2 syn_flood_at_threshold fixture exactly

DGA_CANDIDATE_POOL = 30  # generate this many; keep only the ones the model actually scores as DGA
DGA_CANDIDATE_SEED = 26_145  # reuses the project's fixed split/training seed for determinism

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


def _port_scan_incident_packets(*, start_ts: float, incident_index: int) -> tuple[SynPacket, ...]:
    """One exact copy of the Milestone 1 vertical-threshold pattern (1 alert).

    Each incident uses its own source address (``192.0.2.230`` +
    ``incident_index``, outside the load-block pool ``192.0.2.2``-``.201``
    and outside every other incident's address), so ``PORT_SCAN_INCIDENTS``
    independent alerts fire without depending on cooldown expiry between
    incidents.
    """

    return tuple(
        SynPacket(
            timestamp=start_ts + index * 0.25,
            source_ip=f"192.0.2.{230 + incident_index}",
            source_port=41_000 + index,
            destination_ip="198.51.100.250",
            destination_port=20 + (index % PORT_SCAN_UNIQUE_PORTS),
            sequence=5_000 + index,
            ip_identification=6_000 + index,
        )
        for index in range(PORT_SCAN_ATTEMPTS)
    )


def _syn_flood_incident_packets(*, start_ts: float, incident_index: int) -> tuple[SynPacket, ...]:
    """One exact copy of the Milestone 2 exact-threshold pattern (1 alert).

    All incidents reuse the same 20 source addresses (``203.0.113.210``-
    ``.229``, outside the load-block pool), which is safe because SYN-flood
    state is keyed by destination endpoint: each incident uses its own
    target address (``198.51.100.220`` + ``incident_index``, outside the
    load-block pool ``198.51.100.2``-``.201``), so ``SYN_FLOOD_INCIDENTS``
    independent alerts fire without any cross-incident state sharing.
    """

    return tuple(
        SynPacket(
            timestamp=start_ts + index * 0.05,
            source_ip=f"203.0.113.{210 + (index % SYN_FLOOD_UNIQUE_SOURCES)}",
            source_port=42_000 + index,
            destination_ip=f"198.51.100.{220 + incident_index}",
            destination_port=443,
            sequence=7_000 + index,
            ip_identification=8_000 + index,
        )
        for index in range(SYN_FLOOD_EVENTS)
    )


def _generate_dga_candidates(count: int, *, seed: int) -> tuple[str, ...]:
    """Return deterministic, high-entropy alphanumeric labels under ``.example``.

    Generation is a fixed-seed PRNG, not live randomness, so the fixture
    stays byte-deterministic across regenerations. Candidates are filtered
    against the real packaged model below; this only proposes labels.
    """

    rng = Random(seed)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    candidates = []
    for _ in range(count):
        length = rng.randint(12, 20)
        label = "".join(rng.choice(alphabet) for _ in range(length))
        candidates.append(f"{label}.example")
    return tuple(candidates)


def _benign_dns_packet(*, ts: float, port_offset: int = 0) -> DnsQueryPacket:
    return DnsQueryPacket(
        timestamp=ts,
        source_ip="192.0.2.10",
        source_port=53_000 + port_offset,
        destination_ip="198.51.100.53",
        destination_port=53,
        transaction_id=0x2614 + port_offset,
        query_name="example.com",
        query_type=1,
        query_class=1,
        ip_identification=2_000 + port_offset,
    )


def _dga_dns_packet(*, ts: float, query_name: str, port_offset: int) -> DnsQueryPacket:
    return DnsQueryPacket(
        timestamp=ts,
        source_ip="192.0.2.10",
        source_port=53_001 + port_offset,
        destination_ip="198.51.100.53",
        destination_port=53,
        transaction_id=0x2615 + port_offset,
        query_name=query_name,
        query_type=1,
        query_class=1,
        ip_identification=2_001 + port_offset,
    )


def _model_verified_dga_domains() -> tuple[str, ...]:
    """Return the verified Milestone 3 DGA domain plus model-verified extras.

    Candidates are generated deterministically and kept only if the actual
    packaged ``dga_logreg_v1`` model scores them above its own decision
    threshold, so every embedded "DGA" packet is a genuine, verified
    trigger of the real detector rather than an assumed one.
    """

    if TYPE_CHECKING or __package__:
        from tools.generate_milestone3_fixtures import _model_facts
    else:
        from generate_milestone3_fixtures import _model_facts  # type: ignore[no-redef]

    model, _artifact_sha256 = _model_facts()
    verified = ["x9q7z8v6k5j4m3n2.example"]  # the already-verified Milestone 3 fixture domain
    for candidate in _generate_dga_candidates(DGA_CANDIDATE_POOL, seed=DGA_CANDIDATE_SEED):
        if model.predict_probability(candidate) >= 0.5:
            verified.append(candidate)
    return tuple(verified)


def build_packets() -> tuple[Packet, ...]:
    """Return every packet for the fixture, already in non-decreasing time order."""

    load_syn = _load_syn_packets(start_ts=BASE_TIMESTAMP)
    load_syn_end = load_syn[-1].timestamp

    load_dns = _load_dns_packets(start_ts=load_syn_end + 1.0)
    load_dns_end = load_dns[-1].timestamp if load_dns else load_syn_end

    port_scan_packets: list[SynPacket] = []
    incident_start = load_dns_end + 30.0
    for incident_index in range(PORT_SCAN_INCIDENTS):
        incident = _port_scan_incident_packets(
            start_ts=incident_start, incident_index=incident_index
        )
        port_scan_packets.extend(incident)
        incident_start = incident[-1].timestamp + 6.0
    port_scan_end = port_scan_packets[-1].timestamp

    syn_flood_packets: list[SynPacket] = []
    incident_start = port_scan_end + 30.0
    for incident_index in range(SYN_FLOOD_INCIDENTS):
        incident = _syn_flood_incident_packets(
            start_ts=incident_start, incident_index=incident_index
        )
        syn_flood_packets.extend(incident)
        incident_start = incident[-1].timestamp + 6.0
    syn_flood_end = syn_flood_packets[-1].timestamp

    dns_alert_packets: list[DnsQueryPacket] = [_benign_dns_packet(ts=syn_flood_end + 5.0)]
    dga_domains = _model_verified_dga_domains()
    for offset, domain in enumerate(dga_domains, start=1):
        previous_ts = dns_alert_packets[-1].timestamp
        dns_alert_packets.append(
            _dga_dns_packet(ts=previous_ts + 0.1, query_name=domain, port_offset=offset)
        )

    return (*load_syn, *load_dns, *port_scan_packets, *syn_flood_packets, *dns_alert_packets)


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


def _dga_domain_names(packets: Sequence[Packet]) -> tuple[str, ...]:
    """Return every embedded DGA-candidate query name (excludes background/benign)."""

    return tuple(
        packet.query_name
        for packet in packets
        if isinstance(packet, DnsQueryPacket)
        and packet.query_name != "example.com"
        and not packet.query_name.startswith("benign-host-")
    )


def _manifest(packets: Sequence[Packet], capture: bytes) -> bytes:
    counts = _counts(packets)
    dga_domains = _dga_domain_names(packets)
    expected_alert_count = PORT_SCAN_INCIDENTS + SYN_FLOOD_INCIDENTS + len(dga_domains)
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
            "port_scan_incidents": PORT_SCAN_INCIDENTS,
            "port_scan_attempts_per_incident": PORT_SCAN_ATTEMPTS,
            "syn_flood_incidents": SYN_FLOOD_INCIDENTS,
            "syn_flood_events_per_incident": SYN_FLOOD_EVENTS,
            "dga_candidate_pool_size": DGA_CANDIDATE_POOL,
            "dga_model_verified_domains": len(dga_domains),
            "embedded_benign_dns_control_events": 1,
        },
        "expected_alert_count": expected_alert_count,
        "expected_alert_count_by_class": {
            "PORT_SCAN": PORT_SCAN_INCIDENTS,
            "SYN_FLOOD": SYN_FLOOD_INCIDENTS,
            "DGA": len(dga_domains),
        },
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
