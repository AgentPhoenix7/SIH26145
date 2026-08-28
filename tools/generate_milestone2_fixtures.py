"""Generate deterministic, offline Milestone 2 SYN-flood PCAP fixtures."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING or __package__:
    from tools.generate_milestone1_fixtures import BASE_TIMESTAMP, SynPacket, pcap_bytes
else:
    from generate_milestone1_fixtures import BASE_TIMESTAMP, SynPacket, pcap_bytes

GENERATOR_VERSION = "1.0.0"


@dataclass(frozen=True, slots=True)
class Scenario:
    scenario_id: str
    label: str
    expected_alert_count: int
    parameters: dict[str, int]
    packets: tuple[SynPacket, ...]


def _distributed_packets(
    *,
    syn_events: int,
    unique_sources: int,
    unique_targets: int,
) -> tuple[SynPacket, ...]:
    return tuple(
        SynPacket(
            timestamp=BASE_TIMESTAMP + index * 0.05,
            source_ip=f"192.0.2.{1 + index % unique_sources}",
            source_port=40_000 + index,
            destination_ip=f"198.51.100.{20 + index % unique_targets}",
            destination_port=443,
            sequence=2_000 + index,
            ip_identification=1_000 + index,
        )
        for index in range(syn_events)
    )


def scenarios() -> tuple[Scenario, ...]:
    """Return the three code-owned deterministic Milestone 2 scenarios."""

    return (
        Scenario(
            scenario_id="benign_distributed",
            label="BENIGN_DISTRIBUTED_SYN",
            expected_alert_count=0,
            parameters={
                "syn_events": 100,
                "unique_sources": 20,
                "unique_targets": 10,
            },
            packets=_distributed_packets(
                syn_events=100,
                unique_sources=20,
                unique_targets=10,
            ),
        ),
        Scenario(
            scenario_id="syn_flood_below",
            label="SYN_FLOOD_BELOW_THRESHOLD",
            expected_alert_count=0,
            parameters={
                "syn_events": 99,
                "unique_sources": 20,
                "unique_targets": 1,
            },
            packets=_distributed_packets(
                syn_events=99,
                unique_sources=20,
                unique_targets=1,
            ),
        ),
        Scenario(
            scenario_id="syn_flood_at_threshold",
            label="SYN_FLOOD",
            expected_alert_count=1,
            parameters={
                "syn_events": 100,
                "unique_sources": 20,
                "unique_targets": 1,
            },
            packets=_distributed_packets(
                syn_events=100,
                unique_sources=20,
                unique_targets=1,
            ),
        ),
    )


def _utc_string(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _ip_sort_key(value: str) -> tuple[int, int]:
    address = ipaddress.ip_address(value)
    return address.version, int(address)


def _manifest(scenario: Scenario, capture: bytes) -> bytes:
    manifest: dict[str, Any] = {
        "schema_version": "fixture_manifest_v1",
        "generator": "tools/generate_milestone2_fixtures.py",
        "generator_version": GENERATOR_VERSION,
        "scenario_id": scenario.scenario_id,
        "label": scenario.label,
        "parameters": scenario.parameters,
        "expected_alert_count": scenario.expected_alert_count,
        "expected_threat_class": "SYN_FLOOD",
        "timestamp_range": {
            "start": _utc_string(scenario.packets[0].timestamp),
            "end": _utc_string(scenario.packets[-1].timestamp),
        },
        "endpoints": {
            "source_ips": sorted(
                {packet.source_ip for packet in scenario.packets},
                key=_ip_sort_key,
            ),
            "destination_ips": sorted(
                {packet.destination_ip for packet in scenario.packets},
                key=_ip_sort_key,
            ),
            "destination_ports": sorted({packet.destination_port for packet in scenario.packets}),
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
