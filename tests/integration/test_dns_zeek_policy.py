from __future__ import annotations

import ipaddress
import shutil
import struct
import subprocess
from importlib import resources
from pathlib import Path

import pytest

from sih26145.contracts.events import DnsEventV1, EndOfStreamV1, parse_stream_line
from tools.generate_milestone1_fixtures import PCAP_GLOBAL_HEADER, internet_checksum

POLICY = Path("src/sih26145/zeek/emit_events.zeek").resolve()


def _dns_query_pcap(domain: str) -> bytes:
    labels = domain.encode("ascii").split(b".")
    question_name = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
    dns = (
        struct.pack("!HHHHHH", 0x2614, 0x0100, 1, 0, 0, 0)
        + question_name
        + struct.pack("!HH", 1, 1)
    )
    source_ip = ipaddress.IPv4Address("192.0.2.10").packed
    destination_ip = ipaddress.IPv4Address("198.51.100.53").packed
    udp_length = 8 + len(dns)
    udp_without_checksum = struct.pack("!HHHH", 53_000, 53, udp_length, 0)
    pseudo_header = source_ip + destination_ip + b"\x00\x11" + struct.pack("!H", udp_length)
    udp_checksum = internet_checksum(pseudo_header + udp_without_checksum + dns)
    udp = struct.pack("!HHHH", 53_000, 53, udp_length, udp_checksum) + dns
    ip_length = 20 + len(udp)
    ip_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_length,
        1,
        0x4000,
        64,
        17,
        0,
        source_ip,
        destination_ip,
    )
    ip_checksum = internet_checksum(ip_without_checksum)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_length,
        1,
        0x4000,
        64,
        17,
        ip_checksum,
        source_ip,
        destination_ip,
    )
    ethernet = bytes.fromhex("0200000000020200000000010800")
    frame = ethernet + ip_header + udp
    record_header = struct.pack("<IIII", 1_700_000_000, 250_000, len(frame), len(frame))
    return PCAP_GLOBAL_HEADER + record_header + frame


@pytest.mark.integration
def test_native_combined_policy_emits_dns_query_then_consistent_eos(tmp_path: Path) -> None:
    zeek = shutil.which("zeek")
    assert zeek is not None, "native Zeek must resolve through PATH"
    pcap = tmp_path / "query.pcap"
    pcap.write_bytes(_dns_query_pcap("Example.COM"))
    work = tmp_path / "work"
    work.mkdir()

    completed = subprocess.run(
        [zeek, "-D", "-b", "-r", str(pcap), str(POLICY)],
        cwd=work,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        shell=False,
    )

    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    assert completed.stderr == b""
    assert list(work.iterdir()) == []
    records = [parse_stream_line(line) for line in completed.stdout.splitlines(keepends=True)]
    assert len(records) == 2
    event = records[0]
    assert isinstance(event, DnsEventV1)
    assert event.query_name == "example.com"
    assert event.query_type == 1
    assert event.query_class == 1
    assert event.transport == "udp"
    assert str(event.src_ip) == "192.0.2.10"
    assert str(event.dst_ip) == "198.51.100.53"
    eos = records[1]
    assert isinstance(eos, EndOfStreamV1)
    assert eos.emitted_events == 1
    assert eos.last_event_ts == event.ts


def test_combined_policy_is_a_packaged_resource() -> None:
    policy = resources.files("sih26145").joinpath("zeek/emit_events.zeek")

    assert policy.is_file()
