from __future__ import annotations

import shutil
import subprocess
from importlib import resources
from pathlib import Path

import pytest

from sih26145.contracts.events import (
    EndOfStreamV1,
    StreamRecord,
    TcpSynAttemptV1,
    parse_stream_line,
)

FIXTURES = Path("tests/fixtures/milestone1").resolve()
POLICY = Path("src/sih26145/zeek/emit_syn_attempts.zeek").resolve()


def replay_policy(fixture_name: str, working_directory: Path) -> list[StreamRecord]:
    zeek = shutil.which("zeek")
    assert zeek is not None, "native Zeek must resolve through PATH"
    completed = subprocess.run(
        [zeek, "-b", "-r", str(FIXTURES / fixture_name), str(POLICY)],
        cwd=working_directory,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        shell=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    assert completed.stderr == b""
    assert list(working_directory.iterdir()) == []
    return [parse_stream_line(line) for line in completed.stdout.splitlines(keepends=True)]


@pytest.mark.integration
@pytest.mark.parametrize(
    ("fixture_name", "expected_events"),
    [
        ("benign.pcap", 10),
        ("vertical_below.pcap", 20),
        ("vertical_at_threshold.pcap", 20),
        ("horizontal_at_threshold.pcap", 20),
        ("retransmitted_syn.pcap", 20),
    ],
)
def test_native_policy_emits_syn_records_then_one_consistent_eos(
    fixture_name: str,
    expected_events: int,
    tmp_path: Path,
) -> None:
    records = replay_policy(fixture_name, tmp_path)

    assert len(records) == expected_events + 1
    syn_records = [record for record in records if isinstance(record, TcpSynAttemptV1)]
    assert len(syn_records) == expected_events
    eos = records[-1]
    assert isinstance(eos, EndOfStreamV1)
    assert eos.emitted_events == expected_events
    assert eos.last_event_ts == syn_records[-1].ts
    assert all(record.transport == "tcp" for record in syn_records)
    assert all(str(record.src_ip) == "192.0.2.10" for record in syn_records)


@pytest.mark.integration
def test_retransmitted_syn_packets_keep_one_zeek_uid(tmp_path: Path) -> None:
    records = replay_policy("retransmitted_syn.pcap", tmp_path)
    events = [record for record in records if isinstance(record, TcpSynAttemptV1)]

    assert len(events) == 20
    assert len({event.uid for event in events}) == 1


def test_policy_is_a_packaged_resource() -> None:
    policy = resources.files("sih26145").joinpath("zeek/emit_syn_attempts.zeek")

    assert policy.is_file()
