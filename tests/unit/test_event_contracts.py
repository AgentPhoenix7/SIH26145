from __future__ import annotations

import json
from typing import Any

import pytest

from sih26145.contracts.events import (
    EndOfStreamV1,
    StreamContractError,
    TcpSynAttemptV1,
    parse_stream_line,
)


def syn_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "tcp_syn_attempt_v1",
        "event_type": "tcp_syn_attempt",
        "ts": 1_700_000_000.125,
        "uid": "C9e2pMxSR3KXn846a",
        "src_ip": "192.0.2.10",
        "src_port": 58_024,
        "dst_ip": "198.51.100.20",
        "dst_port": 443,
        "transport": "tcp",
    }
    payload.update(overrides)
    return payload


def json_line(payload: object) -> bytes:
    return json.dumps(payload, separators=(",", ":"), allow_nan=True).encode() + b"\n"


def test_parse_valid_syn_line() -> None:
    record = parse_stream_line(json_line(syn_payload()))

    assert isinstance(record, TcpSynAttemptV1)
    assert str(record.src_ip) == "192.0.2.10"
    assert str(record.dst_ip) == "198.51.100.20"


def test_parse_valid_ipv6_syn_line() -> None:
    record = parse_stream_line(
        json_line(syn_payload(src_ip="2001:db8::10", dst_ip="2001:db8::20"))
    )

    assert isinstance(record, TcpSynAttemptV1)
    assert str(record.src_ip) == "2001:db8::10"


@pytest.mark.parametrize("port", [-1, 65_536, 1.5, "443", True])
def test_syn_port_is_strict_and_bounded(port: object) -> None:
    with pytest.raises(StreamContractError):
        parse_stream_line(json_line(syn_payload(dst_port=port)))


@pytest.mark.parametrize("port", [0, 65_535])
def test_boundary_ports_are_accepted(port: int) -> None:
    record = parse_stream_line(json_line(syn_payload(dst_port=port)))

    assert isinstance(record, TcpSynAttemptV1)
    assert record.dst_port == port


@pytest.mark.parametrize(
    "raw",
    [
        b"\n",
        b"{bad}\n",
        b"\xff\n",
        b"{}",
        b"x" * 16_384 + b"\n",
    ],
)
def test_invalid_or_unbounded_line_fails(raw: bytes) -> None:
    with pytest.raises(StreamContractError):
        parse_stream_line(raw)


def test_line_at_exact_byte_limit_is_accepted() -> None:
    compact = json_line(syn_payload())
    padded = compact[:-1] + (b" " * (16_384 - len(compact))) + b"\n"

    assert len(padded) == 16_384
    assert isinstance(parse_stream_line(padded), TcpSynAttemptV1)


@pytest.mark.parametrize(
    "overrides",
    [
        {"unexpected": "field"},
        {"schema_version": "tcp_syn_attempt_v2"},
        {"event_type": "connection"},
        {"uid": "contains whitespace"},
        {"uid": ""},
        {"src_ip": "not-an-ip"},
        {"transport": "udp"},
        {"ts": float("nan")},
        {"ts": float("inf")},
        {"ts": -0.1},
        {"ts": 253_402_300_800.0},
    ],
)
def test_invalid_syn_fields_fail(overrides: dict[str, Any]) -> None:
    with pytest.raises(StreamContractError):
        parse_stream_line(json_line(syn_payload(**overrides)))


def test_empty_eos_omits_last_timestamp() -> None:
    record = parse_stream_line(
        json_line(
            {
                "schema_version": "control_v1",
                "event_type": "end_of_stream",
                "emitted_events": 0,
            }
        )
    )

    assert isinstance(record, EndOfStreamV1)
    assert record.last_event_ts is None


def test_nonempty_eos_requires_last_timestamp() -> None:
    with pytest.raises(StreamContractError):
        parse_stream_line(
            json_line(
                {
                    "schema_version": "control_v1",
                    "event_type": "end_of_stream",
                    "emitted_events": 1,
                }
            )
        )


def test_empty_eos_rejects_last_timestamp() -> None:
    with pytest.raises(StreamContractError):
        parse_stream_line(
            json_line(
                {
                    "schema_version": "control_v1",
                    "event_type": "end_of_stream",
                    "emitted_events": 0,
                    "last_event_ts": 1_700_000_000.0,
                }
            )
        )


def test_empty_eos_rejects_explicit_null_timestamp() -> None:
    with pytest.raises(StreamContractError):
        parse_stream_line(
            json_line(
                {
                    "schema_version": "control_v1",
                    "event_type": "end_of_stream",
                    "emitted_events": 0,
                    "last_event_ts": None,
                }
            )
        )


def test_nonempty_eos_accepts_finite_last_timestamp() -> None:
    record = parse_stream_line(
        json_line(
            {
                "schema_version": "control_v1",
                "event_type": "end_of_stream",
                "emitted_events": 1,
                "last_event_ts": 1_700_000_000.0,
            }
        )
    )

    assert isinstance(record, EndOfStreamV1)
    assert record.last_event_ts == 1_700_000_000.0


def test_root_json_value_must_be_an_object() -> None:
    with pytest.raises(StreamContractError):
        parse_stream_line(json_line([syn_payload()]))
