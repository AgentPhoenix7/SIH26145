from __future__ import annotations

from typing import Any

from sih26145.contracts.events import TcpSynAttemptV1


def syn(
    *,
    ts: float = 100.0,
    uid: str = "uid-0",
    src_ip: str = "192.0.2.10",
    src_port: int = 40_000,
    dst_ip: str = "198.51.100.20",
    dst_port: int = 443,
    **overrides: Any,
) -> TcpSynAttemptV1:
    payload: dict[str, Any] = {
        "schema_version": "tcp_syn_attempt_v1",
        "event_type": "tcp_syn_attempt",
        "ts": ts,
        "uid": uid,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "transport": "tcp",
    }
    payload.update(overrides)
    return TcpSynAttemptV1.model_validate(payload)


def vertical_events(
    *,
    attempts: int,
    ports: int,
    start_ts: float = 100.0,
    step: float = 0.25,
    src_ip: str = "192.0.2.10",
) -> list[TcpSynAttemptV1]:
    return [
        syn(
            ts=start_ts + index * step,
            uid=f"uid-{index}",
            src_ip=src_ip,
            src_port=40_000 + index,
            dst_port=20 + (index % ports),
        )
        for index in range(attempts)
    ]


def horizontal_events(
    *,
    attempts: int,
    hosts: int,
    start_ts: float = 100.0,
    step: float = 0.25,
    src_ip: str = "192.0.2.10",
) -> list[TcpSynAttemptV1]:
    return [
        syn(
            ts=start_ts + index * step,
            uid=f"uid-{index}",
            src_ip=src_ip,
            src_port=40_000 + index,
            dst_ip=f"198.51.100.{20 + (index % hosts)}",
            dst_port=443,
        )
        for index in range(attempts)
    ]
