"""Small subprocess fixture for replay-runner lifecycle tests."""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any


def _write_stdout(value: dict[str, Any]) -> None:
    sys.stdout.buffer.write(json.dumps(value, separators=(",", ":")).encode() + b"\n")
    sys.stdout.buffer.flush()


def _syn(index: int, *, ts: float | None = None) -> dict[str, Any]:
    return {
        "schema_version": "tcp_syn_attempt_v1",
        "event_type": "tcp_syn_attempt",
        "ts": 100.0 + index * 0.1 if ts is None else ts,
        "uid": f"fake-{index}",
        "src_ip": "192.0.2.10",
        "src_port": 40_000 + index,
        "dst_ip": "198.51.100.20",
        "dst_port": 20 + index,
        "transport": "tcp",
    }


def _eos(count: int, last_ts: float | None = None) -> dict[str, Any]:
    record: dict[str, Any] = {
        "schema_version": "control_v1",
        "event_type": "end_of_stream",
        "emitted_events": count,
    }
    if last_ts is not None:
        record["last_event_ts"] = last_ts
    return record


def _hang() -> None:
    while True:
        time.sleep(60.0)


def main() -> int:
    mode = sys.argv[1]
    pid_path = Path(sys.argv[2])
    pid_path.write_text(str(os.getpid()), encoding="ascii")

    if mode == "happy":
        sys.stderr.write("fake child diagnostic\n")
        sys.stderr.flush()
        for index in range(20):
            _write_stdout(_syn(index))
            time.sleep(0.005)
        _write_stdout(_eos(20, 101.9))
        return 0
    if mode == "blank":
        sys.stdout.buffer.write(b"\n")
    elif mode == "oversized":
        sys.stdout.buffer.write(b"x" * 16_384 + b"\n")
    elif mode == "invalid-utf8":
        sys.stdout.buffer.write(b"\xff\n")
    elif mode == "malformed-json":
        sys.stdout.buffer.write(b'{"src_ip":"203.0.113.244",not-json}\n')
    elif mode == "unknown-record":
        _write_stdout({"schema_version": "mystery_v1", "event_type": "mystery"})
        return 0
    elif mode == "regression":
        _write_stdout(_syn(0, ts=101.0))
        _write_stdout(_syn(1, ts=100.0))
        return 0
    elif mode == "missing-eos":
        _write_stdout(_syn(0))
        return 0
    elif mode == "duplicate-eos":
        _write_stdout(_eos(0))
        _write_stdout(_eos(0))
        return 0
    elif mode == "premature-eos":
        _write_stdout(_eos(1, 100.0))
        return 0
    elif mode == "count-mismatch":
        _write_stdout(_syn(0))
        _write_stdout(_eos(2, 100.0))
        return 0
    elif mode == "timestamp-mismatch":
        _write_stdout(_syn(0))
        _write_stdout(_eos(1, 101.0))
        return 0
    elif mode == "data-after-eos":
        _write_stdout(_eos(0))
        sys.stdout.buffer.write(b"untrusted data after eos\n")
    elif mode == "nonzero":
        _write_stdout(_eos(0))
        return 7
    elif mode == "ignore-sigterm":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        sys.stdout.buffer.write(b"not-json\n")
        sys.stdout.buffer.flush()
        _hang()
    elif mode == "stderr-flood":
        sys.stderr.buffer.write(b"A" * 16_384)
        sys.stderr.buffer.write(b"B" * 65_536)
        sys.stderr.buffer.flush()
        _write_stdout(_eos(0))
        return 7
    elif mode == "hang-after-eos":
        _write_stdout(_eos(0))
        _hang()
    else:
        raise ValueError(f"unknown fake mode: {mode}")

    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
