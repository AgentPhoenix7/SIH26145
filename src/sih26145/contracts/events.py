"""Strict JSON Lines contracts for the native Zeek replay boundary."""

from __future__ import annotations

import json
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    StrictInt,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    model_validator,
)

MAX_LINE_BYTES = 16_384
MAX_CAPTURE_TS = 253_402_300_799.0


class StreamContractError(ValueError):
    """A stream line violated the bounded versioned input contract."""


class StrictModel(BaseModel):
    """Base model that rejects coercion and unknown fields."""

    model_config = ConfigDict(extra="forbid", strict=True)


CaptureTimestamp = Annotated[
    float,
    Field(ge=0.0, le=MAX_CAPTURE_TS, allow_inf_nan=False),
]
FlowUid = Annotated[str, StringConstraints(pattern=r"^[!-~]{1,128}$")]
TransportPort = Annotated[StrictInt, Field(ge=0, le=65_535)]


class TcpSynAttemptV1(StrictModel):
    """One originator TCP SYN observed by Zeek."""

    schema_version: Literal["tcp_syn_attempt_v1"]
    event_type: Literal["tcp_syn_attempt"]
    ts: CaptureTimestamp
    uid: FlowUid
    src_ip: IPvAnyAddress
    src_port: TransportPort
    dst_ip: IPvAnyAddress
    dst_port: TransportPort
    transport: Literal["tcp"]


class EndOfStreamV1(StrictModel):
    """Final record proving how many SYN records Zeek emitted."""

    schema_version: Literal["control_v1"]
    event_type: Literal["end_of_stream"]
    emitted_events: Annotated[StrictInt, Field(ge=0)]
    last_event_ts: CaptureTimestamp | None = None

    @model_validator(mode="after")
    def validate_last_timestamp(self) -> Self:
        timestamp_was_supplied = "last_event_ts" in self.model_fields_set
        if self.emitted_events == 0 and timestamp_was_supplied:
            raise ValueError("last_event_ts must be omitted when emitted_events is zero")
        if self.emitted_events > 0 and (not timestamp_was_supplied or self.last_event_ts is None):
            raise ValueError("last_event_ts is required when emitted_events is positive")
        return self


StreamRecord = Annotated[
    TcpSynAttemptV1 | EndOfStreamV1,
    Field(discriminator="event_type"),
]
_STREAM_RECORD_ADAPTER: TypeAdapter[StreamRecord] = TypeAdapter(StreamRecord)


def _reject_nonstandard_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def parse_stream_line(raw: bytes) -> StreamRecord:
    """Decode and validate one bounded, newline-terminated JSONL record."""

    if not raw:
        raise StreamContractError("stream ended without a record")
    if len(raw) > MAX_LINE_BYTES:
        raise StreamContractError("stream line exceeds 16384-byte limit")
    if not raw.endswith(b"\n"):
        raise StreamContractError("stream line is not newline terminated")

    try:
        text = raw.decode("utf-8", errors="strict")
        if not text.strip():
            raise ValueError("blank stream line")
        value = json.loads(text, parse_constant=_reject_nonstandard_constant)
        if not isinstance(value, dict):
            raise ValueError("stream record must be a JSON object")
        record: StreamRecord = _STREAM_RECORD_ADAPTER.validate_python(value)
        return record
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        raise StreamContractError("invalid stream record") from exc
