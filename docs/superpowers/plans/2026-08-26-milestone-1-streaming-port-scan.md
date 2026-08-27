# Milestone 1 Streaming Port-Scan Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Approved by the user on 2026-08-26; ready for execution in an isolated worktree.

**Goal:** Build the smallest reproducible end-to-end path that replays a deterministic PCAP through native Zeek, consumes validated SYN-attempt events incrementally, maintains bounded scan state, and emits a validated evidence-bearing `PORT_SCAN` alert before end of stream.

**Architecture:** A packaged Zeek policy emits one flushed JSONL record for every originator TCP SYN and one final EOS record. A synchronous Python runner owns the child lifecycle and stream contract, while a concrete capture-time window and scan detector own monotonic event-time state, deduplication, bounds, cooldown, thresholding, and alert construction. Tiny deterministic IPv4 fixtures are generated offline with the Python standard library; IPv6 remains covered at the schema and detector unit level in this milestone.

**Tech Stack:** Native Zeek 8.2.2 through `PATH`; Python 3.12+; uv; Pydantic 2; pytest; Ruff; mypy; Python standard library subprocess/threading/PCAP generation. Bun remains the required frontend tool, but Milestone 1 creates no frontend and invokes no npm-family command.

**Spec:** `docs/architecture.md`

## Global Constraints

- Consume only passive PCAP data; never connect to, probe, interpolate, or otherwise use observed endpoints as destinations.
- Do not decrypt payloads, create a network listener, add a return path, or add mitigation behavior.
- Invoke `zeek` through `PATH` with an argument vector; do not use a shell or hard-code `/opt/zeek/bin/zeek`.
- Process stdout incrementally with a 16 KiB per-line limit; alert JSON goes only to stdout and diagnostics only to stderr.
- Use capture time, zero allowed lateness, explicit expiry, and hard cardinality limits.
- Treat thresholds as configurable CLI behavior and fixed schema/resource limits as code-owned values.
- Use Python 3.12+ and uv. Do not install a second Zeek, add a Zeek container, use CUDA, or create frontend scaffolding.
- Do not claim Milestone 1 or any compliance status as verified until the exact final proof commands pass.

## Approval Decisions Incorporated by This Draft

1. **Flush Zeek stdout explicitly.** Call `flush_all()` after each event and EOS `print`. Newline order alone is insufficient evidence of bounded delivery when stdout is a pipe.
2. **Put event-time ownership in the state engine.** `PortScanWindow.observe()` rejects a timestamp below its watermark before mutation. The runner owns process order and EOS/count consistency but does not duplicate the watermark rule.
3. **Bound cooldown separately.** Maintain an expiry-ordered `source -> last_alert_ts` map with a hard limit of 4,096 entries. Expire entries at `last_alert_ts + cooldown_seconds`; fail without partial mutation if a new alert would exceed the bound.
4. **Add a post-EOS process bound.** Zeek must exit within 2 seconds after EOS. Otherwise the runner fails and terminates/kills that child, avoiding an indefinite read while checking that no data follows EOS.
5. **Keep the initial rule and heuristic score.** Retain the documented 10-second window, 20-attempt/15-host-or-port thresholds, 30-second cooldown, confidence formula, and severity bands as uncalibrated controlled-demo defaults.
6. **Keep fixture scope IPv4-only.** Generate IPv4 PCAPs for the native end-to-end path; validate IPv4 and IPv6 event handling in focused Python tests. This avoids an unnecessary second packet encoder before the first vertical slice works.

These decisions were approved on 2026-08-26. If any decision changes, revise `docs/architecture.md` and this plan together before continuing implementation.

## File and Responsibility Map

| Path | Responsibility |
| --- | --- |
| `pyproject.toml`, `uv.lock` | Minimal packaged runtime, CLI, and quality-tool configuration |
| `.gitignore` | Exclude virtual environments, caches, builds, large captures/data, and secrets while allowing committed tiny test fixtures |
| `src/sih26145/contracts/events.py` | Strict `tcp_syn_attempt_v1` / `control_v1` schemas and bounded JSONL parsing |
| `src/sih26145/contracts/alerts.py` | Strict typed `alert_v1` contract and cross-field evidence validation |
| `src/sih26145/detection/scan_window.py` | Capture-time window, counters, UID TTL deduplication, expiry, and resource bounds |
| `src/sih26145/detection/port_scan.py` | Thresholds, bounded cooldown, confidence/severity, and alert construction |
| `src/sih26145/replay.py` | Native Zeek command, pipe draining, EOS invariants, child cleanup, and failure reporting |
| `src/sih26145/cli.py` | `argparse` boundary, validated configuration, stdout/stderr separation, and exit codes |
| `src/sih26145/zeek/emit_syn_attempts.zeek` | Passive SYN packet observation and flushed versioned JSONL emission |
| `tools/generate_milestone1_fixtures.py` | Offline deterministic Ethernet/IPv4/TCP PCAP and manifest generation/checking |
| `tests/unit/` | Contract, state, detector, and generator behavior without Zeek |
| `tests/integration/` | Fake-child lifecycle/stream failures and native Zeek policy contract |
| `tests/e2e/` | Real fixture → Zeek → Python → alert acceptance path |
| `tests/fixtures/milestone1/` | Small committed PCAPs and provenance manifests |
| `docs/features.md` | Implemented `tcp_syn_attempt_v1` and scan-feature definitions |
| `docs/requirements-traceability.md` | Requirement status, exact commands, and evidence |
| `docs/ppt-notes.md` | Only actual verified alert/demo evidence produced by this milestone |
| `README.md`, `PROGRESS.md`, `docs/architecture.md` | Reproduction instructions, factual handoff, and approved clarifications |

---

### Task 1: Project Foundation and Strict Stream Contracts

**Files:**
- Create: `pyproject.toml`
- Create: `uv.lock`
- Create: `.gitignore`
- Create: `src/sih26145/__init__.py`
- Create: `src/sih26145/contracts/__init__.py`
- Create: `src/sih26145/contracts/events.py`
- Create: `tests/unit/test_event_contracts.py`

**Interfaces:**
- Produces: `TcpSynAttemptV1`, `EndOfStreamV1`, `StreamRecord`, `StreamContractError`, and `parse_stream_line(raw: bytes) -> StreamRecord`.
- Invariants: `extra="forbid"`; strict integers; finite epoch seconds `0 <= ts <= 253402300799`; ASCII visible UID regex `^[!-~]{1,128}$`; IP parsing; TCP literal; EOS conditional fields; newline-terminated UTF-8 JSON bounded to 16,384 total bytes including LF.

- [ ] **Step 1: Add the minimal uv package and quality configuration**

Use `requires-python = ">=3.12"`, runtime dependency `pydantic>=2,<3`, a `sih26145-replay = "sih26145.cli:main"` script, and a dev dependency group containing pytest, Ruff, and mypy. Configure pytest markers `integration` and `e2e`, Ruff for Python 3.12, and strict mypy over `src`, `tests`, and `tools`. Add `.gitignore` entries for `.venv/`, Python/tool caches, `dist/`, coverage outputs, credentials, models, and general PCAP/data outputs, with an explicit allow rule for `tests/fixtures/milestone1/*.pcap`. Do not add FastAPI, NumPy, ML, PCAP libraries, or frontend dependencies.

- [ ] **Step 2: Write failing input-contract tests**

```python
def test_parse_valid_syn_line() -> None:
    record = parse_stream_line(valid_syn_json() + b"\n")
    assert isinstance(record, TcpSynAttemptV1)
    assert str(record.src_ip) == "192.0.2.10"


@pytest.mark.parametrize("port", [-1, 65536, 1.5, "443", True])
def test_syn_port_is_strict_and_bounded(port: object) -> None:
    with pytest.raises(StreamContractError):
        parse_stream_line(syn_json(dst_port=port) + b"\n")


@pytest.mark.parametrize("raw", [b"\n", b"{bad}\n", b"\xff\n", b"{}", b"x" * 16384 + b"\n"])
def test_invalid_or_unbounded_line_fails(raw: bytes) -> None:
    with pytest.raises(StreamContractError):
        parse_stream_line(raw)


def test_nonempty_eos_requires_matching_last_timestamp_field() -> None:
    with pytest.raises(StreamContractError):
        parse_stream_line(eos_json(emitted_events=1, last_event_ts=None) + b"\n")
```

Also cover unknown fields/schema/event types, whitespace in UID, NaN/infinity, invalid IPv4/IPv6, port 0 and 65535 acceptance, an empty EOS with omitted `last_event_ts`, and a nonempty EOS with a finite timestamp.

- [ ] **Step 3: Run the focused tests and confirm the expected failure**

Run: `uv run pytest tests/unit/test_event_contracts.py -v`

Expected: FAIL during collection because `sih26145.contracts.events` does not exist.

- [ ] **Step 4: Implement the exact parsing boundary**

```python
MAX_LINE_BYTES = 16_384
MAX_CAPTURE_TS = 253_402_300_799.0


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class TcpSynAttemptV1(StrictModel):
    schema_version: Literal["tcp_syn_attempt_v1"]
    event_type: Literal["tcp_syn_attempt"]
    ts: Annotated[float, Field(ge=0.0, le=MAX_CAPTURE_TS, allow_inf_nan=False)]
    uid: Annotated[str, StringConstraints(pattern=r"^[!-~]{1,128}$")]
    src_ip: IPvAnyAddress
    src_port: Annotated[StrictInt, Field(ge=0, le=65535)]
    dst_ip: IPvAnyAddress
    dst_port: Annotated[StrictInt, Field(ge=0, le=65535)]
    transport: Literal["tcp"]


class EndOfStreamV1(StrictModel):
    schema_version: Literal["control_v1"]
    event_type: Literal["end_of_stream"]
    emitted_events: Annotated[StrictInt, Field(ge=0)]
    last_event_ts: (
        Annotated[float, Field(ge=0.0, le=MAX_CAPTURE_TS, allow_inf_nan=False)] | None
    ) = None

    @model_validator(mode="after")
    def validate_last_timestamp(self) -> Self:
        if (self.emitted_events == 0) != (self.last_event_ts is None):
            raise ValueError("last_event_ts must be omitted exactly when emitted_events is zero")
        return self
```

`parse_stream_line` must reject a missing final newline, measure bytes before UTF-8 decoding, decode with `errors="strict"`, parse one JSON object, reject non-standard JSON constants, and validate through a discriminated `TypeAdapter` keyed by `event_type`. Wrap Unicode, JSON, and Pydantic failures in `StreamContractError` without printing the untrusted line.

- [ ] **Step 5: Run focused and static checks**

Run: `uv run pytest tests/unit/test_event_contracts.py -v`

Expected: PASS.

Run: `uv run ruff check src/sih26145/contracts tests/unit/test_event_contracts.py && uv run mypy src/sih26145/contracts tests/unit/test_event_contracts.py`

Expected: both exit 0.

- [ ] **Step 6: Commit the contract slice**

```bash
git add .gitignore pyproject.toml uv.lock src/sih26145/__init__.py src/sih26145/contracts tests/unit/test_event_contracts.py
git commit -m "feat: define milestone one stream contracts"
```

---

### Task 2: Typed Common Alert Contract

**Files:**
- Create: `src/sih26145/contracts/alerts.py`
- Create: `tests/unit/test_alert_contracts.py`

**Interfaces:**
- Consumes: validated IP types and timestamp range semantics from Task 1.
- Produces: `Severity`, `DetectorIdentity`, `AlertSource`, `AlertWindow`, `ScanThresholdEvidence`, `DestinationSample`, `PortScanEvidence`, and `AlertV1`.
- Serialization: `AlertV1.model_dump_json()` emits UTC timestamps in canonical RFC 3339 form ending in `Z`.

- [ ] **Step 1: Write the failing happy-path and cross-field tests**

```python
def test_alert_v1_round_trips_with_typed_scan_evidence() -> None:
    alert = AlertV1.model_validate(valid_alert_dict())
    encoded = alert.model_dump_json()
    assert '"schema_version":"alert_v1"' in encoded
    assert '"timestamp":"2026-08-26T15:00:00.123456Z"' in encoded


@pytest.mark.parametrize(
    ("field", "value"),
    [("confidence", -0.01), ("confidence", 1.01), ("flow_id", ""), ("protocol", "udp")],
)
def test_alert_rejects_invalid_common_values(field: str, value: object) -> None:
    payload = valid_alert_dict()
    payload[field] = value
    with pytest.raises(ValidationError):
        AlertV1.model_validate(payload)


def test_alert_rejects_evidence_that_cannot_describe_its_window() -> None:
    payload = valid_alert_dict()
    payload["evidence"]["deduplicated_attempts"] = 2
    payload["evidence"]["unique_destination_endpoints"] = 3
    with pytest.raises(ValidationError):
        AlertV1.model_validate(payload)
```

Cover non-UTC/naive timestamps, inverted windows, span greater than configured window, `observed_span_seconds != end - start`, `attempt_rate_per_second != attempts / configured_seconds`, counts above attempts, endpoint count below host/port maxima, duplicate/unsorted samples, more than 10 samples, negative values, unknown fields, invalid detector version/name, and all three severity values.

- [ ] **Step 2: Run the focused test and confirm failure**

Run: `uv run pytest tests/unit/test_alert_contracts.py -v`

Expected: FAIL because `sih26145.contracts.alerts` does not exist.

- [ ] **Step 3: Implement the alert models and exact consistency rules**

```python
class AlertV1(StrictModel):
    schema_version: Literal["alert_v1"] = "alert_v1"
    timestamp: datetime
    flow_id: Annotated[str, StringConstraints(pattern=r"^[!-~]{1,128}$")]
    threat_class: Literal["PORT_SCAN"]
    protocol: Literal["tcp"]
    confidence: Annotated[float, Field(ge=0.0, le=1.0, allow_inf_nan=False)]
    severity: Severity
    detector: DetectorIdentity
    source: AlertSource
    window: AlertWindow
    evidence: PortScanEvidence
```

Use model validators to require timezone-aware UTC values, `start <= end`, `end - start <= configured_seconds`, exact integer count relationships, deterministic unique samples, and `math.isclose(actual, expected, rel_tol=1e-9, abs_tol=1e-9)` for calculated floats. Use field serializers that normalize UTC datetimes to six fractional digits plus `Z`.

- [ ] **Step 4: Run focused and static checks**

Run: `uv run pytest tests/unit/test_alert_contracts.py -v`

Expected: PASS.

Run: `uv run ruff check src/sih26145/contracts tests/unit/test_alert_contracts.py && uv run mypy src/sih26145/contracts tests/unit/test_alert_contracts.py`

Expected: both exit 0.

- [ ] **Step 5: Commit the alert contract**

```bash
git add src/sih26145/contracts/alerts.py tests/unit/test_alert_contracts.py
git commit -m "feat: add validated port scan alert schema"
```

---

### Task 3: Bounded Capture-Time Scan Window

**Files:**
- Create: `src/sih26145/detection/__init__.py`
- Create: `src/sih26145/detection/scan_window.py`
- Create: `tests/factories.py`
- Create: `tests/unit/test_scan_window.py`

**Interfaces:**
- Consumes: `TcpSynAttemptV1`.
- Produces: `StateLimits`, `WindowSnapshot`, `PortScanWindow.observe(event: TcpSynAttemptV1) -> WindowSnapshot | None`, `TimestampRegressionError`, and `StateLimitExceeded`.
- `None` means a duplicate UID within the 60-second TTL; a nonduplicate returns the post-insert snapshot for that source.

- [ ] **Step 1: Write failing ordering, expiry, and deduplication tests**

```python
def test_exact_window_boundary_is_included_then_expires() -> None:
    window = PortScanWindow(window_seconds=10.0)
    window.observe(syn(ts=100.0, uid="first"))
    at_boundary = window.observe(syn(ts=110.0, uid="second"))
    assert at_boundary is not None and at_boundary.attempts == 2
    after_boundary = window.observe(syn(ts=110.000001, uid="third"))
    assert after_boundary is not None and after_boundary.attempts == 2


def test_uid_retransmission_does_not_change_state() -> None:
    window = PortScanWindow(window_seconds=10.0)
    first = window.observe(syn(ts=100.0, uid="same"))
    duplicate = window.observe(syn(ts=101.0, uid="same", dst_port=444))
    assert first is not None
    assert duplicate is None
    assert window.total_attempts == 1


def test_timestamp_regression_fails_before_mutation() -> None:
    window = PortScanWindow(window_seconds=10.0)
    window.observe(syn(ts=101.0, uid="accepted"))
    before = window.debug_counts()
    with pytest.raises(TimestampRegressionError):
        window.observe(syn(ts=100.0, uid="late"))
    assert window.debug_counts() == before
```

Also test equal timestamps preserving insertion order, per-source isolation, host/port/endpoint counters decrementing on expiry, dedup UID reuse after 60 seconds, IPv6 sources, and deterministic endpoint sorting by IP version/numeric IP/port.

- [ ] **Step 2: Write failing low-limit tests without large allocations**

Instantiate `StateLimits(max_active_sources=2, max_attempts_per_source=2, max_total_attempts=3, max_dedup_uids=3, max_cooldown_sources=2, dedup_ttl_seconds=60.0)` and separately cross each bound by one. Assert the named limit in `StateLimitExceeded.limit_name` and assert `debug_counts()` is unchanged by the rejected event.

- [ ] **Step 3: Run the focused tests and confirm failure**

Run: `uv run pytest tests/unit/test_scan_window.py -v`

Expected: FAIL because the scan window does not exist.

- [ ] **Step 4: Implement ordered state and preflighted mutation**

```python
@dataclass(frozen=True, slots=True)
class StateLimits:
    max_active_sources: int = 4_096
    max_attempts_per_source: int = 4_096
    max_total_attempts: int = 100_000
    max_dedup_uids: int = 200_000
    max_cooldown_sources: int = 4_096
    dedup_ttl_seconds: float = 60.0


@dataclass(frozen=True, slots=True)
class WindowSnapshot:
    source_ip: IPv4Address | IPv6Address
    start_ts: float
    end_ts: float
    attempts: int
    unique_hosts: int
    unique_ports: int
    unique_endpoints: int
    destination_samples: tuple[tuple[IPv4Address | IPv6Address, int], ...]


class PortScanWindow:
    def observe(self, event: TcpSynAttemptV1) -> WindowSnapshot | None:
        self._reject_timestamp_regression(event.ts)
        self._watermark = event.ts
        self._expire_attempts_and_uids(event.ts)
        if event.uid in self._seen_uids:
            return None
        self._preflight_limits(event)
        return self._insert_and_snapshot(event)
```

Use `OrderedDict` for source and UID expiry, a `deque` per source, and `Counter` objects for destinations. Reject regression first, advance the watermark, expire entries with `attempt.ts < watermark - window_seconds` and `uid.first_seen_ts < watermark - dedup_ttl_seconds`, preflight every affected bound, then mutate. Exact window and UID-TTL boundaries remain included; an epsilon past them expires the entry. Do not silently evict live evidence. `debug_counts()` returns only integer counts for tests/health diagnostics, never raw untrusted values.

- [ ] **Step 5: Run focused and static checks**

Run: `uv run pytest tests/unit/test_scan_window.py -v`

Expected: PASS.

Run: `uv run ruff check src/sih26145/detection/scan_window.py tests && uv run mypy src/sih26145/detection/scan_window.py tests/factories.py tests/unit/test_scan_window.py`

Expected: both exit 0.

- [ ] **Step 6: Commit the bounded state engine**

```bash
git add src/sih26145/detection tests/factories.py tests/unit/test_scan_window.py
git commit -m "feat: add bounded capture-time scan window"
```

---

### Task 4: Port-Scan Rule, Cooldown, Confidence, and Evidence

**Files:**
- Create: `src/sih26145/detection/port_scan.py`
- Create: `tests/unit/test_port_scan_detector.py`

**Interfaces:**
- Consumes: `PortScanWindow`, `WindowSnapshot`, `AlertV1`.
- Produces: `ScanConfig` and `PortScanDetector.process(event: TcpSynAttemptV1) -> AlertV1 | None`.
- Defaults: window 10.0 s, minimum attempts 20, minimum ports 15, minimum hosts 15, cooldown 30.0 s.

- [ ] **Step 1: Write failing configuration and threshold tests**

```python
def test_vertical_scan_alerts_at_exact_threshold() -> None:
    detector = PortScanDetector(config=ScanConfig())
    alerts = [detector.process(event) for event in vertical_events(attempts=20, ports=15)]
    alert = next(item for item in alerts if item is not None)
    assert alert.flow_id == "uid-19"
    assert alert.evidence.deduplicated_attempts == 20
    assert alert.evidence.unique_destination_ports == 15
    assert alert.confidence == 0.75
    assert alert.severity is Severity.MEDIUM


def test_below_both_fanout_thresholds_does_not_alert() -> None:
    detector = PortScanDetector(config=ScanConfig())
    assert all(detector.process(event) is None for event in vertical_events(attempts=20, ports=14))
```

Cover horizontal threshold, minimum-attempt gate, per-source isolation, custom CLI-equivalent config, invalid/NaN durations, nonpositive thresholds, and confidence/severity boundaries.

- [ ] **Step 2: Write failing cooldown and evidence tests**

Test suppression before 30 seconds, re-alert exactly at 30 seconds if the current window still satisfies the rule, no state freeze during cooldown, expiry of cooldown entries, and the low `max_cooldown_sources=2` failure without partial insertion. Assert source, trigger UID, UTC timestamps, window, rate, observed span, thresholds, and at most 10 sorted destination samples all come from the current snapshot.

- [ ] **Step 3: Run the focused test and confirm failure**

Run: `uv run pytest tests/unit/test_port_scan_detector.py -v`

Expected: FAIL because `sih26145.detection.port_scan` does not exist.

- [ ] **Step 4: Implement the concrete detector**

```python
class ScanConfig(StrictModel):
    window_seconds: Annotated[float, Field(gt=0.0, allow_inf_nan=False)] = 10.0
    minimum_attempts: Annotated[StrictInt, Field(gt=0)] = 20
    minimum_unique_destination_ports: Annotated[StrictInt, Field(gt=0)] = 15
    minimum_unique_destination_hosts: Annotated[StrictInt, Field(gt=0)] = 15
    cooldown_seconds: Annotated[float, Field(ge=0.0, allow_inf_nan=False)] = 30.0


class PortScanDetector:
    def process(self, event: TcpSynAttemptV1) -> AlertV1 | None:
        snapshot = self._window.observe(event)
        self._expire_cooldowns(event.ts)
        if snapshot is None or not self._crosses_threshold(snapshot):
            return None
        if self._is_cooling_down(event.src_ip, event.ts):
            return None
        self._preflight_cooldown_limit(event.src_ip)
        alert = self._build_alert(event, snapshot)
        self._last_alert_by_source[event.src_ip] = event.ts
        return alert
```

Build the documented confidence formula exactly and round to four decimals. Derive severity with `<0.85`, `<0.95`, else critical. Convert capture timestamps with `datetime.fromtimestamp(ts, UTC)`. Construct typed evidence and let `AlertV1` validate the final record; never assemble an untyped evidence dictionary at the output boundary.

- [ ] **Step 5: Run focused and static checks**

Run: `uv run pytest tests/unit/test_port_scan_detector.py -v`

Expected: PASS.

Run: `uv run ruff check src/sih26145/detection tests/unit/test_port_scan_detector.py && uv run mypy src/sih26145/detection tests/unit/test_port_scan_detector.py`

Expected: both exit 0.

- [ ] **Step 6: Commit detector behavior**

```bash
git add src/sih26145/detection/port_scan.py tests/unit/test_port_scan_detector.py
git commit -m "feat: detect port scan fanout with evidence"
```

---

### Task 5: Deterministic Offline PCAP Fixtures and Manifests

**Files:**
- Create: `tools/generate_milestone1_fixtures.py`
- Create: `tests/unit/test_fixture_generator.py`
- Create: `tests/fixtures/milestone1/benign.pcap`
- Create: `tests/fixtures/milestone1/vertical_below.pcap`
- Create: `tests/fixtures/milestone1/vertical_at_threshold.pcap`
- Create: `tests/fixtures/milestone1/horizontal_at_threshold.pcap`
- Create: `tests/fixtures/milestone1/retransmitted_syn.pcap`
- Create: matching `*.manifest.json` files beside each PCAP

**Interfaces:**
- Produces: deterministic little-endian microsecond PCAP files containing Ethernet + IPv4 + TCP SYN packets with valid IPv4 and TCP checksums.
- CLI: `uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1` writes; adding `--check` regenerates in memory and exits nonzero on any byte/manifest drift.

- [ ] **Step 1: Write failing checksum, determinism, and scenario tests**

```python
def test_generation_is_byte_deterministic(tmp_path: Path) -> None:
    first = generate_all(tmp_path / "first")
    second = generate_all(tmp_path / "second")
    assert {p.name: p.read_bytes() for p in first} == {p.name: p.read_bytes() for p in second}


def test_manifest_hash_matches_capture(tmp_path: Path) -> None:
    pcap_paths = generate_all(tmp_path)
    for pcap in pcap_paths:
        manifest = json.loads(pcap.with_suffix(".manifest.json").read_text())
        assert manifest["capture_sha256"] == hashlib.sha256(pcap.read_bytes()).hexdigest()
```

Parse the generated headers with `struct.unpack` in tests to verify PCAP magic/version/link type, captured/original lengths, EtherType, IPv4 total length/checksum, TCP SYN flags/checksum, documentation-only addresses, packet counts, and strictly nondecreasing timestamps. Assert the module imports no `socket`, subprocess, or third-party packet library.

- [ ] **Step 2: Run the focused test and confirm failure**

Run: `uv run pytest tests/unit/test_fixture_generator.py -v`

Expected: FAIL because the generator does not exist.

- [ ] **Step 3: Implement the offline encoder and exact scenarios**

```python
def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


PCAP_GLOBAL_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
```

Implement `ethernet_ipv4_tcp_syn(packet: SynPacket) -> bytes`, `write_pcap(path: Path, packets: Sequence[TimestampedPacket]) -> str`, and `generate_all(output: Path) -> list[Path]` using this checksum and header. `write_pcap` returns the SHA-256 of the exact bytes it writes; `generate_all` writes manifests from those returned digests.

Use epoch `1_700_000_000`, deterministic microsecond offsets, fixed MAC addresses, `192.0.2.0/24` sources, `198.51.100.0/24` destinations, and no random source. Vary source ports so unique scan attempts receive distinct Zeek UIDs; keep the retransmission fixture's 5-tuple and TCP sequence constant. Encode these outcomes:

- `benign`: 10 attempts, 10 destination ports, one destination host, no alert.
- `vertical_below`: 20 attempts, 14 destination ports, one host, no alert.
- `vertical_at_threshold`: 20 attempts, 15 destination ports, one host, one alert.
- `horizontal_at_threshold`: 20 attempts, one destination port, 15 hosts, one alert.
- `retransmitted_syn`: 20 repeated SYN packets for one 5-tuple/sequence, one deduplicated attempt, no alert.

Each manifest records schema version, generator version, scenario ID/label, parameters, expected alert count, UTC timestamp range, endpoint ranges, packet count, actual SHA-256, and provenance `locally_generated_documentation_ranges`.

- [ ] **Step 4: Generate committed fixtures and prove regeneration stability**

Run: `uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1`

Expected: five PCAPs and five manifests are written with actual computed hashes.

Run: `uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1 --check`

Expected: exit 0 with no changed artifact.

- [ ] **Step 5: Run focused and static checks**

Run: `uv run pytest tests/unit/test_fixture_generator.py -v && uv run ruff check tools tests/unit/test_fixture_generator.py && uv run mypy tools/generate_milestone1_fixtures.py tests/unit/test_fixture_generator.py`

Expected: all exit 0.

- [ ] **Step 6: Commit fixtures and provenance**

```bash
git add tools/generate_milestone1_fixtures.py tests/unit/test_fixture_generator.py tests/fixtures/milestone1
git commit -m "test: add deterministic milestone one pcaps"
```

---

### Task 6: Native Zeek SYN-to-JSONL Policy

**Files:**
- Create: `src/sih26145/zeek/emit_syn_attempts.zeek`
- Create: `tests/integration/test_zeek_policy.py`
- Modify: `pyproject.toml` (ensure the `.zeek` resource is included in the wheel)

**Interfaces:**
- Consumes: passive PCAP packets.
- Produces: only `tcp_syn_attempt_v1` lines followed by exactly one `control_v1` EOS line on stdout.

- [ ] **Step 1: Write failing native-policy contract tests**

Invoke `zeek -b -r <fixture> <absolute-policy-path>` with `subprocess.run(["zeek", "-b", "-r", str(fixture), str(policy)], shell=False, cwd=tmp_path, check=False, capture_output=True)`. Parse every stdout line using `parse_stream_line`. Assert zero exit, `list(tmp_path.iterdir()) == []`, correct SYN count, originator-only records, a final EOS count/timestamp match, and no record after EOS. On the retransmission PCAP, assert Zeek emits repeated packet events with one stable UID so Python deduplication has the documented input.

- [ ] **Step 2: Run the integration test and confirm failure**

Run: `uv run pytest tests/integration/test_zeek_policy.py -v`

Expected: FAIL because the policy file does not exist.

- [ ] **Step 3: Implement the passive policy with explicit flushes**

```zeek
global emitted_events: count = 0;
global last_event_ts: time = 0secs;

event connection_SYN_packet(c: connection, pkt: SYN_packet)
    {
    if ( ! pkt$is_orig )
        return;

    local ts = network_time();
    local record: table[string] of any = {
        ["schema_version"] = "tcp_syn_attempt_v1",
        ["event_type"] = "tcp_syn_attempt",
        ["ts"] = ts,
        ["uid"] = c$uid,
        ["src_ip"] = c$id$orig_h,
        ["src_port"] = port_to_count(c$id$orig_p),
        ["dst_ip"] = c$id$resp_h,
        ["dst_port"] = port_to_count(c$id$resp_p),
        ["transport"] = "tcp"
    } &ordered;
    print to_json(record);
    flush_all();
    ++emitted_events;
    last_event_ts = ts;
    }
```

At `event zeek_done() &priority=-100`, create an ordered EOS table, add `last_event_ts` only when `emitted_events > 0`, print once, and call `flush_all()`. Do not load logging frameworks, open a file/socket, aggregate traffic, or refer to an observed address outside the JSON value.

- [ ] **Step 4: Run policy, packaging, and static checks**

Run: `uv run pytest tests/integration/test_zeek_policy.py -v`

Expected: PASS with native Zeek 8.2.2.

Run: `uv build && uv run python -c 'from pathlib import Path; from zipfile import ZipFile; wheels=list(Path("dist").glob("*.whl")); assert len(wheels)==1; names=ZipFile(wheels[0]).namelist(); assert sum(name.endswith("emit_syn_attempts.zeek") for name in names)==1'`

Expected: exactly one packaged policy resource is listed.

Run: `uv run ruff check tests/integration/test_zeek_policy.py && uv run mypy tests/integration/test_zeek_policy.py`

Expected: both exit 0.

- [ ] **Step 5: Commit the Zeek boundary**

```bash
git add pyproject.toml uv.lock src/sih26145/zeek/emit_syn_attempts.zeek tests/integration/test_zeek_policy.py
git commit -m "feat: stream syn attempts from native zeek"
```

---

### Task 7: Incremental Replay Runner and Failure Semantics

**Files:**
- Create: `src/sih26145/replay.py`
- Create: `tests/helpers/fake_zeek.py`
- Create: `tests/integration/test_replay_runner.py`

**Interfaces:**
- Produces: `ReplayResult(events_processed: int, alerts_emitted: int, last_event_ts: float | None)`, `ReplayError`, `run_command(command: Sequence[str], detector: PortScanDetector, emit_alert: Callable[[AlertV1], None]) -> ReplayResult`, and `run_replay(pcap_path: Path, detector: PortScanDetector, emit_alert: Callable[[AlertV1], None]) -> ReplayResult`.
- `run_replay` command is exactly `("zeek", "-b", "-r", str(pcap), str(policy))` with no shell and an isolated temporary cwd.

- [ ] **Step 1: Write failing incremental happy-path tests**

Use the fake child to write 20 valid SYN lines slowly enough for the callback to record each alert, then EOS. Assert the threshold alert callback occurs before the parser accepts EOS, the result count/timestamp matches, stderr is not mixed into alert output, and the command is a sequence with `shell=False`.

- [ ] **Step 2: Write failing stream-contract and lifecycle tests**

Parameterize blank, oversized, invalid UTF-8, malformed JSON, unknown record, regression, missing/duplicate/premature EOS, count mismatch, timestamp mismatch, data after EOS, nonzero exit, and a child that ignores `SIGTERM`. Assert each raises `ReplayError`, emits a named diagnostic without echoing the untrusted line, terminates only the direct child, escalates to `kill()` after 2 seconds when required, joins the stderr thread, and leaves no child running.

Add one fake-child mode that writes more than the OS pipe capacity to stderr before valid stdout; assert no deadlock and only the latest 64 KiB is retained. Add a mode that emits a valid EOS but does not exit; assert the new 2-second post-EOS limit fails the run.

- [ ] **Step 3: Run the focused tests and confirm failure**

Run: `uv run pytest tests/integration/test_replay_runner.py -v`

Expected: FAIL because `sih26145.replay` does not exist.

- [ ] **Step 4: Implement bounded line consumption and EOS accounting**

```python
@dataclass(frozen=True, slots=True)
class ReplayResult:
    events_processed: int
    alerts_emitted: int
    last_event_ts: float | None


process = subprocess.Popen(
    list(command),
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    cwd=temporary_working_directory,
    shell=False,
    bufsize=0,
)
```

Implement the declared `run_command` and `run_replay` interfaces around this exact process boundary. Keep the event loop synchronous and use only the stderr drain thread; do not add asyncio or a general process abstraction.

Use `subprocess.Popen` with `stdout=PIPE`, `stderr=PIPE`, `shell=False`, `bufsize=0`, and a temporary cwd. Drain stderr in one daemon thread into a byte-bounded `deque` while forwarding decoded replacement-text diagnostics to stderr. The main thread calls a bounded newline reader, validates and processes each SYN immediately, flushes each callback before reading again, and validates one EOS against observed count/last timestamp.

After EOS, wait at most 2 seconds for child exit, then read any remaining stdout and reject nonempty data. On any failure call `terminate()`, wait 2 seconds, then `kill()` only if necessary. Always close pipes, wait/reap, and join the stderr thread in `finally`. Preserve already emitted alerts but return/exit failure.

- [ ] **Step 5: Resolve the packaged policy safely**

Use `importlib.resources.files("sih26145").joinpath("zeek/emit_syn_attempts.zeek")` and `as_file()` so the policy remains available from an installed wheel. Validate the PCAP is an existing regular file before process creation. Never derive the executable or policy path from packet contents.

- [ ] **Step 6: Run focused and static checks**

Run: `uv run pytest tests/integration/test_replay_runner.py -v`

Expected: PASS.

Run: `uv run ruff check src/sih26145/replay.py tests/helpers tests/integration/test_replay_runner.py && uv run mypy src/sih26145/replay.py tests/helpers tests/integration/test_replay_runner.py`

Expected: both exit 0.

- [ ] **Step 7: Commit the replay runner**

```bash
git add src/sih26145/replay.py tests/helpers tests/integration/test_replay_runner.py
git commit -m "feat: consume zeek replay incrementally"
```

---

### Task 8: CLI and Native End-to-End Acceptance

**Files:**
- Create: `src/sih26145/cli.py`
- Create: `tests/e2e/test_milestone1.py`

**Interfaces:**
- CLI: `uv run sih26145-replay PCAP [--window-seconds FLOAT] [--min-attempts INT] [--min-unique-ports INT] [--min-unique-hosts INT] [--cooldown-seconds FLOAT]`.
- Exit codes: `0` successful replay, `2` CLI/config/path error, `1` replay/contract/process/state failure.
- Output: one canonical `alert_v1` JSON object per stdout line, flushed immediately; diagnostics only on stderr.

- [ ] **Step 1: Write failing CLI boundary tests**

Assert missing/non-file PCAP and invalid thresholds exit 2 before Zeek starts; replay failures exit 1; help documents defaults and heuristic/unvalidated status; a valid benign replay exits 0 with empty stdout; and a valid scan replay exits 0 with only parseable `AlertV1` stdout lines.

- [ ] **Step 2: Write failing real native-Zeek acceptance tests**

Mark tests `e2e`. Replay `benign.pcap`, `vertical_at_threshold.pcap`, and `horizontal_at_threshold.pcap` through `run_replay`, not a fake. Assert 0/1/1 alerts, exact actual evidence, triggering flow IDs from Zeek output, and deterministic alert JSON across two runs. Replay `retransmitted_syn.pcap` and assert no alert.

Use a callback plus a monkeypatched wrapper around `parse_stream_line` only in the e2e test to record `alert` and `end_of_stream` observations; assert the alert observation precedes EOS acceptance. This keeps test instrumentation out of the production interface.

- [ ] **Step 3: Run the focused tests and confirm failure**

Run: `uv run pytest tests/e2e/test_milestone1.py -v`

Expected: FAIL because the CLI does not exist.

- [ ] **Step 4: Implement the CLI boundary**

```python
def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = ScanConfig(
            window_seconds=args.window_seconds,
            minimum_attempts=args.min_attempts,
            minimum_unique_destination_ports=args.min_unique_ports,
            minimum_unique_destination_hosts=args.min_unique_hosts,
            cooldown_seconds=args.cooldown_seconds,
        )
        detector = PortScanDetector(config=config)
        run_replay(args.pcap, detector, emit_alert)
    except (ValidationError, ReplayError, StateLimitExceeded) as exc:
        print(safe_diagnostic(exc), file=sys.stderr, flush=True)
        return 1
    return 0
```

Map argparse/path errors to 2. `emit_alert` writes `alert.model_dump_json() + "\n"` and flushes stdout. `safe_diagnostic` names the failure class and invariant but never includes a raw input line or observed endpoint.

- [ ] **Step 5: Run CLI and end-to-end checks**

Run: `uv run pytest tests/e2e/test_milestone1.py -v`

Expected: PASS using native Zeek 8.2.2.

Run: `uv run sih26145-replay tests/fixtures/milestone1/vertical_at_threshold.pcap`

Expected: exit 0 and one actual validated `alert_v1` JSON line on stdout.

Run: `uv run sih26145-replay tests/fixtures/milestone1/benign.pcap`

Expected: exit 0 and no stdout alert.

- [ ] **Step 6: Commit the complete runtime path**

```bash
git add src/sih26145/cli.py tests/e2e/test_milestone1.py
git commit -m "feat: add milestone one replay command"
```

---

### Task 9: Reproducibility, Traceability, and Final Evidence

**Files:**
- Modify: `docs/architecture.md`
- Create: `docs/features.md`
- Create: `docs/requirements-traceability.md`
- Create: `docs/ppt-notes.md`
- Modify: `README.md`
- Modify: `PROGRESS.md`

**Interfaces:**
- Consumes: only commands and outputs actually verified in Tasks 1–8.
- Produces: one reproducible quickstart, honest status labels, exact evidence commands, and a current SIH26145 compliance snapshot.

- [ ] **Step 1: Run the complete proof from the locked environment**

```bash
uv sync --frozen --group dev
uv run pytest -m "not e2e" -v
uv run pytest -m e2e -v
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests tools
uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1 --check
uv run sih26145-replay tests/fixtures/milestone1/vertical_at_threshold.pcap > /tmp/sih26145-scan-alerts.jsonl
uv run sih26145-replay tests/fixtures/milestone1/benign.pcap > /tmp/sih26145-benign-alerts.jsonl
uv run python -c 'from pathlib import Path; from sih26145.contracts.alerts import AlertV1; lines=Path("/tmp/sih26145-scan-alerts.jsonl").read_text().splitlines(); assert len(lines)==1; AlertV1.model_validate_json(lines[0]); assert Path("/tmp/sih26145-benign-alerts.jsonl").read_bytes()==b""'
```

Expected: every command exits 0; scan output contains exactly one schema-valid actual alert; benign output is empty. If any command fails, keep the corresponding status unverified and fix the root cause with a regression test before continuing.

- [ ] **Step 2: Measure only the narrow evidence this milestone can support**

Record native Zeek/Python versions, fixture hash, event count, alert count, and the fact that alert emission preceded EOS. Do not claim throughput capacity, production false-positive rate, calibrated confidence, ML inference, dashboard behavior, or coverage beyond port scanning.

- [ ] **Step 3: Update architecture and feature documentation**

Change the architecture status only after proof passes. Record the six approved clarifications from this plan, exact schema/feature semantics, capture-time expiry boundary, cooldown bound, and the IPv4-fixture/IPv6-unit-test scope. In `docs/features.md`, define attempts, unique hosts/ports/endpoints, fixed-window rate, observed span, confidence, and observability from passive SYN metadata.

- [ ] **Step 4: Add traceability and reproduction instructions**

In `docs/requirements-traceability.md`, use only `PLANNED`, `IN PROGRESS`, `IMPLEMENTED`, `VERIFIED`, or `DEFERRED`. Mark only the Milestone 1 scan rows supported by the exact proof. In README, document `uv sync --frozen --group dev`, fixture verification, test commands, and benign/scan replay commands; state that native Zeek must resolve through `PATH` and that Bun remains reserved for later frontend work.

- [ ] **Step 5: Update factual handoff and PPT evidence**

Update `PROGRESS.md` base commit/repository state, acceptance checkboxes, exact evidence, limitations, open risks, compliance snapshot, and next highest-priority milestone (SYN/DDoS). Add to `docs/ppt-notes.md` only actual alert fields and verified architecture/demo facts; do not invent screenshots, rates, or metrics.

- [ ] **Step 6: Re-run documentation-sensitive verification**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests tools && uv run pytest -v && git diff --check && git status --short`

Expected: all executable checks pass; `git diff --check` is clean; status contains only the intended Milestone 1 files.

- [ ] **Step 7: Commit the verified milestone documentation**

```bash
git add README.md PROGRESS.md docs/architecture.md docs/features.md docs/requirements-traceability.md docs/ppt-notes.md
git commit -m "docs: record milestone one verification"
```

## Plan Self-Review

- Spec coverage: every Milestone 1 acceptance condition in `PROGRESS.md` maps to Tasks 1–9.
- Ownership: Zeek parses packets; contracts validate; the window owns event time/state; the detector owns policy/cooldown/evidence; the runner owns process/EOS; the CLI owns user input/output.
- Bounds: line, stderr ring, attempts, sources, UIDs, cooldown entries, samples, termination grace, and post-EOS grace are explicit.
- Test-first ordering: every behavior task begins with a focused failing test and records its expected failure before implementation.
- Scope: no API, dashboard, Bun project, DDoS, DNS, ML, database, container, live capture, or benchmark claim is introduced.
- Approval gate: this document is a draft and creates no authority to execute implementation tasks.
