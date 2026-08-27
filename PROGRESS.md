# SIH26145 Progress and Conversation Handoff

Last updated: **2026-08-27 (UTC)**

## Current Phase

**Milestone 1 port-scan vertical slice is implemented and verified. The next priority is SYN/DDoS.**

The verified path is:

```text
deterministic PCAP replay
  -> native Zeek originator-SYN events
  -> versioned JSON Lines
  -> strict Python validation
  -> bounded capture-time scan state
  -> evidence-bearing alert_v1 PORT_SCAN output
```

This milestone covers exactly one of the six required threat classes: reconnaissance/port scanning. It does not include DDoS, C2 beaconing, DNS/DGA or tunnelling, encrypted-session malware metadata, data exfiltration, genuine ML, an API/dashboard, or performance benchmarking.

## Authoritative Context and Git State

- Official problem statement: `docs/problem.md`
- Durable rules: `AGENTS.md`
- Architecture: `docs/architecture.md`
- Versioned feature semantics: `docs/features.md`
- Requirements traceability: `docs/requirements-traceability.md`
- Repository: `/home/agntdrgn/WorkSpace/SIH26145`
- Implementation worktree: `/home/agntdrgn/WorkSpace/SIH26145/.worktrees/milestone-1-port-scan`
- Branch: `feature/milestone-1-port-scan`
- Branch point from `main`: `59afa18` (`docs: approve milestone one implementation plan`)
- Tasks 1-8 reviewed implementation base: `3ca426c` (`fix: preserve safe replay failures`)
- Required Task 9 formatter-only cleanup: `1be64d9` (`style: apply Ruff formatting`)
- This handoff and the Milestone 1 documentation are recorded by the documentation commit containing this file, whose predecessor is `1be64d9`.

The implementation history is intentionally sliced: contracts (`dd01d7f`, `78284b7`), bounded window and detector (`43fd8f1`, `e572485`), fixtures (`13a2512`), Zeek streaming policy (`8900707`), replay runner and deadline hardening (`2a41b6b`, `6871624`, `2bb8b0b`), and CLI/safe diagnostics (`c5371b2`, `3ca426c`). Inspect live status and commits before continuing because this snapshot can become stale.

## Verified Environment and Artifacts

Fresh 2026-08-27 commands reported:

| Item | Verified value |
| --- | --- |
| Native Zeek | `zeek version 8.2.2` |
| Python used by the locked uv environment | `Python 3.13.15` |
| uv | `uv 0.12.5 (x86_64-unknown-linux-gnu)` |
| Vertical threshold fixture | `tests/fixtures/milestone1/vertical_at_threshold.pcap` |
| Fixture SHA-256 | `1a1a615d3ed57fd929f993057e068daa812d5a19b022a4d7b7355d7892c93266` |
| Actual native replay accounting | 20 processed events, 1 emitted alert |
| Scan CLI output | 1 JSONL record, 1,041 bytes |
| Benign CLI output | 0 records, exactly 0 bytes |
| Incremental order | `alert,end_of_stream` |

The public native command is `zeek -D -b -r <pcap> <policy>`. `-D` makes identical controlled replays preserve the real Zeek UID and deterministic alert JSON. A Zeek UID is not durable across different captures, Zeek versions, or replay modes.

## Completed Implementation

- Strict `tcp_syn_attempt_v1`, `control_v1`, and typed `alert_v1` contracts reject untrusted fields and invalid values.
- A native Zeek policy emits and flushes one originator-SYN JSON record at a time followed by exactly one consistent EOS record.
- Python validates and processes each event before reading the next record; a threshold alert callback precedes EOS.
- The capture-time scan window deduplicates Zeek UIDs, tracks attempts/hosts/ports/endpoints, expires old state, and rejects timestamp regression before mutation.
- Hard limits cover line length, active sources, per-source and global attempts, retained UIDs, cooldown sources, stderr retention, and child process shutdown.
- The detector uses configurable attempt/fan-out thresholds, exact-boundary expiry and cooldown semantics, deterministic endpoint samples, and typed measured evidence.
- The CLI emits canonical alert JSON only on stdout; child stderr is privately retained only as the byte-exact latest 64 KiB and is never echoed. CLI stderr contains only trusted safe diagnostics.
- CLI status is `0` for success, `2` for invalid configuration/path, and `1` for runtime/process/contract/timestamp/callback/state-limit failure.
- Deterministic offline PCAP generation uses documentation-only IPv4 ranges and records scenario parameters, expected outcomes, packet counts, SHA-256, and provenance in manifests.
- IPv4 native replay is e2e tested; IPv6 schemas, state, and sample ordering are unit tested.

## Milestone 1 Acceptance

- [x] A deterministic PCAP passes through native Zeek.
- [x] Zeek produces versioned structured connection-attempt events and a consistent EOS record.
- [x] Python consumes records incrementally rather than loading a finished report.
- [x] Rolling scan state tracks source, destination hosts/ports/endpoints, deduplicated SYN attempts, fixed-window rate, and observation window.
- [x] State expires at documented capture-time boundaries and has explicit cardinality/resource limits.
- [x] Scan thresholds are configurable and validated.
- [x] Controlled vertical and horizontal scan fixtures raise validated `PORT_SCAN` alerts.
- [x] Benign and retransmitted-SYN fixtures do not raise the same alert.
- [x] `alert_v1` includes timestamp, flow ID, class, confidence, severity, detector/version, source, protocol, window, thresholds, and actual evidence.
- [x] Focused tests cover contracts, expiry, deduplication, thresholds, cooldown, state limits, process/EOS failure, safe diagnostics, and native replay.
- [x] The uv/native-Zeek workflow and fixture verification are reproducible.
- [x] Requirements traceability, feature documentation, PPT facts, and this handoff are current.

## Exact Evidence Commands

The managed sandbox required only a cache-location override; it does not change project behavior. The following exact commands were run from the worktree after mechanical Ruff cleanup:

```bash
UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv sync --frozen --group dev
UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv run pytest -m "not e2e" -v
UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv run pytest -m e2e -v
UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv run ruff check .
UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv run ruff format --check .
UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv run mypy src tests tools
UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1 --check
UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv run sih26145-replay tests/fixtures/milestone1/vertical_at_threshold.pcap > /tmp/sih26145-scan-alerts.jsonl
UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv run sih26145-replay tests/fixtures/milestone1/benign.pcap > /tmp/sih26145-benign-alerts.jsonl
UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv run python -c 'from pathlib import Path; from sih26145.contracts.alerts import AlertV1; lines=Path("/tmp/sih26145-scan-alerts.jsonl").read_text().splitlines(); assert len(lines)==1; AlertV1.model_validate_json(lines[0]); assert Path("/tmp/sih26145-benign-alerts.jsonl").read_bytes()==b""'
```

Evidence summary:

- `154 passed, 19 deselected` for non-e2e tests.
- `19 passed, 154 deselected` for native e2e tests.
- Ruff lint passed; Ruff format check confirmed 29 files already formatted; strict mypy found no issues in 22 source files.
- Fixture `--check` exited `0` without changing committed fixtures.
- Actual scan output contained one schema-valid alert; benign output was zero bytes.
- A direct replay observation recorded `events_processed=20 alerts_emitted=1 callback_alerts=1 order=alert,end_of_stream`.

Portable commands in `README.md` omit the sandbox-specific `UV_CACHE_DIR` prefix.

After updating the six Task 9 documents, this exact documentation-sensitive gate also exited `0`:

```bash
UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv run ruff check . && UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv run ruff format --check . && UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv run mypy src tests tools && UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv run pytest -v && git diff --check && git status --short
```

It reported all Ruff checks passed, 32 files already formatted, no mypy issues in 22 source files, and `173 passed`; `git diff --check` was clean and status listed only `README.md`, `PROGRESS.md`, `docs/architecture.md`, `docs/features.md`, `docs/requirements-traceability.md`, and `docs/ppt-notes.md`.

## Current SIH26145 Compliance Snapshot

```text
Read-only ingest:             VERIFIED for deterministic PCAP replay
Active probing/return path:   ABSENT and verified for the current path
Payload decryption:           ABSENT and verified for the current scan path
Streaming processing:         VERIFIED; alert callback precedes EOS
Bounded alert latency:        Incremental path implemented; wall-time percentiles NOT MEASURED
Alert schema/evidence:        VERIFIED with one actual strict alert_v1 record
Dataset research/provenance:  Official-resource research recorded; local fixture provenance VERIFIED
ML model trained:             NO
Model storage/resume:         NO; no model exists
Offline model inference:      NO; no model exists
Threat coverage:              1 / 6, exactly reconnaissance/port scanning
Throughput measured:          NO
Demo reproducible:            VERIFIED for native scan and benign replay
PPT evidence:                 Verified facts recorded; screenshots and performance plots NOT CAPTURED
```

## Limitations and Risks

- The rule is scan fan-out only. The remaining five official classes are unimplemented.
- Thresholds and the `0.75` threshold confidence are heuristic, not production calibrated or probability estimates.
- The benign fixture proves only its deterministic expected result; no production false-positive rate has been measured.
- Strict zero-lateness ordering rejects timestamp regressions instead of reordering merged/live traffic.
- A Zeek UID supports retransmission deduplication inside a replay but is not durable across different captures, versions, or modes.
- State pressure stops the prototype with a named invariant. A future live path needs measured degradation/telemetry without weakening bounds.
- Native e2e fixtures are IPv4; IPv6 has unit coverage only.
- Child stderr is intentionally not public. Trusted diagnostics preserve the failed invariant, but additional private troubleshooting tooling may be needed later.
- No wall-clock alert latency, throughput, CPU, or memory result exists.
- No official downloadable SIH26145 dataset was found as of 2026-08-26; every future corpus or scenario needs licence and provenance review.
- No API/dashboard, genuine ML artifact, offline model inference, screenshot, or final presentation exists yet.

## Immediate Next Objective: SYN/DDoS

Move directly to the next MUST-HAVE class rather than over-polishing scan detection:

1. Define the smallest versioned passive event/features needed for SYN-flood rate, response ratio, destination concentration, and source/spoofing-characteristic evidence while preserving runtime parity.
2. Add bounded rolling aggregate state on the existing incremental replay path, with named limits and capture-time expiry.
3. Create isolated, deterministic benign and controlled SYN-flood scenarios with ground-truth manifests; do not target any external or unauthorized endpoint.
4. Implement an explainable baseline detector, validate typed common alerts, and prove attack versus benign behavior before considering UDP reflection/amplification.
5. Record actual evidence in traceability, features, evaluation, PPT notes, and this handoff.

After SYN/DDoS, priority remains passive DNS/DGA or tunnelling data and the genuine trained/deployed ML component, then exfiltration, with C2 as SHOULD HAVE and encrypted-session metadata as stretch. API/dashboard and measured end-to-end evaluation remain required before submission.

## Handoff Checklist

1. Confirm the repository/worktree and inspect `git status`, diffs, and recent commits.
2. Read `AGENTS.md`, `docs/problem.md`, this file, and relevant source/tests completely.
3. Treat this as a verified snapshot, not a substitute for fresh commands.
4. Continue SYN/DDoS as the highest-priority milestone and preserve all passive/no-decryption/bounded-state invariants.
5. Never claim a class, model, dashboard, metric, screenshot, or benchmark without actual current evidence.
