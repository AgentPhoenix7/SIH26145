# SIH26145 Progress and Conversation Handoff

Last updated: **2026-08-28 (UTC)**

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
- Milestone 1 documentation baseline: `1eacfaa` (`docs: record milestone one verification`)
- Post-review lifecycle fix: `af96c9e` (`fix: enforce post-eos cleanup deadline`)
- Alert-span precision fix: `c8da88a` (`fix: normalize port scan alert spans`)
- Configuration/state consistency fix: `6727d65` (`fix: validate scan config against state limits`)
- Timestamp/cooldown precision fix: `01b3645` (`fix: align scan duration precision`)
- This cooldown-capacity atomicity correction is recorded by the commit containing this file, whose predecessor is `01b3645`.

The implementation history is intentionally sliced: contracts (`dd01d7f`, `78284b7`), bounded window and detector (`43fd8f1`, `e572485`), fixtures (`13a2512`), Zeek streaming policy (`8900707`), replay runner and deadline hardening (`2a41b6b`, `6871624`, `2bb8b0b`, `af96c9e`), CLI/safe diagnostics (`c5371b2`, `3ca426c`), and review-driven scan consistency fixes (`c8da88a`, `6727d65`, `01b3645`, plus the commit containing this file). Inspect live status and commits before continuing because this snapshot can become stale.

## Verified Environment and Artifacts

Fresh 2026-08-28 commands reported:

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
- Hard limits cover line length, active sources, per-source and global attempts, retained UIDs, cooldown sources, stderr retention, and child process shutdown. Pre-EOS failure cleanup has a two-second terminate-to-kill grace; after EOS, child exit, pipe completion, drainer shutdown, and direct-child cleanup share one absolute two-second deadline with no fresh cleanup budget.
- The detector uses configurable attempt/fan-out thresholds, exact-boundary expiry and cooldown semantics, deterministic endpoint samples, and typed measured evidence. Cooldown suppression and expiry compare elapsed time directly, preserving positive cooldowns even when adding them to a large epoch timestamp would round them away.
- A threshold event rejected by the cooldown-source capacity limit is rolled back from rolling attempts, fan-out counters, and UID deduplication state before the named failure propagates, so catching and retrying the event cannot silently lose its alert.
- Detector construction rejects windows that can overflow derived rates, thresholds above effective state capacity, and windows longer than the UID deduplication TTL; the CLI reports these as invalid configuration before Zeek starts.
- Detector construction normalizes the effective scan window to microsecond precision before membership, rate calculation, alert reporting, and duration validation. Alert span evidence is derived from the same microsecond-normalized UTC timestamps as `AlertWindow`, preventing ordinary large-epoch float or configuration precision differences from discarding a threshold alert during strict schema validation.
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

The managed sandbox required only a cache-location override; it does not change project behavior. The following exact commands were run from the worktree after the post-review lifecycle fix:

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

- `155 passed, 19 deselected` for non-e2e tests.
- `19 passed, 155 deselected` for native e2e tests.
- Ruff lint passed; Ruff format check confirmed 32 files already formatted; strict mypy found no issues in 22 source files.
- Fixture `--check` exited `0` without changing committed fixtures.
- Actual scan output contained one schema-valid alert; benign output was zero bytes.
- A direct replay observation recorded `events_processed=20 alerts_emitted=1 callback_alerts=1 order=alert,end_of_stream`.

Portable commands in `README.md` omit the sandbox-specific `UV_CACHE_DIR` prefix.

After the post-review fix and five-document evidence refresh, these documentation-sensitive checks also exited `0`:

```bash
UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv run ruff check .
UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv run ruff format --check .
UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv run mypy src tests tools
UV_CACHE_DIR=/tmp/sih26145-task9-uv-cache uv run pytest -v
git diff --check
git status --short
```

They reported all Ruff checks passed, 32 files already formatted, no mypy issues in 22 source files, and `174 passed`; `git diff --check` was clean and status listed only `PROGRESS.md`, `docs/architecture.md`, `docs/features.md`, `docs/requirements-traceability.md`, and `docs/ppt-notes.md`.

PR review correction evidence on 2026-08-28:

```bash
UV_CACHE_DIR=/tmp/sih26145-review-uv-cache uv run pytest tests/unit/test_port_scan_detector.py::test_alert_span_uses_normalized_capture_timestamps -v
UV_CACHE_DIR=/tmp/sih26145-review-uv-cache uv run pytest
UV_CACHE_DIR=/tmp/sih26145-review-uv-cache uv run ruff check .
UV_CACHE_DIR=/tmp/sih26145-review-uv-cache uv run ruff format --check .
UV_CACHE_DIR=/tmp/sih26145-review-uv-cache uv run mypy src tests tools
UV_CACHE_DIR=/tmp/sih26145-review-uv-cache uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1 --check
UV_CACHE_DIR=/tmp/sih26145-review-uv-cache uv run sih26145-replay tests/fixtures/milestone1/vertical_at_threshold.pcap > /tmp/sih26145-review-scan-alerts.jsonl
UV_CACHE_DIR=/tmp/sih26145-review-uv-cache uv run sih26145-replay tests/fixtures/milestone1/benign.pcap > /tmp/sih26145-review-benign-alerts.jsonl
UV_CACHE_DIR=/tmp/sih26145-review-uv-cache uv run python -c 'from pathlib import Path; from sih26145.contracts.alerts import AlertV1; lines=Path("/tmp/sih26145-review-scan-alerts.jsonl").read_text().splitlines(); assert len(lines)==1; alert=AlertV1.model_validate_json(lines[0]); assert alert.evidence.observed_span_seconds==4.75; assert Path("/tmp/sih26145-review-benign-alerts.jsonl").read_bytes()==b""'
```

The focused large-epoch, one-microsecond regression test was observed failing before the fix and passing after it. The full suite then reported `175 passed`; Ruff lint, Ruff format, strict mypy, and deterministic fixture checks passed; native replay emitted one schema-valid scan alert with a `4.75`-second span while benign replay emitted zero bytes.

Additional P2 configuration-review evidence on 2026-08-28:

```bash
UV_CACHE_DIR=/tmp/sih26145-p2-uv-cache uv run pytest
UV_CACHE_DIR=/tmp/sih26145-p2-uv-cache uv run ruff check .
UV_CACHE_DIR=/tmp/sih26145-p2-uv-cache uv run ruff format --check .
UV_CACHE_DIR=/tmp/sih26145-p2-uv-cache uv run mypy src tests tools
UV_CACHE_DIR=/tmp/sih26145-p2-uv-cache uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1 --check
UV_CACHE_DIR=/tmp/sih26145-p2-uv-cache uv run sih26145-replay tests/fixtures/milestone1/benign.pcap --window-seconds 1e-309
UV_CACHE_DIR=/tmp/sih26145-p2-uv-cache uv run sih26145-replay tests/fixtures/milestone1/benign.pcap --min-attempts 4097
UV_CACHE_DIR=/tmp/sih26145-p2-uv-cache uv run sih26145-replay tests/fixtures/milestone1/benign.pcap --window-seconds 61
UV_CACHE_DIR=/tmp/sih26145-p2-uv-cache uv run sih26145-replay tests/fixtures/milestone1/vertical_at_threshold.pcap > /tmp/sih26145-p2-scan-alerts.jsonl
UV_CACHE_DIR=/tmp/sih26145-p2-uv-cache uv run sih26145-replay tests/fixtures/milestone1/benign.pcap > /tmp/sih26145-p2-benign-alerts.jsonl
```

The rate-overflow, unreachable-threshold, and short-UID-retention cases were each observed failing before their constructor checks were added. The full suite reported `185 passed`; all three invalid CLI examples exited `2` with the fixed configuration diagnostic before replay; Ruff, strict mypy, fixture checks, native threshold replay, and native benign replay passed.

Additional P2 timestamp-precision evidence on 2026-08-28:

```bash
UV_CACHE_DIR=/tmp/sih26145-p2b-uv-cache uv sync --frozen --group dev
UV_CACHE_DIR=/tmp/sih26145-p2b-uv-cache uv run pytest
UV_CACHE_DIR=/tmp/sih26145-p2b-uv-cache uv run ruff check .
UV_CACHE_DIR=/tmp/sih26145-p2b-uv-cache uv run ruff format --check .
UV_CACHE_DIR=/tmp/sih26145-p2b-uv-cache uv run mypy src tests tools
UV_CACHE_DIR=/tmp/sih26145-p2b-uv-cache uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1 --check
UV_CACHE_DIR=/tmp/sih26145-p2b-uv-cache uv run sih26145-replay tests/fixtures/milestone1/vertical_at_threshold.pcap > /tmp/sih26145-p2b-scan-alerts.jsonl
UV_CACHE_DIR=/tmp/sih26145-p2b-uv-cache uv run sih26145-replay tests/fixtures/milestone1/benign.pcap > /tmp/sih26145-p2b-benign-alerts.jsonl
UV_CACHE_DIR=/tmp/sih26145-p2b-uv-cache uv run python -c 'from pathlib import Path; from sih26145.contracts.alerts import AlertV1; lines=Path("/tmp/sih26145-p2b-scan-alerts.jsonl").read_text().splitlines(); assert len(lines)==1; alert=AlertV1.model_validate_json(lines[0]); assert alert.evidence.observed_span_seconds==4.75; assert Path("/tmp/sih26145-p2b-benign-alerts.jsonl").read_bytes()==b""'
```

Both new focused regressions were observed failing before their fixes and passing after them: a `0.09999995`-second window now becomes one effective `0.1`-second window for state, rate, and alert validation, and a positive `1e-8`-second cooldown suppresses a same-timestamp event near epoch `1700000000.0`. The full suite reported `187 passed`; Ruff lint and format, strict mypy, deterministic fixture checks, native threshold replay, and native benign replay passed. The actual scan output contained one schema-valid alert with a `4.75`-second observed span, while benign output was zero bytes.

Additional P2 cooldown-capacity atomicity evidence on 2026-08-28:

```bash
UV_CACHE_DIR=/tmp/sih26145-p2c-uv-cache uv sync --frozen --group dev
UV_CACHE_DIR=/tmp/sih26145-p2c-uv-cache uv run pytest
UV_CACHE_DIR=/tmp/sih26145-p2c-uv-cache uv run ruff check .
UV_CACHE_DIR=/tmp/sih26145-p2c-uv-cache uv run ruff format --check .
UV_CACHE_DIR=/tmp/sih26145-p2c-uv-cache uv run mypy src tests tools
UV_CACHE_DIR=/tmp/sih26145-p2c-uv-cache uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1 --check
UV_CACHE_DIR=/tmp/sih26145-p2c-uv-cache uv run sih26145-replay tests/fixtures/milestone1/vertical_at_threshold.pcap > /tmp/sih26145-p2c-scan-alerts.jsonl
UV_CACHE_DIR=/tmp/sih26145-p2c-uv-cache uv run sih26145-replay tests/fixtures/milestone1/benign.pcap > /tmp/sih26145-p2c-benign-alerts.jsonl
```

The retry regression was observed failing before the rollback and passing afterward: with a 10-second scan window, 30-second cooldown, and one cooldown-source slot, a new threshold event at `111.0` is rejected while the prior source's attempt has expired but its cooldown remains. Retrying that identical event now raises the same named `max_cooldown_sources` limit instead of returning `None` as a retained-UID duplicate. The full suite reported `188 passed`; Ruff lint and format, strict mypy, deterministic fixture checks, native threshold replay, and native benign replay passed. Actual scan output contained one schema-valid alert with a `4.75`-second observed span, while benign output was zero bytes.

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
