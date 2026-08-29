# SIH26145 Progress and Conversation Handoff

Last updated: **2026-08-29 (UTC)**

## Current Handoff State

- **Date:** 2026-08-29 (UTC)
- **Current branch:** `feature/milestone-3-dns-dga`
- **Milestone 2 merge commit:** `2e8706c404c088ee6e2312a740ff4df38dc63cbe`
- **Milestone 2 final feature commit:** `7cb1eb513295a844ef8959616631f9f1e8fed531`
- **Current milestone:** Milestone 3 — DNS/DGA ML (**VERIFIED after complete code review; PR #3 is open and unmerged**).
- **Active milestone branch:** `feature/milestone-3-dns-dga`
- **Active milestone worktree:** `/home/agntdrgn/WorkSpace/SIH26145/.worktrees/milestone-3-dns-dga`
- **Milestone 3 base commit:** `95159b6da04f0ee7ae6b61b3befd941842aac9bc`
- **Milestone 3 review-fix commit:** `9965de5b85d9d3add72ff417f16ad1f9a7875c19`
- **Milestone 3 pull request:** `https://github.com/AgentPhoenix7/SIH26145/pull/3`

### Verified Working

- Milestone 1 is **VERIFIED + MERGED + FROZEN** on `main`; merge commit `459924c3b699a011c06192f526786acd7a5318ea`.
- Passive deterministic PCAP replay, native Zeek streaming, bounded port-scan state, and validated evidence-bearing `PORT_SCAN` alerts retain the detailed evidence below.
- Fresh merged-`main` verification at `2e8706c` passed on 2026-08-28: locked `uv sync` succeeded; `240 passed in 15.22s`; Ruff lint passed; Ruff confirmed 41 files formatted; strict mypy found no issues in 30 source files; both deterministic fixture checks passed.
- The fresh Milestone 2 worktree baseline at `288af2c` passed on 2026-08-28: `189 passed`; Ruff lint passed; Ruff confirmed 33 files formatted; strict mypy found no issues in 22 source files.
- Milestone 2 is **MERGED + VERIFIED + FROZEN** by PR #2 at merge commit `2e8706c`; the merged final feature commit is `7cb1eb5`. Native exact-threshold replay emitted one typed `SYN_FLOOD` alert before EOS; below-threshold and distributed-benign outputs were zero bytes.
- PR review identified avoidable high-cardinality work: every SYN recomputed entropy across all sources and sorted them before alert eligibility. The merged test-first correction maintains `sum(count * log2(count))` during source-count changes and sorts samples only while building an eligible alert.
- Fresh merged-`main` native replay produced one 794-byte schema-valid `SYN_FLOOD` alert with 100 deduplicated SYN events, 20 unique sources, entropy `4.32192809488736`, fixed-window rate `10.0`, observed span `4.95`, and confidence `0.75`. The below-threshold and distributed-benign replays each produced exactly zero output bytes; the suite includes native alert-before-EOS tests.
- Fresh Milestone 3 worktree baseline at `95159b6` passed on 2026-08-29: frozen `uv sync` succeeded; `240 passed in 16.24s`; Ruff lint passed; Ruff confirmed 41 files formatted; strict mypy found no issues in 30 source files; both deterministic fixture checks passed.
- Milestone 3 now has a strict passive `dns_event_v1`, combined SYN/DNS Zeek stream, shared 140-value `dns_features_v1`, provenance-backed grouped training, a packaged 5,825-byte Logistic Regression artifact, local offline inference, typed `DGA` alerts, and deterministic native benign/DGA replay.
- Native synthetic replay processed one DNS event and emitted one 987-byte schema-valid `DGA` alert with probability `0.9999563398163442` before EOS. Native `example.com` replay processed one event and emitted exactly zero output bytes.
- Post-review Milestone 3 gate passed on 2026-08-29: frozen sync succeeded; `320 passed in 18.13s`; Ruff lint passed; Ruff confirmed 62 files formatted; strict mypy found no issues in 47 source files; all three fixture checks, actual benign/DGA replay, strict alert and artifact validation, exact scikit-learn wheel dependency inspection, wheel-resource inspection, and `git diff --check` passed.

### Implemented but Not Verified

- None for Milestone 3. End-to-end benchmark, API/dashboard, screenshots, and later threat coverage remain separate unfinished scope.

### In Progress

- PR #3 is open against `main` with the complete reviewed branch. Await PR feedback or explicit merge direction; merge remains unauthorized.

### Known Problems

- UDP reflection/amplification, DNS tunnelling, API, dashboard, and end-to-end benchmarking are not implemented.
- Demonstrated detector coverage spans three of six named classes, but DDoS is limited to SYN floods and DNS coverage to DGA lexical classification; no full-coverage claim is valid.

### Deferred

- Tier 2: data exfiltration until the Tier-1 feature-freeze gate is safe.
- Tier 3: C2 beaconing, TLS/QUIC malware metadata, advanced DNS tunnelling, flow-export ingest, advanced UI/ML, and production infrastructure.

### Important Decisions

- Deadline: 2026-08-31; feature freeze: 2026-08-30.
- Tier 1 is verified port scan + streaming DDoS + genuine DNS/DGA ML and local inference + standard alerts + minimal API/dashboard + end-to-end proof + benchmark + synchronized docs/PPT.
- `AGENTS.pre-mvp.md` preserves the pre-deadline-policy repository instructions; `AGENTS.md` now owns the deadline-first execution policy.
- Milestone 1 may be touched only for a later integration regression or compliance defect.
- Milestone 2 reuses `tcp_syn_attempt_v1` and the current Zeek policy unchanged; a synchronous in-process pipeline feeds the frozen port-scan and target-keyed SYN-flood detectors.
- Every milestone requires a fresh `feature/milestone-<number>-<slug>` branch and `.worktrees/milestone-<number>-<slug>` linked worktree. Never implement a milestone on `main` or reuse an older milestone worktree.

### Dataset / ML State

- No downloadable official SIH26145 dataset was found as of the recorded 2026-08-26 research.
- The ignored prepared dataset contains 20,000 Majestic benign-proxy domains and 7,723 examples from eight pinned DGA families. DGA test families are `kraken_v1` and `simda`; family overlap and domain overlap are zero.
- Held-out precision is `0.7187797902764538`, recall `0.25133333333333335`, F1 `0.37243763892319093`, and false-positive rate `0.07223310479921645`. These controlled-source results are not production claims.

### Model Artifacts

- Packaged artifact: `src/sih26145/artifacts/dga_logreg_v1.joblib`, 5,825 bytes, SHA-256 `0627eea04dec557ccf4e6ab2382b6d1e432380bcfa140908dd0da68798e03f47`.
- The strict metadata sidecar records features, preprocessing, labels, threshold, sources, split, evaluation, environment, and measured batch inference. Runtime loads and validates both locally before Zeek starts; no remote storage or Internet inference is required.

### Benchmark State

- End-to-end throughput, CPU, memory, and wall-clock alert-latency percentiles are unmeasured. Model-only batch inference measured `2.340909655567489` microseconds/domain (`427184.36297686916` domains/second) and must not be presented as pipeline throughput.

### SIH Compliance State

- The current verified path is passive, read-only, incremental, bounded-state, no-decryption, and evidence-producing. See the detailed compliance snapshot below.
- Demonstrated detector coverage spans 3/6 named classes: reconnaissance/port scanning, the SYN-flood subset of volumetric/protocol DDoS, and DGA lexical detection.

### Immediate Next Actions

1. Review PR #3 checks and feedback; make only required Milestone 3 corrections in this worktree.
2. Do not merge PR #3 without explicit user instruction.
3. After an explicitly authorized merge, create a fresh isolated milestone for the minimal local API, bounded alert storage, and dashboard; then finish the demo, benchmark, screenshots, and PPT evidence.

### Commands to Resume

```bash
git status --short --branch
git worktree list --porcelain
git log --oneline --decorate -10
git check-ignore -v .worktrees/
```

Progress status vocabulary is `PLANNED`, `IN PROGRESS`, `IMPLEMENTED`, `TESTED`, `VERIFIED`, `BLOCKED`, or `DEFERRED`. `IMPLEMENTED` means code exists; `TESTED` means the relevant tests actually ran; `VERIFIED` additionally requires observed expected behavior and passed acceptance criteria.

## Current Phase

**Milestones 1 and 2 are verified, merged, and frozen on `main`. Milestone 3 — DNS/DGA ML is verified after complete code review on its isolated feature branch; PR #3 is open against `main` and is not merged.**

The verified path is:

```text
deterministic PCAP replay
  -> native Zeek originator-SYN and DNS-request events
  -> versioned JSON Lines
  -> strict Python validation
  -> synchronous detector pipeline
     -> bounded capture-time source fan-out state
     -> bounded capture-time target SYN state
     -> shared lexical features + packaged local Logistic Regression
  -> evidence-bearing alert_v1 PORT_SCAN / SYN_FLOOD / DGA output
```

Demonstrated detector coverage spans three of six required classes: reconnaissance/port scanning, the SYN-flood subset of volumetric/protocol DDoS, and DGA lexical detection. UDP reflection/amplification, C2 beaconing, DNS tunnelling, encrypted-session malware metadata, data exfiltration, an API/dashboard, and end-to-end benchmarking remain absent.

## Authoritative Context and Git State

- Official problem statement: `docs/problem.md`
- Durable rules: `AGENTS.md`
- Architecture: `docs/architecture.md`
- Versioned feature semantics: `docs/features.md`
- Requirements traceability: `docs/requirements-traceability.md`
- Repository: `/home/agntdrgn/WorkSpace/SIH26145`
- Current branch: `feature/milestone-3-dns-dga`
- Current worktree: `/home/agntdrgn/WorkSpace/SIH26145/.worktrees/milestone-3-dns-dga`
- Main worktree: `/home/agntdrgn/WorkSpace/SIH26145`
- Milestone 3 base commit: `95159b6da04f0ee7ae6b61b3befd941842aac9bc`
- Milestone 3 review-fix commit: `9965de5b85d9d3add72ff417f16ad1f9a7875c19`
- Milestone 3 pull request: `https://github.com/AgentPhoenix7/SIH26145/pull/3`
- Milestone 2 merged pull request: `https://github.com/AgentPhoenix7/SIH26145/pull/2`
- Milestone 2 merge commit: `2e8706c404c088ee6e2312a740ff4df38dc63cbe`
- Milestone 2 final feature commit: `7cb1eb513295a844ef8959616631f9f1e8fed531`
- Milestone 2 base commit: `288af2cd61dbe34ec30587d96599c98de680ff54`
- Milestone 1 merge commit: `459924c3b699a011c06192f526786acd7a5318ea`
- Historical implementation worktree: `/home/agntdrgn/WorkSpace/SIH26145/.worktrees/milestone-1-port-scan`
- Historical implementation branch: `feature/milestone-1-port-scan`
- Branch point from `main`: `59afa18` (`docs: approve milestone one implementation plan`)
- Tasks 1-8 reviewed implementation base: `3ca426c` (`fix: preserve safe replay failures`)
- Required Task 9 formatter-only cleanup: `1be64d9` (`style: apply Ruff formatting`)
- Milestone 1 documentation baseline: `1eacfaa` (`docs: record milestone one verification`)
- Post-review lifecycle fix: `af96c9e` (`fix: enforce post-eos cleanup deadline`)
- Alert-span precision fix: `c8da88a` (`fix: normalize port scan alert spans`)
- Configuration/state consistency fix: `6727d65` (`fix: validate scan config against state limits`)
- Timestamp/cooldown precision fix: `01b3645` (`fix: align scan duration precision`)
- Cooldown-capacity atomicity fix: `37ca272` (`fix: rollback rejected scan observations`)
- This pre-EOS inactivity correction is recorded by the commit containing this file, whose predecessor is `37ca272`.

The implementation history is intentionally sliced: contracts (`dd01d7f`, `78284b7`), bounded window and detector (`43fd8f1`, `e572485`), fixtures (`13a2512`), Zeek streaming policy (`8900707`), replay runner and deadline hardening (`2a41b6b`, `6871624`, `2bb8b0b`, `af96c9e`, plus the commit containing this file), CLI/safe diagnostics (`c5371b2`, `3ca426c`), and review-driven scan consistency fixes (`c8da88a`, `6727d65`, `01b3645`, `37ca272`). Inspect live status and commits before continuing because this snapshot can become stale.

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
| SYN-flood threshold fixture | `tests/fixtures/milestone2/syn_flood_at_threshold.pcap` |
| SYN-flood fixture SHA-256 | `712bb6ea6da09fe4b7cb7af184f00110dc755d32a667e68e2e94cdb08b1be76d` |
| Actual SYN-flood replay accounting | 100 processed events, 1 emitted alert |
| SYN-flood CLI output | 1 JSONL record, 794 bytes |
| SYN-flood comparison outputs | 99-event and distributed-benign captures: exactly 0 bytes |
| SYN-flood incremental order | `alert,end_of_stream` |

The public native command is `zeek -D -b -r <pcap> <policy>`. `-D` makes identical controlled replays preserve the real Zeek UID and deterministic alert JSON. A Zeek UID is not durable across different captures, Zeek versions, or replay modes.

## Completed Implementation

- Strict `tcp_syn_attempt_v1`, `control_v1`, and typed `alert_v1` contracts reject untrusted fields and invalid values.
- A native Zeek policy emits and flushes one originator-SYN JSON record at a time followed by exactly one consistent EOS record.
- Python validates and processes each event before reading the next record; a threshold alert callback precedes EOS.
- The capture-time scan window deduplicates Zeek UIDs, tracks attempts/hosts/ports/endpoints, expires old state, and rejects timestamp regression before mutation.
- Hard limits cover line length, pre-EOS record inactivity, active sources, per-source and global attempts, retained UIDs, cooldown sources, stderr retention, and child process shutdown. A partial or absent next record fails after two seconds without stdout progress and then uses the pre-EOS two-second terminate-to-kill cleanup grace; after EOS, child exit, pipe completion, drainer shutdown, and direct-child cleanup share one absolute two-second deadline with no fresh cleanup budget.
- The detector uses configurable attempt/fan-out thresholds, exact-boundary expiry and cooldown semantics, deterministic endpoint samples, and typed measured evidence. Cooldown suppression and expiry compare elapsed time directly, preserving positive cooldowns even when adding them to a large epoch timestamp would round them away.
- A threshold event rejected by the cooldown-source capacity limit is rolled back from rolling attempts, fan-out counters, and UID deduplication state before the named failure propagates, so catching and retrying the event cannot silently lose its alert.
- Detector construction rejects windows that can overflow derived rates, thresholds above effective state capacity, and windows longer than the UID deduplication TTL; the CLI reports these as invalid configuration before Zeek starts.
- Detector construction normalizes the effective scan window to microsecond precision before membership, rate calculation, alert reporting, and duration validation. Alert span evidence is derived from the same microsecond-normalized UTC timestamps as `AlertWindow`, preventing ordinary large-epoch float or configuration precision differences from discarding a threshold alert during strict schema validation.
- The CLI emits canonical alert JSON only on stdout; child stderr is privately retained only as the byte-exact latest 64 KiB and is never echoed. CLI stderr contains only trusted safe diagnostics.
- CLI status is `0` for success, `2` for invalid configuration/path, and `1` for runtime/process/contract/timestamp/callback/state-limit failure.
- Deterministic offline PCAP generation uses documentation-only IPv4 ranges and records scenario parameters, expected outcomes, packet counts, SHA-256, and provenance in manifests.
- IPv4 native replay is e2e tested; IPv6 schemas, state, and sample ordering are unit tested.

Milestone 2 adds:

- A destination `(IP, port)` keyed capture-time window with UID deduplication, exact-boundary expiry, source counts, incrementally maintained Shannon source-IP entropy, alert-only deterministic source sampling, and independent hard limits for targets, per-target/global events, UIDs, and cooldown targets.
- A configurable `SYN_FLOOD` rule requiring both 100 deduplicated SYN events and 20 unique sources in the default 10-second window. Entropy is supporting source-distribution evidence, not proof of spoofing.
- Typed `SynFloodEvidence` inside the unchanged `alert_v1` envelope, while detector-specific alert subclasses preserve static port-scan evidence typing and serialization compatibility.
- A concrete synchronous `DetectionPipeline` that may produce zero, one, or two alerts for one validated event before the replay runner reads the next record.
- Public CLI options for the SYN-flood window, event threshold, source threshold, and target cooldown; invalid combinations fail before Zeek starts with a trusted diagnostic.
- Three deterministic offline RFC 5737 fixtures: exact threshold, 99-event below threshold, and 100 events distributed across 10 targets. Manifests record parameters, hashes, timestamps, endpoints, expected outcomes, and no-network provenance.

Milestone 3 adds:

- Strict request-only `dns_event_v1` records for UDP/TCP, with lowercase LDH-only names, bounded lines, validated endpoints/codes/timestamps, and one EOS count shared with SYN events.
- One shared `dns_features_v1` extractor: 12 explainable lexical summaries plus 128 normalized hashed character n-gram buckets, used unchanged by training and runtime.
- Offline bounded preparation from the Majestic Million and eight pinned GPL-2.0 DGA example families, with source hashes, caps, duplicate rejection, and ignored corpora.
- Family-disjoint DGA and stable hash-based benign splitting with zero domain overlap; one CPU `StandardScaler` + class-balanced Logistic Regression candidate at fixed threshold `0.5`.
- A strict packaged model loader that validates artifact/feature/model versions, labels, threshold, ordered features, bytes, SHA-256, and sklearn pipeline shape before local inference.
- Stateless DNS routing and typed `DGA` `alert_v1` evidence containing actual probability, query, query type, threshold, model/feature identities, and recomputed lexical summaries.
- Two deterministic offline DNS PCAPs and manifests. Synthetic DGA replay alerts before EOS; controlled benign replay emits no alert.

## Milestone 3 Acceptance

- [x] Dataset source, licence, format, restrictions, hashes, revision, selected files, and limitations are recorded.
- [x] Strict passive DNS request validation and combined native stream behavior have focused tests.
- [x] Training and runtime share one versioned 140-value lexical feature implementation.
- [x] Preparation is bounded; DGA families are held out whole; train/test domains do not overlap.
- [x] The actual Logistic Regression model, metadata, labels, preprocessing, feature order, evaluation, and artifact hash are persisted.
- [x] Runtime inference is local/offline, validates the packaged artifact before Zeek, and performs bounded stateless work per DNS record.
- [x] DGA alerts use strict typed evidence and deterministic probability-based severity.
- [x] Native DGA replay emits one strict alert before EOS and native benign DNS replay emits zero bytes.
- [x] Final full locked test/lint/type/fixture/replay/documentation and wheel-resource gate passed.

## Milestone 3 Code Review

Complete local review, supplemented by independent read-only reviewer findings, found and corrected seven material issues before PR: training now binds the prepared CSV to its provenance manifest and records train/test class and family counts; DGA source files stream through a 4,096-byte record bound instead of whole-file loading; training rejects noncanonical domain identities before splitting; the packaged joblib requires and validates its exact scikit-learn `1.9.0` runtime; stateless DGA alerts use a truthful zero-duration window; mixed SYN/DNS timestamp regression is rejected at the stream boundary; and dataset documentation no longer claims an unrecorded retrieval timestamp. Each production correction has a focused regression.

## Milestone 2 Acceptance

- [x] Reuses the frozen `tcp_syn_attempt_v1` and Zeek policy unchanged.
- [x] One validated event feeds both detectors synchronously and all resulting alerts are emitted before the next stream record.
- [x] Target-keyed state measures deduplicated events, fixed-window rate, unique sources, source entropy, observed span, target, thresholds, and deterministic source samples.
- [x] Entropy maintenance performs constant work per source-count change, and full source sorting occurs only for an eligible alert.
- [x] State expiry, UID deduplication, timestamp rejection, every target/event/UID bound, cooldown, and retry-safe cooldown-capacity rollback have focused tests.
- [x] SYN-flood configuration is validated against finite rates, UID TTL, and effective state capacity before replay.
- [x] Exact-threshold native replay emits one strict `SYN_FLOOD` alert before EOS.
- [x] The 99-event and distributed-benign native replays emit zero alert bytes.
- [x] Existing port-scan serialization, CLI behavior, native fixtures, and regression tests remain green.
- [x] Full tests, Ruff lint, Ruff formatting, strict mypy, both fixture checks, actual CLI JSON validation, and affected documentation are current.

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

Fresh post-review Milestone 3 verification was run from the dedicated worktree on 2026-08-29:

```bash
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv sync --frozen --group dev
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv run pytest
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv run ruff check .
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv run ruff format --check .
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv run mypy src tests tools
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1 --check
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv run python tools/generate_milestone2_fixtures.py --output tests/fixtures/milestone2 --check
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv run python tools/generate_milestone3_fixtures.py --output tests/fixtures/milestone3 --check
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv run sih26145-replay tests/fixtures/milestone3/dga_dns.pcap > /tmp/sih26145-m3-final-dga.jsonl
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv run sih26145-replay tests/fixtures/milestone3/benign_dns.pcap > /tmp/sih26145-m3-final-benign.jsonl
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv build
git diff --check
```

Observed results: `320 passed in 18.13s`; Ruff lint passed; Ruff confirmed 62 files formatted; strict mypy found no issues in 47 source files; all three fixture checks exited `0`. The actual DGA output was one line and 987 bytes, validated as strict `alert_v1` with probability `0.9999563398163442` and zero configured window seconds; benign output was zero bytes. Artifact size/hash validation passed at 5,825 bytes and SHA-256 `0627eea04dec557ccf4e6ab2382b6d1e432380bcfa140908dd0da68798e03f47`; metadata records 15,916 benign plus 4,723 DGA training rows and 4,084 benign plus 3,000 DGA test rows. The built wheel contains the joblib artifact, metadata sidecar, combined Zeek policy, and `py.typed`, and declares exact `scikit-learn==1.9.0`. `git diff --check` passed.

Fresh Milestone 3 isolation and baseline verification was run from the dedicated worktree on 2026-08-29:

```bash
git worktree add .worktrees/milestone-3-dns-dga -b feature/milestone-3-dns-dga main
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv sync --frozen --group dev
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv run pytest
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv run ruff check .
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv run ruff format --check .
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv run mypy src tests tools
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1 --check
UV_CACHE_DIR=/tmp/sih26145-m3-uv-cache uv run python tools/generate_milestone2_fixtures.py --output tests/fixtures/milestone2 --check
```

The branch and linked worktree were created from `95159b6`. The first sandboxed sync attempt failed only because external DNS was restricted; the identical frozen sync succeeded with dependency-download access. Verification then reported `240 passed in 16.24s`, `All checks passed!`, `41 files already formatted`, `Success: no issues found in 30 source files`, and zero-exit fixture checks. No Milestone 3 implementation or dataset import occurred.

Fresh Milestone 2 verification was run from the dedicated worktree on 2026-08-28:

```bash
UV_CACHE_DIR=/tmp/sih26145-m2-uv-cache uv run pytest
UV_CACHE_DIR=/tmp/sih26145-m2-uv-cache uv run ruff check .
UV_CACHE_DIR=/tmp/sih26145-m2-uv-cache uv run ruff format --check .
UV_CACHE_DIR=/tmp/sih26145-m2-uv-cache uv run mypy src tests tools
UV_CACHE_DIR=/tmp/sih26145-m2-uv-cache uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1 --check
UV_CACHE_DIR=/tmp/sih26145-m2-uv-cache uv run python tools/generate_milestone2_fixtures.py --output tests/fixtures/milestone2 --check
UV_CACHE_DIR=/tmp/sih26145-m2-uv-cache uv run sih26145-replay tests/fixtures/milestone2/syn_flood_at_threshold.pcap > /tmp/sih26145-m2-flood-alerts.jsonl
UV_CACHE_DIR=/tmp/sih26145-m2-uv-cache uv run sih26145-replay tests/fixtures/milestone2/syn_flood_below.pcap > /tmp/sih26145-m2-below-alerts.jsonl
UV_CACHE_DIR=/tmp/sih26145-m2-uv-cache uv run sih26145-replay tests/fixtures/milestone2/benign_distributed.pcap > /tmp/sih26145-m2-benign-alerts.jsonl
```

Observed results after the PR performance correction: `240 passed in 15.10s`; `All checks passed!`; `41 files already formatted`; `Success: no issues found in 30 source files`; both fixture checks exited `0`. The actual threshold output was one line and 794 bytes; both comparison outputs were zero bytes. The alert validated as `alert_v1` with class `SYN_FLOOD`, 100 deduplicated events, 20 unique sources, entropy `4.32192809488736`, fixed-window rate `10.0`, span `4.95`, target `198.51.100.20:443`, and confidence `0.75`. Native e2e observation recorded `alert,end_of_stream`.

The two focused PR regressions were observed failing before the correction: 100 unique-source observations made 5,050 `log2` calls against a constant-work limit of 400, and the first below-threshold event attempted to sort the active source set. Both passed after incremental entropy maintenance and alert-only sample sorting. The full gate and actual replay evidence above then passed without changing the fixture bytes, alert class, counts, thresholds, target, confidence, or comparison outcomes.

The new contract, detector, pipeline, runner batching, direct-script generator, and CLI behaviors were each observed failing for the expected missing or incorrect behavior before their minimal implementation/fix and then passing focused tests. The pre-implementation worktree baseline remains recorded above as 189 tests.

The following cheap sanity check was run from clean `main` on 2026-08-28 after the deadline-policy migration. The first sandboxed `uv sync` attempt failed only because DNS/network access was restricted; rerunning the same locked sync with dependency-download access succeeded, after which every check passed:

```bash
UV_CACHE_DIR=/tmp/sih26145-mvp-uv-cache uv sync --frozen --group dev
UV_CACHE_DIR=/tmp/sih26145-mvp-uv-cache uv run pytest
UV_CACHE_DIR=/tmp/sih26145-mvp-uv-cache uv run ruff check .
UV_CACHE_DIR=/tmp/sih26145-mvp-uv-cache uv run ruff format --check .
UV_CACHE_DIR=/tmp/sih26145-mvp-uv-cache uv run mypy src tests tools
```

Observed results: `189 passed in 15.13s`; `All checks passed!`; `33 files already formatted`; `Success: no issues found in 22 source files`. This accepts the merged Milestone 1 implementation as the current frozen baseline without repeating its historical manual verification campaign.

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

Additional P2 pre-EOS inactivity evidence on 2026-08-28:

```bash
UV_CACHE_DIR=/tmp/sih26145-p2d-uv-cache uv sync --frozen --group dev
UV_CACHE_DIR=/tmp/sih26145-p2d-uv-cache uv run pytest
UV_CACHE_DIR=/tmp/sih26145-p2d-uv-cache uv run ruff check .
UV_CACHE_DIR=/tmp/sih26145-p2d-uv-cache uv run ruff format --check .
UV_CACHE_DIR=/tmp/sih26145-p2d-uv-cache uv run mypy src tests tools
UV_CACHE_DIR=/tmp/sih26145-p2d-uv-cache uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1 --check
UV_CACHE_DIR=/tmp/sih26145-p2d-uv-cache uv run sih26145-replay tests/fixtures/milestone1/vertical_at_threshold.pcap > /tmp/sih26145-p2d-scan-alerts.jsonl
UV_CACHE_DIR=/tmp/sih26145-p2d-uv-cache uv run sih26145-replay tests/fixtures/milestone1/benign.pcap > /tmp/sih26145-p2d-benign-alerts.jsonl
```

The real-child partial-line regression was observed remaining blocked before the fix and completing with `pre_end_of_stream_timeout` afterward. The test verifies that the direct child is terminated and reaped and that no stderr-drainer thread remains. The full suite reported `189 passed`; Ruff lint and format, strict mypy, deterministic fixture checks, native threshold replay, and native benign replay passed. Actual scan output contained one schema-valid alert with a `4.75`-second observed span, while benign output was zero bytes. Detector/end-to-end wall-time percentiles remain unmeasured.

## Current SIH26145 Compliance Snapshot

```text
Read-only ingest:             VERIFIED for deterministic PCAP replay
Active probing/return path:   ABSENT and verified for the current path
Payload decryption:           ABSENT and verified for SYN and DNS/DGA paths
Streaming processing:         VERIFIED; all three class callbacks precede EOS
Bounded alert latency:        Incremental path implemented; wall-time percentiles NOT MEASURED
Alert schema/evidence:        VERIFIED with actual strict PORT_SCAN, SYN_FLOOD, and DGA records
Dataset research/provenance:  Source licences/hashes/revision and fixture provenance VERIFIED
ML model trained:             VERIFIED for dga_logreg_v1 with grouped held-out evaluation
Model storage/resume:         Packaged joblib + strict metadata VERIFIED; remote resume NOT APPLICABLE
Offline model inference:      VERIFIED for packaged local DGA model with socket disabled
Threat coverage:              3 / 6 demonstrated; DDoS limited to SYN flood, DNS limited to DGA
Throughput measured:          NO
Demo reproducible:            VERIFIED for native scan, SYN-flood, DGA, and comparison replay
PPT evidence:                 Verified facts recorded; screenshots and performance plots NOT CAPTURED
```

## Limitations and Risks

- Implemented paths cover scan fan-out, destination-centric SYN floods, and DGA lexical classification. UDP reflection/amplification, DNS tunnelling, and three official classes are unimplemented.
- DGA held-out recall is `0.2513` and false-positive rate is `0.0722` on controlled sources; it is not a production verdict or blocking signal.
- Both detectors' thresholds and `0.75` threshold confidence are heuristic, not production calibrated or probability estimates.
- The benign and below-threshold fixtures prove only deterministic expected results; no production false-positive rate has been measured.
- Source-IP entropy describes distribution characteristics and is not proof that sources are spoofed.
- Strict zero-lateness ordering rejects timestamp regressions instead of reordering merged/live traffic.
- A Zeek UID supports retransmission deduplication inside a replay but is not durable across different captures, versions, or modes.
- State pressure stops the prototype with a named invariant. A future live path needs measured degradation/telemetry without weakening bounds.
- Native e2e fixtures are IPv4; IPv6 has unit coverage only.
- Child stderr is intentionally not public. Trusted diagnostics preserve the failed invariant, but additional private troubleshooting tooling may be needed later.
- No wall-clock alert latency, throughput, CPU, or memory result exists.
- No official downloadable SIH26145 dataset was found as of 2026-08-26; the selected Majestic and DGA sources have recorded licences/provenance, and every future corpus still requires review.
- No API/dashboard, screenshot set, or final presentation exists yet.

## Milestone 2 Approved Plan Outcome: Streaming SYN-DDoS (`VERIFIED`)

The approved plan remained deliberately limited to SYN flood. All ten items are implemented and verified on the dedicated feature branch:

1. Reuse `tcp_syn_attempt_v1` unchanged. It already supplies capture time, UID, source, destination endpoint, and TCP transport; the Zeek policy remains passive and unchanged.
2. Add capture-time state keyed by destination `(IP, port)`, with UID deduplication, expiry, exact-boundary behavior, hard limits for targets/events/UIDs/cooldowns, and named deterministic failures.
3. Measure per target: deduplicated SYN count, fixed-window SYN rate, unique sources, Shannon source-IP entropy, observed span, and deterministic source samples. Entropy is evidence of source-distribution characteristics, not proof of spoofing.
4. Trigger `SYN_FLOOD` when both configurable minimum SYN events and minimum unique sources are reached for one target in the window. Use a deterministic heuristic confidence based on threshold strength; do not call it a calibrated probability.
5. Extend `alert_v1` with typed SYN-flood evidence while preserving existing port-scan serialization and validation. Use the triggering Zeek UID as `flow_id`, the triggering source as the observed source, and the target endpoint inside measured evidence.
6. Add a small synchronous detector pipeline because one event must feed both the frozen port-scan detector and the new SYN-flood detector and may produce zero, one, or two alerts before the next stream record.
7. Generate offline RFC 5737 PCAP fixtures and manifests for benign distributed traffic, below-threshold traffic, and an exact-threshold multi-source SYN flood; no packet is transmitted.
8. Test configuration, strict alert evidence, entropy, expiry, deduplication, bounds, rollback/cooldown, exact thresholds, pipeline multi-alert behavior, native Zeek replay, benign no-alert behavior, and alert-before-EOS ordering.
9. Run the focused and full suites, replay real benign and flood fixtures, validate actual alert JSON, then update only affected README, architecture, feature, traceability, PPT, and progress documentation.
10. Freeze Milestone 2 immediately after acceptance; UDP reflection/amplification remains deferred unless later schedule review proves it cheap and Tier 1 stays safe.

Milestone 2 is merged and frozen. The user approved Milestone 3, and its minimum DNS/DGA path is implemented in the dedicated branch/worktree. After its final gate and review, the next deadline priority is the minimal API/dashboard, reproducible demo, measured benchmark, and submission evidence.

## Handoff Checklist

1. Confirm the repository/worktree and inspect `git status`, diffs, and recent commits.
2. Read `AGENTS.md`, `docs/problem.md`, this file, and relevant source/tests completely.
3. Confirm the active Milestone 3 branch/worktree and base commit recorded above, and keep Milestone 2 frozen.
4. Treat this as a verified snapshot, not a substitute for fresh commands.
5. Do not broaden Milestone 3 beyond the approved minimum DGA path or begin another milestone in this worktree.
6. Never claim a class, model, dashboard, metric, screenshot, or benchmark without actual current evidence.
