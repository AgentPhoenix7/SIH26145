# SIH26145 Progress and Conversation Handoff

Last updated: **2026-08-30 (UTC)**, Milestone 5 implementation slice

## Current Handoff State

- **Date:** 2026-08-30 (UTC)
- **Current branch:** `feature/milestone-5-benchmark`
- **Milestone 5 base commit:** `d8f3fdb` (`docs: record milestone four merge in progress handoff`, on `main`)
- **Milestone 5 worktree:** `/home/agntdrgn/WorkSpace/SIH26145/.worktrees/milestone-5-benchmark`
- **Milestone 5 baseline verification (2026-08-30):** frozen `uv sync --frozen --group dev` succeeded; `347 passed in 20.09s`; Ruff lint passed; Ruff confirmed 69 files formatted; strict mypy found no issues in 53 source files; all three deterministic fixture checks exited `0`.
- **Milestone 4 base commit:** `7498634bf2e91a9540197166d876c3e381adee40`
- **Milestone 4 baseline evidence commit:** `67a78d74d63513affd8a2ac164bbd4d1c505a09a`
- **Milestone 4 feature commit:** `571c4b1fa13529e659640259aab1475cd05182b3`
- **Milestone 4 review-fix commit:** `47a1eda8327176480ada6ba6268bc372c3c03e20`
- **Milestone 4 merged pull request:** `https://github.com/AgentPhoenix7/SIH26145/pull/4`, merge commit `44c51d88da7d9d1abb574da3775e06832cf5846a`, merged 2026-08-30T12:31:46Z
- **Milestone 2 merge commit:** `2e8706c404c088ee6e2312a740ff4df38dc63cbe`
- **Milestone 2 final feature commit:** `7cb1eb513295a844ef8959616631f9f1e8fed531`
- **Milestone 3 merge commit:** `9fc30e612f4ea5accbd412610b692899b93d4ffc`
- **Milestone 3 final feature fix:** `d61bec43f6559e6191cb0d64309317844dbcc9a2`
- **Current milestone:** Milestone 5 — measured end-to-end benchmark (throughput, alert latency, CPU, memory) (**IMPLEMENTED + TESTED**; PR #5 (`https://github.com/AgentPhoenix7/SIH26145/pull/5`) is open as a draft against `main`; review/merge/freeze not yet done).
- **Active milestone branch:** `feature/milestone-5-benchmark`
- **Active milestone worktree:** `/home/agntdrgn/WorkSpace/SIH26145/.worktrees/milestone-5-benchmark`
- **Milestone 4:** minimal local API, bounded alert storage, and dashboard (**MERGED into `main` at `44c51d88da7d9d1abb574da3775e06832cf5846a` and FROZEN**); its branch/worktree were deleted after merge.
- **Milestone 3 base commit:** `95159b6da04f0ee7ae6b61b3befd941842aac9bc`
- **Milestone 3 review-fix commit:** `9965de5b85d9d3add72ff417f16ad1f9a7875c19`
- **Milestone 3 merged pull request:** `https://github.com/AgentPhoenix7/SIH26145/pull/3`

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
- PR #3 P2 follow-up now validates the original DNS query as ASCII before lowercasing, so Unicode case mappings such as U+212A cannot become accepted ASCII identities. The Kelvin-sign regression failed before the fix; afterward 97 focused contract/feature/alert/dataset/training tests, Ruff lint/format, strict mypy, and `git diff --check` passed.
- Fresh Milestone 4 worktree baseline at `7498634` passed on 2026-08-29: frozen `uv sync` succeeded; `321 passed in 20.48s`; Ruff lint passed; Ruff confirmed 62 files formatted; strict mypy found no issues in 47 source files; all three deterministic fixture checks and `git diff --check` passed.
- Milestone 4 now has a strict 100-record in-memory alert store, seven-enum approved fixture registry, loopback-only FastAPI entrypoint, existing replay-callback integration, and same-origin static dashboard with bounded 50-row polling/rendering.
- Native API e2e replay stored one actual `PORT_SCAN`, `SYN_FLOOD`, and `DGA` alert newest-first. Port-scan benign, SYN-flood below-threshold, distributed benign, and benign DNS replays each added no dashboard alert.
- Actual browser controls ran all three alert fixtures into the store. Desktop 1440×1000 and narrow 390×844 inspection found no horizontal/card overflow, undefined/object placeholder text, console errors, or framework overlay. Offline failure and recovery states were also exercised. Screenshots are in `docs/screenshots/`.
- The AnyIO static-file regression was observed failing with `FileResponse`; fixed package assets now return from async in-memory responses. Its focused regression, 10 API integration tests, strict mypy, and the pre-review full `339 passed in 18.29s` suite passed.
- Final read-only review reproduced two boundary defects: caller mutation could change stored alerts after validation, and a cross-origin webpage could trigger a bodyless loopback replay POST. New regressions failed first; the store now deep-copies at ingress/egress and replay mutation requires a non-safelisted fixed action header.
- Post-review verification reported `21 passed in 2.57s` for the Milestone 4 focused command and `342 passed in 18.21s` for the full suite; the final browser action, Ruff, strict mypy, fixtures, and rebuilt wheel also passed.
- PR-preparation review reproduced two remaining boundaries: a model mutated before insertion could bypass instance validation, and a DNS-rebinding Host could bypass the action-header defense. Regression-first fixes now revalidate existing models through strict JSON, accept only the `127.0.0.1` Host, reject foreign browser Origins, and prove approved-fixture symlinks cannot escape the repository root.
- Post-PR-preparation verification reported `26 passed in 3.21s` for the focused Milestone 4 command and `347 passed in 19.08s` for the full suite; locked sync, Ruff lint/format, strict mypy, all three fixture checks, and `git diff --check` also passed.
- A real loopback HTTP check returned `200` for alert listing, `400` for a hostile Host, `403` for a hostile Origin with the action header, and `200` with zero alerts for an actual same-origin benign DGA replay. The final sdist and wheel rebuild also passed.
- Final PR review on remote head `de260eb` found no Critical or Important issue and marked the implementation ready to merge. The one Minor limitation is already documented: fixture replay from an installed wheel still requires the source-repository root. GitHub reports no configured status checks.

### Implemented but Not Verified

- None outstanding for Milestone 5; the benchmark tooling, fixture, and measured evidence below are implemented and verified by actual command execution. PR #5 is open as a draft; review/merge/freeze is the remaining step.

### In Progress

- Milestone 5 (this worktree): implementation, tests, and full verification gate complete. PR #5 (`https://github.com/AgentPhoenix7/SIH26145/pull/5`) is open as a draft against `main`; not yet reviewed, merged, or frozen. PR #4 previously merged into `main` at `44c51d88da7d9d1abb574da3775e06832cf5846a` on 2026-08-30T12:31:46Z; Milestone 4 is frozen. `main` also carries one post-merge documentation commit, `7a7e870` (`CLAUDE.md` added as a symlink to `AGENTS.md`).

### Known Problems

- UDP reflection/amplification and DNS tunnelling are not implemented.
- Demonstrated detector coverage spans three of six named classes, but DDoS is limited to SYN floods and DNS coverage to DGA lexical classification; no full-coverage claim is valid.
- The Milestone 5 benchmark is single-replay, across the Python detector process and its native Zeek child (both measured separately for CPU/RSS), and excludes API/dashboard polling latency; see `docs/evaluation.md` for full scope limitations.

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

- Milestone 5 measured end-to-end sustained-replay throughput, alert latency, CPU, and memory: `tools/generate_benchmark_fixture.py` deterministically builds a 21,431-event / 1,507,321-byte PCAP (20,000+ benign background SYN/DNS events, measured directly against the real detectors to stay benign: each source reaches up to 26 rolling-window attempts — above the port-scan minimum — but only 1 unique destination host/port; each destination reaches up to 51 rolling-window events from only 2 unique sources, both below the SYN-flood minimums; see `docs/evaluation.md` for the exact measured numbers and mechanism; plus 10 independent copies each of the verified Milestone 1 port-scan and Milestone 2 SYN-flood exact-threshold patterns, plus the verified Milestone 3 DGA domain and further deterministic candidate domains kept only when the actual packaged model scores them above threshold — 31 qualified); `tools/run_benchmark.py` validates the candidate PCAP and measures the replay in two separate dedicated subprocesses (a PR #5 review finding caught that an earlier revision built the fixture generator's ~21,431-packet object graph in the same process being measured — first before sampling `RUSAGE_SELF`, then, in a first attempted fix, as a reaped child that instead inflated the reported Zeek RSS through `RUSAGE_CHILDREN`'s cross-child high-water mark). The replay-measuring subprocess times the unmodified `DetectionPipeline`/`run_replay` path via a `TimingPipeline` subclass, measures alert latency from the start of detector work through actual JSON serialization and write/flush (mirroring `sih26145.cli.emit_alert`), not detector time alone -- this is post-validation latency, not the full event-acceptance-to-alert-availability interval, since `run_command` (the frozen, unmodified replay path) has already read the raw JSONL line and completed JSON/Pydantic validation before this timer starts -- and measures CPU/peak-RSS separately for itself (`RUSAGE_SELF`) and the native Zeek child it spawns and fully waits for (`RUSAGE_CHILDREN`), not Python alone. A predefined, unselected batch of 5 consecutive runs on WSL2 Linux (16 logical CPUs, Python `3.13.15`, Zeek `8.2.2`) — reported in full, no run selected, reordered, or discarded by its own result — each produced exactly 51 alerts (10 `PORT_SCAN` + 10 `SYN_FLOOD` + 31 `DGA`) and measured, using per-metric medians computed independently across all 5 runs (not one "representative" run and not a hand-picked subset): `12,600`-`16,250` events/sec (`5.5`-`7.1` Mbps computed from actual traffic bytes, not pcap file size, median `~14,800`/`~6.4`), event-processing-latency P50/P95/P99 median `0.020`/`0.033`/`0.406` ms, alert-latency P50/P95/P99 median `0.862`/`1.018`/`1.049` ms (range across runs roughly `0.94`-`1.47` ms at P95/P99), median combined CPU `2.13` s and median combined peak RSS upper bound `~265.6` MiB (Python component medians `1.33` s CPU / `~138.9` MiB RSS, Zeek component medians `0.78` s CPU / `~126.7` MiB RSS — each computed independently across the 5 runs like every other per-metric median here, so they do not necessarily sum exactly to the combined figures; RSS also not necessarily simultaneous). A PR #5 review finding caught that an earlier revision of this table instead hand-picked the 3 lowest-wall-clock runs from a larger unshown batch, which systematically biases throughput up and latency down; this 5-run batch replaces that selection. Full per-run table, method, the Mbps-basis fix, the run-selection-bias fix, and the explicit 51-sample caveat on P95/P99 confidence are in `docs/evaluation.md`. Model-only batch inference measured separately at `2.340909655567489` microseconds/domain (`427184.36297686916` domains/second) and is not pipeline throughput.

### SIH Compliance State

- The current verified path is passive, read-only, incremental, bounded-state, no-decryption, and evidence-producing. See the detailed compliance snapshot below.
- Demonstrated detector coverage spans 3/6 named classes: reconnaissance/port scanning, the SYN-flood subset of volumetric/protocol DDoS, and DGA lexical detection.

### Immediate Next Actions

1. Milestones 1–4 are merged and frozen; do not redesign them without a demonstrated regression.
2. Milestone 5 (this worktree) is implemented, tested, and gate-verified. Review, PR, merge, and freeze it.
3. After merge, treat final submission/PPT rehearsal as the last feature-freeze priority (2026-08-30 is feature freeze; 2026-08-31 is reserved for verification/demo/PPT/packaging only).

### Commands to Resume

```bash
git status --short --branch
git worktree list --porcelain
git log --oneline --decorate -10
git check-ignore -v .worktrees/
```

Progress status vocabulary is `PLANNED`, `IN PROGRESS`, `IMPLEMENTED`, `TESTED`, `VERIFIED`, `BLOCKED`, or `DEFERRED`. `IMPLEMENTED` means code exists; `TESTED` means the relevant tests actually ran; `VERIFIED` additionally requires observed expected behavior and passed acceptance criteria.

## Current Phase

**Milestones 1, 2, 3, and 4 are verified, merged, and frozen on `main`. Milestone 4's minimum API/store/dashboard merged via PR #4 at `44c51d8`; its feature branch and worktree were deleted after merge. `main` matches `origin/main`. Milestone 5 (end-to-end benchmark; see the Benchmark State section above) is implemented, tested, and gate-verified on `feature/milestone-5-benchmark` (PR #5) but not yet merged into `main`.**

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
  -> bounded 100-alert in-memory store
  -> loopback API + same-origin static dashboard
```

Demonstrated detector coverage spans three of six required classes: reconnaissance/port scanning, the SYN-flood subset of volumetric/protocol DDoS, and DGA lexical detection. UDP reflection/amplification, C2 beaconing, DNS tunnelling, encrypted-session malware metadata, and data exfiltration remain absent. End-to-end benchmarking is measured (see the Benchmark State section above and `docs/evaluation.md`) on `feature/milestone-5-benchmark`, not yet merged into `main`.

## Authoritative Context and Git State

- Official problem statement: `docs/problem.md`
- Durable rules: `AGENTS.md`
- Architecture: `docs/architecture.md`
- Versioned feature semantics: `docs/features.md`
- Requirements traceability: `docs/requirements-traceability.md`
- Repository: `/home/agntdrgn/WorkSpace/SIH26145`
- Current branch: `feature/milestone-5-benchmark`
- Current worktree: `/home/agntdrgn/WorkSpace/SIH26145/.worktrees/milestone-5-benchmark` (active Milestone 5 worktree; PR #5 open as a draft against `main`, not yet merged)
- Milestone 4 merge commit: `44c51d88da7d9d1abb574da3775e06832cf5846a`
- Milestone 4 base commit: `7498634bf2e91a9540197166d876c3e381adee40`
- Main worktree: `/home/agntdrgn/WorkSpace/SIH26145`
- Milestone 3 merge commit: `9fc30e612f4ea5accbd412610b692899b93d4ffc`
- Milestone 3 final feature fix: `d61bec43f6559e6191cb0d64309317844dbcc9a2`
- Milestone 3 base commit: `95159b6da04f0ee7ae6b61b3befd941842aac9bc`
- Milestone 3 review-fix commit: `9965de5b85d9d3add72ff417f16ad1f9a7875c19`
- Milestone 3 merged pull request: `https://github.com/AgentPhoenix7/SIH26145/pull/3`
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

Milestone 4 adds:

- A strict thread-safe `AlertStore` with capacity 100, oldest-first eviction, newest-first bounded snapshots, serialized revalidation of existing model instances before mutation, and deep-copy isolation at ingress/egress.
- A shared runtime factory used by both the existing CLI and the API, preserving one detector/replay path and existing CLI JSONL behavior.
- A loopback FastAPI entrypoint with `GET /api/alerts?limit=1..100` and guarded `POST /api/replays/{fixture_id}` for seven code-owned committed fixtures only. The fixed non-safelisted action header prevents ordinary cross-origin mutation without a denied preflight; trusted-host and Origin checks close the DNS-rebinding path.
- One synchronous replay coordinator that feeds the existing callback directly into the store and returns fixed safe errors without exposing child diagnostics.
- A package-local static HTML/CSS/JavaScript dashboard with no frontend dependency or build step, same-origin requests, at most 50 rows, non-overlapping polling, replay-time polling pause, text-only DOM assignment, responsive geometry, and explicit unsupported-coverage labels.
- Actual empty and three-alert screenshots after desktop and narrow browser inspection.

Milestone 5 adds:

- `tools/generate_benchmark_fixture.py`: a deterministic, offline, documentation-address-range PCAP generator producing one sustained-load fixture (20,000 background SYN + 199 background DNS events kept benign by a measured combination of port/host monoculture and rolling-window event/source counts staying under each detector's minimums — see `docs/evaluation.md` for the exact measured numbers, plus 10 independent exact-threshold copies each of the verified Milestone 1 port-scan and Milestone 2 SYN-flood patterns, plus the verified Milestone 3 DGA domain and further deterministic candidate domains kept only when the actual packaged `dga_logreg_v1` model scores them above threshold). Not committed (`.gitignore` `*.pcap`); regenerated on demand, with a byte-determinism/`--check`/no-network-import test suite mirroring Milestones 1–3.
- `tools/run_benchmark.py`: a developer-only measurement harness that replays that fixture through the unmodified `sih26145.runtime.build_detection_pipeline` output via the existing `run_replay`/`run_command` path, using a `TimingPipeline` subclass of the frozen `DetectionPipeline` (subclassing rather than wrapping is required because `run_command` only routes DNS events to a detector that `isinstance`-checks true as `DetectionPipeline`) to record per-event wall-clock processing time, plus an emit callback that performs the real CLI's JSON-serialize-then-write-and-flush emission work into a real OS pipe drained by a background reader thread (`_ConsumedPipe`, exercising the same kernel write/consume path as the real CLI's `sys.stdout` when piped to a consumer, unlike `os.devnull`'s always-instant sink) so measured alert latency covers detector work through actual emission, not detector time alone -- post-validation latency, not the full event-acceptance-to-alert-availability interval, since the frozen `run_command` path already reads and validates the record before this timer starts -- plus `resource.getrusage` CPU/peak-RSS for the process performing the replay (`RUSAGE_SELF`) and the native Zeek child it spawns and fully waits for (`RUSAGE_CHILDREN`), and wall-clock-derived throughput: events/sec from total events divided by elapsed time, and Mbps from the fixture manifest's own `total_captured_bytes` (summed captured Ethernet frame lengths) divided by elapsed time — not the pcap file size, which also counts a 24-byte global header plus a 16-byte record header per packet (capture-format overhead, not traffic). A hard `_MAX_MEASURED_EVENTS` (100,000, matching `SynFloodState`'s own existing global event cap) bounds the per-event bookkeeping lists regardless of manifest trust, and a hard `_MAX_WORKER_MANIFEST_BYTES` (1 MiB, versus the real ~16 KiB manifest) bounds the manifest file itself before it is even read or parsed, since the internal `--worker-manifest` entry point (see below) cannot re-validate against the generator without re-polluting the Zeek RUSAGE_CHILDREN reading. That bound is enforced by rejecting any non-regular manifest path outright and then reading at most one byte over the limit directly, not by trusting a separately queried `stat().st_size` (which a FIFO or character device can misreport, commonly as `0`, while still supplying unbounded or blocking bytes on read). Input is validated before any bytes are loaded: `--pcap` must be a regular file (checked both by an `is_file()` pre-check, which never opens the path, and by `fstat` on the actual open descriptor, so a FIFO or character device is rejected without risking a block on open or a misreported size on read) matching, by size then by SHA-256 digest computed by streaming fixed-size chunks capped at `expected_size + 1` bytes total regardless of how large the underlying file claims or grows to be, the size/digest `tools.generate_benchmark_fixture --fixture-info` currently produces (trust anchored to that deterministic generator, not a caller-controlled sidecar file), and the completed replay's event count and per-class alert counts must match that same generated fixture's own manifest before a report is produced. Those same streamed chunks are copied into a private temporary file as they are validated, and the worker subprocess replays that private copy rather than the caller-supplied `--pcap` path, so a path swap (retargeted symlink, replaced file) between validation completing and the worker later opening it cannot substitute unvalidated bytes into the measured replay. Validation and the measured replay each run in their own dedicated subprocess (`_generator_fixture_info`, `_measure_replay` via a `--worker-manifest` re-invocation) so the generator's own ~21,431-packet object-graph construction cannot inflate either the reported Python or the reported Zeek CPU/RSS figures — see the PR #5 review-fix note below.
- No detector, contract, replay-runner, API, or model behavior changed for this milestone.
- Measured, recorded, real evidence (predefined, unselected batch of 5 consecutive runs reported in full, per-metric medians; see `docs/evaluation.md`): `12,600`-`16,250` events/sec, `5.5`-`7.1` Mbps (from actual traffic bytes, not pcap file size), event-processing-latency P50/P95/P99 median `0.020`/`0.033`/`0.406` ms, alert-latency (post-validation: detector start through actual emission into a real, drained OS pipe -- excludes the line-read/parse/validate `run_command` already did) P50/P95/P99 median `0.862`/`1.018`/`1.049` ms over 51 alert samples/run, median combined CPU `2.13` s, median combined peak RSS upper bound `~265.6` MiB (Python component medians `1.33` s CPU / `~138.9` MiB RSS, Zeek component medians `0.78` s CPU / `~126.7` MiB RSS — independently computed, not additive). Four PR #5 review findings (validation/measurement subprocess isolation; Mbps computed from actual traffic bytes, not pcap file overhead; unbiased run reporting instead of hand-picking the 3 lowest-wall-clock runs from a larger batch; component CPU/RSS medians presented as independent figures rather than an additive equation) are fixed. See `docs/evaluation.md` for the corrected methodology and the complete 5-run table.

## Milestone 5 Acceptance

- [x] Locked environment synchronization succeeds and the recorded pre-implementation baseline (`347 passed`) passed.
- [x] The benchmark fixture is deterministic, offline, byte-reproducible, and produces exactly the expected event/alert counts on native Zeek replay.
- [x] The benchmark harness measures the existing, unmodified detector/replay path (no duplicated detection logic, no new detector/model behavior).
- [x] Throughput (events/sec, Mbps), event-processing and alert-latency P50/P95/P99, CPU, and peak RSS are measured from real command execution, not estimated or fabricated.
- [x] Focused unit tests cover the percentile function and the timing proxy's recording/dispatch behavior; full suite, Ruff lint/format, strict mypy, all four fixture `--check` commands, and `uv build` pass together.
- [x] `docs/evaluation.md`, `docs/requirements-traceability.md`, `docs/limitations.md`, `docs/ppt-notes.md`, `docs/architecture.md`, `README.md`, and this file are synchronized with the measured results and honest scope limitations.

## Milestone 4 Acceptance

- [x] Locked environment synchronization succeeds and the recorded pre-implementation baseline passed.
- [x] API entrypoint binds to loopback by default; route limits and fixture identifiers reject invalid input safely.
- [x] Alert validation precedes mutation; capacity, deterministic oldest eviction, newest-first ordering, and bounded snapshots have focused tests.
- [x] The existing replay callback feeds the store through the shared three-detector runtime factory without duplicating detector logic.
- [x] Native port-scan, SYN-flood, and DGA fixture replays each add their expected strict alert; four benign/below-threshold comparisons add none.
- [x] The real dashboard displays actual stored values and evidence with bounded polling/rows and explicit unsupported coverage.
- [x] Browser inspection covers loading/empty/success/failure/recovery behavior, actual replay controls, desktop and narrow geometry, overflow, and console errors.
- [x] Final full tests, Ruff, strict mypy, three fixture checks, package-resource inspection, documentation checks, and `git diff --check` pass together.

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

PR #3 follow-up review found that lowercasing preceded ASCII validation. `normalize_dns_name` now validates the original observed spelling as ASCII first, then removes one terminal dot and lowercases; U+212A (`KELVIN SIGN`) is a permanent event-contract regression case.

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

Fresh Milestone 5 implementation/verification was run from the dedicated worktree on 2026-08-30:

```bash
UV_CACHE_DIR=/tmp/sih26145-m5-uv-cache uv sync --frozen --group dev
UV_CACHE_DIR=/tmp/sih26145-m5-uv-cache uv run pytest -q
UV_CACHE_DIR=/tmp/sih26145-m5-uv-cache uv run ruff check .
UV_CACHE_DIR=/tmp/sih26145-m5-uv-cache uv run ruff format --check .
UV_CACHE_DIR=/tmp/sih26145-m5-uv-cache uv run mypy src tests tools
UV_CACHE_DIR=/tmp/sih26145-m5-uv-cache uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1 --check
UV_CACHE_DIR=/tmp/sih26145-m5-uv-cache uv run python tools/generate_milestone2_fixtures.py --output tests/fixtures/milestone2 --check
UV_CACHE_DIR=/tmp/sih26145-m5-uv-cache uv run python tools/generate_milestone3_fixtures.py --output tests/fixtures/milestone3 --check
UV_CACHE_DIR=/tmp/sih26145-m5-uv-cache uv run python tools/generate_benchmark_fixture.py --output tests/fixtures/benchmark
UV_CACHE_DIR=/tmp/sih26145-m5-uv-cache uv run zeek -D -b -r tests/fixtures/benchmark/sustained_load.pcap src/sih26145/zeek/emit_events.zeek
UV_CACHE_DIR=/tmp/sih26145-m5-uv-cache uv run sih26145-replay tests/fixtures/benchmark/sustained_load.pcap
UV_CACHE_DIR=/tmp/sih26145-m5-uv-cache uv run python tools/run_benchmark.py --pcap tests/fixtures/benchmark/sustained_load.pcap
UV_CACHE_DIR=/tmp/sih26145-m5-uv-cache uv build
git diff --cached --check
```

Observed results: locked sync checked 33 packages; the full suite reported `361 passed`; Ruff lint passed; Ruff confirmed 73 files formatted; strict mypy found no issues in 57 source files; all four fixture `--check` commands exited `0`; native Zeek replay of the generated benchmark PCAP emitted exactly `21431` events ending with `end_of_stream`; `sih26145-replay` on the same PCAP emitted exactly 51 alert lines (10 `PORT_SCAN`, 10 `SYN_FLOOD`, 31 `DGA`); `tools/run_benchmark.py` ran three times, each reporting exactly `21431` events processed and 51 alerts emitted, with the throughput/latency/CPU/RSS figures (per-metric medians) recorded in `docs/evaluation.md`; the sdist/wheel build succeeded; `git diff --cached --check` passed.

Fresh evidence for the PR #5 subprocess-isolation review fix (`r3889840575`) was run from the same worktree on 2026-08-30:

```bash
UV_CACHE_DIR=/tmp/sih26145-m5-fix-uv-cache uv run ruff check .
UV_CACHE_DIR=/tmp/sih26145-m5-fix-uv-cache uv run ruff format --check .
UV_CACHE_DIR=/tmp/sih26145-m5-fix-uv-cache uv run mypy src tests tools
UV_CACHE_DIR=/tmp/sih26145-m5-fix-uv-cache uv run pytest -q
UV_CACHE_DIR=/tmp/sih26145-m5-fix-uv-cache uv run python tools/generate_benchmark_fixture.py --output tests/fixtures/benchmark --check
UV_CACHE_DIR=/tmp/sih26145-m5-fix-uv-cache uv run zeek -D -b -r tests/fixtures/benchmark/sustained_load.pcap src/sih26145/zeek/emit_events.zeek
UV_CACHE_DIR=/tmp/sih26145-m5-fix-uv-cache uv run sih26145-replay tests/fixtures/benchmark/sustained_load.pcap | wc -l
UV_CACHE_DIR=/tmp/sih26145-m5-fix-uv-cache uv run python tools/run_benchmark.py --pcap tests/fixtures/benchmark/sustained_load.pcap  # x3
UV_CACHE_DIR=/tmp/sih26145-m5-fix-uv-cache uv build
git diff --cached --check
```

Observed results: Ruff lint passed; Ruff confirmed 73 files formatted; strict mypy found no issues in 57 source files; the full suite reported `374 passed` (13 new tests: `--fixture-info`/worker-manifest coverage plus an AST-based regression pinning that `tools/run_benchmark.py` never imports the generator's object-graph builder in-process); the `--check` fixture command confirmed the pcap bytes are unchanged (only the generator's argparse/CLI surface changed); native Zeek replay still emitted exactly `21431` events; `sih26145-replay` still emitted exactly 51 alert lines; `tools/run_benchmark.py` ran three times with the two-subprocess isolation, each reporting exactly `21431` events processed and 51 alerts emitted, with corrected per-metric-median figures recorded in `docs/evaluation.md`, `docs/limitations.md`, `docs/ppt-notes.md`, and the Benchmark State section above; the sdist/wheel build succeeded; `git diff --cached --check` passed.

A code-review pass on PR #5 found the alert-latency measurement timed only `DetectionPipeline.process()` (not the real serialize/write/flush emission), that 3 alert samples could not support a P95/P99 claim, and that a summary CPU figure was miscalculated. All three were fixed: `tools/run_benchmark.py` now times event-acceptance through an emit callback that performs the CLI's actual JSON-serialize-then-write-and-flush work; `tools/generate_benchmark_fixture.py` now embeds 10 independent Milestone 1 port-scan and 10 independent Milestone 2 SYN-flood incidents plus model-verified DGA candidate domains (31 qualified), yielding 51 alert samples/run instead of 3; and every reported figure below is now computed programmatically as a genuine per-metric median across 3 runs.

A follow-up PR #5 review comment (`r3889840575`) found that validating `--pcap` called `_benchmark_artifacts()` in-process before sampling `RUSAGE_SELF`, so the reported Python peak RSS could reflect the fixture generator's ~21,431-packet object-graph construction rather than the detector replay. A first attempted fix moved that validation into its own subprocess, but since that subprocess was reaped *before* Zeek, it instead polluted the reported Zeek RSS via `RUSAGE_CHILDREN`'s cross-child high-water mark (observed regression: Zeek RSS rose from its true ~126 MiB to ~140 MiB, matching the generator's own footprint). The final fix runs fixture validation (`_generator_fixture_info`) and the measured replay itself (`_measure_replay`, invoked via a `--worker-manifest` re-exec of this same script) in two separate, dedicated subprocesses, so neither pollutes the other; `tools/generate_benchmark_fixture.py` gained a `--fixture-info` mode to support this without ever transmitting the full ~1.5 MB pcap bytes over the subprocess boundary. Three fresh runs under the corrected methodology measured `16,500`-`17,750` events/sec, median combined CPU `1.84` s (Python component median `1.15` s, Zeek component median `0.69` s), and median combined peak RSS `~265.3` MiB (Python component median `~138.8` MiB, Zeek component median `~126.6` MiB) — close to the pre-fix headline figures, confirming the bug did not, in practice, materially distort them for this fixture's size, but the corrected methodology is what is now trusted and documented throughout. (These three-run figures were themselves later superseded by the unbiased 5-run batch recorded further below and in `docs/evaluation.md`.)

A further PR #5 review comment (`r3889897384`) found that the new internal `--worker-manifest` entry point bypasses `_validate_pcap_matches_generated_fixture()` by design (it must: re-validating via the generator inside the measured worker would re-corrupt Zeek's `RUSAGE_CHILDREN` reading). `TimingPipeline.process` now enforces a hard `_MAX_MEASURED_EVENTS` cap (100,000, matching `SynFloodState`'s own existing global event limit) regardless of manifest trust, raising the existing `StateLimitExceeded` (which `sih26145.replay.run_command` already re-raises bare); `_run_worker` catches it for a clean diagnostic. The real 21,431-event fixture stays far under the cap. Full suite: `375 passed` (1 new regression pinning the enforcement point directly).

A final PR #5 review comment (`r3889932943`) found that reported Mbps used `pcap_path.stat().st_size` (the pcap *file* size, `1,507,321` bytes) as its byte basis, which also counts a 24-byte global header plus a 16-byte record header per packet -- `342,920` bytes of pure capture-format overhead for this fixture's 21,431 packets, none of it network traffic; the reviewer computed the resulting overstatement as roughly `9.68` Mbps reported versus `~7.48` Mbps of actual captured frames. `tools/generate_benchmark_fixture.py`'s manifest now also records `total_captured_bytes` (`1,164,401` for this fixture -- the sum of captured Ethernet frame lengths, computed once from the trusted capture bytes the generator already produces); `tools/run_benchmark.py` now computes Mbps from that manifest field instead of the pcap file size, and reports both `pcap_bytes` and the new `traffic_bytes` separately for transparency. Applying the corrected formula to the previously recorded, unaffected wall-clock times from the isolation-fix's quieter session (`1.245`/`1.207`/`1.299` s) gives `7.48`/`7.72`/`7.17` Mbps (median `7.48`) -- confirming the reviewer's own estimate exactly. Fresh end-to-end re-measurement for this fix ran under measurably heavier background host contention than that quieter session (median wall-clock `~1.62` s versus `~1.25` s previously, on the same fixture/hardware); the three least-contended of several runs are the ones now recorded in `docs/evaluation.md`, `docs/limitations.md`, `docs/ppt-notes.md`, `docs/requirements-traceability.md`, and the Benchmark State section above, with the contention disclosed rather than hidden. Full suite: `375 passed`; Ruff lint/format, strict mypy, all four fixture `--check` commands (fixture bytes unchanged; only the manifest gained two new fields), native Zeek/CLI replay, and `uv build` all pass.

A further PR #5 review comment (`r3889981882`) found that the documented benchmark table selected only the 3 lowest-wall-clock runs from a larger, unshown batch, which systematically favors higher throughput and lower latency rather than representing genuinely repeated performance -- `docs/requirements-traceability.md` also called it an "all-run table" even though the omitted runs were never shown. Fixed by adopting a predefined, reproducible run-selection policy instead of post-hoc picking: 5 consecutive runs of `uv run python tools/run_benchmark.py --pcap tests/fixtures/benchmark/sustained_load.pcap` (no code change; `tools/run_benchmark.py` already produces one report per invocation), taken in full with none selected, reordered, or discarded by its own result. All 5 runs produced exactly 21,431 events and 51 alerts (10 `PORT_SCAN` + 10 `SYN_FLOOD` + 31 `DGA`) and measured `12,600`-`16,250` events/sec (`5.5`-`7.1` Mbps, median `~14,800`/`~6.4`), event-processing-latency P50/P95/P99 median `0.020`/`0.033`/`0.406` ms, alert-latency P50/P95/P99 median `0.862`/`1.018`/`1.049` ms (range `0.94`-`1.47` ms at P95/P99 across runs -- the ~13% spread reflects ordinary shared-host contention, disclosed rather than narrowed by selection), median combined CPU `2.13` s, and median combined peak RSS upper bound `271,996` KiB ≈ `265.6` MiB (Python component medians `1.33` s CPU / `~138.9` MiB RSS, Zeek component medians `0.78` s CPU / `~126.7` MiB RSS — each independently computed across the 5 runs, so they do not necessarily sum exactly to the combined figures). `docs/evaluation.md`, `docs/limitations.md`, `docs/ppt-notes.md`, `docs/requirements-traceability.md`, and the Benchmark State section above now report this complete 5-run batch instead of a hand-picked subset. Full suite: `375 passed`; Ruff lint/format, strict mypy, fixture `--check` (bytes unchanged), and native Zeek/CLI replay all pass; no source code changed, so `uv build` is unaffected.

Two further PR #5 review comments (`r3890121073`, `r3890121077`) followed the 5-run-batch fix: `docs/requirements-traceability.md` still told readers the Milestone 5 evidence was a "per-run table (3 runs)", stale after the 5-run replacement; and `docs/ppt-notes.md`'s benchmark table wrote `1.33 s + 0.78 s = ~2.13 s combined`, which is arithmetically wrong (`1.32757 + 0.782425 ≈ 2.11`, not `2.133134`) because the Python and Zeek component figures are each an independently computed per-metric median across the 5 runs, not components of one run, so they need not sum exactly to the combined-column median. Fixed by updating the stale "3 runs" reference to "5 runs", and by removing every "component + component = combined" equation across `docs/evaluation.md`, `docs/limitations.md`, `docs/ppt-notes.md`, `docs/requirements-traceability.md`, and this file, replacing it with wording that presents the combined median and its Python/Zeek component medians as separately, independently computed figures. No measured value changed; only the presentation of already-recorded figures. Full suite: `375 passed`; Ruff lint/format, strict mypy, and `git diff --check` all pass; no source code changed.

A further PR #5 review comment (`r3890156745`) found that the `_MAX_MEASURED_EVENTS` cap added for `r3889897384` bounds only the per-event bookkeeping lists inside `TimingPipeline.process`, but a direct `--worker-manifest` invocation still calls `manifest_path.read_text()` and `json.loads()` on the caller-supplied manifest file in full *before* reaching that cap, so an arbitrarily large manifest file could exhaust memory before any per-event bound ever runs. Fixed by adding `_MAX_WORKER_MANIFEST_BYTES` (1 MiB -- generous headroom over the real ~16 KiB manifest, not a tuned production limit) and checking `manifest_path.stat().st_size` against it in `_run_worker` before `read_text`/`json.loads` are ever called, printing a `worker_manifest_error: manifest_too_large` diagnostic and exiting 1 on violation. The normal `run_benchmark()` path (which always writes its own small manifest) is unaffected. A focused regression writes an over-bound manifest containing invalid JSON and asserts the size check trips before parsing (proven by the diagnostic being the size error rather than a `JSONDecodeError`). Full suite: `376 passed` (1 new); Ruff lint/format, strict mypy, fixture `--check`, native replay, and `uv build` all pass; no measured benchmark figures changed.

A further PR #5 review comment (`r3890178195`) found that the manifest-size fix for `r3890156745` still trusted `manifest_path.stat().st_size`: a non-regular `--worker-manifest` path (a FIFO, a character device such as `/dev/zero`) can report a misleading size -- commonly `0` -- so the size check would pass and `read_text()` would then proceed unbounded, able to block indefinitely (FIFO with no writer) or exhaust memory (`/dev/zero`) before the event cap ever ran. `_run_worker` now rejects any `manifest_path` that is not a regular file via `Path.is_file()` before attempting any read at all, and reads at most `_MAX_WORKER_MANIFEST_BYTES + 1` bytes directly (`handle.read(N + 1)`, checking the returned length) rather than trusting a separately queried size, so the same bound holds regardless of what `stat()` reports. Two focused regressions: a FIFO with no writer is rejected by the `is_file()` check alone (the test would hang if the implementation ever tried to open/read it, proving the rejection happens first); the existing oversized-manifest regression continues to pass under the new bounded-read implementation. Full suite: `377 passed` (1 new); Ruff lint/format, strict mypy, fixture `--check`, native replay, and `uv build` all pass; no measured benchmark figures changed.

A further PR #5 review comment (`r3890196106`) found a TOCTOU gap in the overall validation flow: `run_benchmark()` validated `--pcap` in the calling process, then separately spawned a worker subprocess pointed at that same original path. If the path (a symlink, a swapped file) were replaced after validation completed but before the worker later opened it for replay, the worker would replay unvalidated bytes while the result checks and Mbps calculation still trusted the original fixture's manifest/`total_captured_bytes` -- an alternate capture matching the fixture's event/alert counts could pass verification while producing invalid benchmark evidence. Fixed by copying the validated bytes into a private temporary file as they are streamed for hashing (`_validate_pcap_matches_generated_fixture` now writes each chunk it reads to a `dest_path` alongside updating the digest), and pointing the worker subprocess at that private copy instead of the caller-supplied path; validation and replay are now provably the same bytes by construction, not just by an earlier check. The report's `pcap_path` field still shows the caller-supplied path for readability (the two are guaranteed identical). A focused regression proves the copy is byte-for-byte identical to the source; existing validation tests updated for the new `dest_path` parameter. Full suite: `377 passed`; Ruff lint/format, strict mypy, fixture `--check`, native replay (still 21,431 events / 51 alerts), and `uv build` all pass; no measured benchmark figures changed.

Two further PR #5 review comments (`r3890220944`, `r3890220948`) followed the TOCTOU fix:

`r3890220944` found that although emit-time measurement was fixed earlier, the alert-latency timer still starts only inside `DetectionPipeline.process()`, after `run_command()` (the frozen, unmodified replay path) has already read the raw Zeek JSONL line and completed `_parse_record`'s JSON decode and Pydantic contract validation. On inputs where parsing/pipe delay is material, the previously documented "event-acceptance-to-alert-availability" claim therefore omitted part of the operational event-to-alert path. Rather than modify `run_command` itself (which this benchmark deliberately never touches, to keep measuring the actual unmodified replay path), every "alert latency" description across `tools/run_benchmark.py`'s docstrings, `docs/evaluation.md`, `docs/ppt-notes.md`, `docs/architecture.md`, `docs/requirements-traceability.md`, and this file was relabeled as post-validation detector-to-emission latency, explicitly noting it excludes the line-read/parse/validate cost `run_command` already performs before the timer starts. No measured value changed.

`r3890220948` found that `_validate_pcap_matches_generated_fixture` still checked size with a preliminary `stat()` and then read/hashed in an unbounded loop: if the pathname were replaced, retargeted, or appended after that `stat()` but before or during the following `open()`+read, a growing regular file, or a FIFO/character device swapped in afterward, could make the loop copy/hash until EOF (or block forever) despite the claimed fixed input bound. Fixed by opening the candidate once, rejecting non-regular files via both an `is_file()` pre-check (which never opens the path, so a plain FIFO with no writer cannot block the process) and an `fstat` of the actual open descriptor, and bounding the read loop to stop after at most `expected_size + 1` bytes regardless of what the file claims or how large it grows. Three focused regressions: a FIFO with no writer is rejected without ever being opened (the test would hang otherwise); a file far larger than the expected fixture size is still rejected promptly rather than fully hashed; the existing missing-file test's expected message updated to match the new `is_file()`-based check. Full suite: `379 passed` (3 new); Ruff lint/format, strict mypy, fixture `--check`, native replay (still 21,431 events / 51 alerts), and `uv build` all pass; no measured benchmark figures changed.

Fresh Milestone 4 verification was run from the dedicated worktree on 2026-08-30:

```bash
UV_CACHE_DIR=/tmp/sih26145-uv-cache UV_LINK_MODE=copy uv sync --frozen --group dev
UV_CACHE_DIR=/tmp/sih26145-uv-cache UV_LINK_MODE=copy uv run pytest tests/unit/test_alert_store.py tests/integration/test_api.py tests/e2e/test_milestone4.py -q
UV_CACHE_DIR=/tmp/sih26145-uv-cache UV_LINK_MODE=copy uv run pytest -q
UV_CACHE_DIR=/tmp/sih26145-uv-cache UV_LINK_MODE=copy uv run ruff check .
UV_CACHE_DIR=/tmp/sih26145-uv-cache UV_LINK_MODE=copy uv run ruff format --check .
UV_CACHE_DIR=/tmp/sih26145-uv-cache UV_LINK_MODE=copy uv run mypy src tests tools
UV_CACHE_DIR=/tmp/sih26145-uv-cache UV_LINK_MODE=copy uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1 --check
UV_CACHE_DIR=/tmp/sih26145-uv-cache UV_LINK_MODE=copy uv run python tools/generate_milestone2_fixtures.py --output tests/fixtures/milestone2 --check
UV_CACHE_DIR=/tmp/sih26145-uv-cache UV_LINK_MODE=copy uv run python tools/generate_milestone3_fixtures.py --output tests/fixtures/milestone3 --check
UV_CACHE_DIR=/tmp/sih26145-uv-cache UV_LINK_MODE=copy uv build
git diff --check
```

Observed results: locked sync checked 33 packages; the final Milestone 4 focused command reported `21 passed in 2.57s`; the full suite reported `342 passed in 18.21s`; Ruff lint passed; Ruff confirmed 68 files formatted; strict mypy found no issues in 53 source files; and all three fixture checks exited `0`. The first sandboxed build attempt failed only because build isolation could not resolve Hatchling through restricted DNS; the identical final build with dependency-download access produced the sdist and wheel. Wheel inspection found the API/store/runtime modules, all three dashboard assets, both console entrypoints, and exact FastAPI/Uvicorn/scikit-learn requirements. `git diff --check` passed.

The real `sih26145-dashboard` server was inspected on `127.0.0.1:8000`. Browser controls ran the three alert fixtures and rendered three actual cards, then a fresh post-static-response check ran one port-scan fixture and rendered one card. Desktop and 390-pixel checks had no horizontal/card overflow; offline failure and recovery states rendered; content and interactive controls were present; no error overlay, placeholder object text, or console error was observed. The two committed PNGs were captured from the real dashboard before documentation claimed them.

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
Bounded alert latency:        PARTIALLY MEASURED; post-validation detector-to-emission P50/P95/P99 measured over 51 alert samples/run, ~0.7-1.5 ms across a predefined unselected 5-run batch (median P95/P99 ~1.0-1.0 ms), excludes the raw-record read/parse/validation `run_command` already performs before the timer starts, so this is not the full record-availability-to-alert-availability bound; see docs/evaluation.md
Alert schema/evidence:        VERIFIED with actual strict PORT_SCAN, SYN_FLOOD, and DGA records
Dataset research/provenance:  Source licences/hashes/revision and fixture provenance VERIFIED
ML model trained:             VERIFIED for dga_logreg_v1 with grouped held-out evaluation
Model storage/resume:         Packaged joblib + strict metadata VERIFIED; remote resume NOT APPLICABLE
Offline model inference:      VERIFIED for packaged local DGA model with socket disabled
Threat coverage:              3 / 6 demonstrated; DDoS limited to SYN flood, DNS limited to DGA
Throughput measured:          YES; 12,600-16,250 events/sec (5.5-7.1 Mbps, from actual traffic bytes), predefined unselected 5-run batch, Python+Zeek combined CPU/RSS, see docs/evaluation.md
Demo reproducible:            VERIFIED for native scan, SYN-flood, DGA, comparison replay, and the benchmark
PPT evidence:                 Actual dashboard screenshots and measured benchmark table captured; final deck NOT ASSEMBLED
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
- Wall-clock alert latency, throughput, CPU, and memory are now measured on `feature/milestone-5-benchmark` (see the Benchmark State section above and `docs/evaluation.md`); not yet merged into `main`.
- No official downloadable SIH26145 dataset was found as of 2026-08-26; the selected Majestic and DGA sources have recorded licences/provenance, and every future corpus still requires review.
- No final presentation deck exists yet. The local API/dashboard, actual screenshot set, and measured end-to-end benchmark evidence now exist.

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

Milestones 1 through 4 are merged, verified, and frozen on `main` (Milestone 4 via PR #4, merge commit `44c51d8`). The next deadline priorities are the measured benchmark and final submission/PPT rehearsal.

## Handoff Checklist

1. Confirm the repository/worktree and inspect `git status`, diffs, and recent commits.
2. Read `AGENTS.md`, `docs/problem.md`, this file, and relevant source/tests completely.
3. Confirm work continues on `feature/milestone-5-benchmark` in `.worktrees/milestone-5-benchmark` until it is reviewed, merged, and frozen; keep Milestones 1 through 4 frozen unless a demonstrated regression requires touching them.
4. Treat this as a verified snapshot, not a substitute for fresh commands.
5. Do not redesign frozen Milestones 1 through 4. Milestone 5 is implemented and gate-verified but not yet reviewed/merged; do not start a new milestone worktree before that happens.
6. Never claim a class, model, dashboard, metric, screenshot, or benchmark without actual current evidence.
