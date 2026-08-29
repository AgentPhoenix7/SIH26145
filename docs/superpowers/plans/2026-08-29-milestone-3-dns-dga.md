# Milestone 3 DNS/DGA ML Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one provenance-backed, trained, persisted, locally inferred DNS/DGA Logistic Regression path to the existing passive streaming replay MVP.

**Architecture:** A combined Zeek policy emits strict SYN and DNS request records. The existing synchronous pipeline routes each record to its responsible detector; a shared lexical extractor feeds one packaged sklearn pipeline, and the DGA detector emits typed `alert_v1` evidence without network access or rolling state.

**Tech Stack:** Python 3.12+, Pydantic 2, native Zeek 8.2.2, scikit-learn Logistic Regression, joblib, uv, pytest, Ruff, strict mypy.

**Spec:** `docs/superpowers/specs/2026-08-29-milestone-3-dns-dga-design.md`

## Global Constraints

- Work only on `feature/milestone-3-dns-dga` in `.worktrees/milestone-3-dns-dga`.
- Preserve the frozen port-scan and SYN-flood behavior and schemas for SYN input.
- Runtime inference is local, offline, passive, request-only, and bounded per record.
- Dataset acquisition is explicit and separate from runtime; full corpora and upstream GPL files remain ignored.
- Implement DGA only; DNS tunnelling and every unrelated milestone remain deferred.
- Every production behavior follows a witnessed RED then GREEN test cycle.

---

### Task 1: Provenance gate and dependency

**Files:**
- Modify: `docs/dataset-research.md`
- Modify: `pyproject.toml`
- Modify: `uv.lock`

**Interfaces:**
- Produces: verified source URLs/licences/revisions and `scikit-learn>=1.7,<2` runtime availability.

- [ ] Record the Majestic CC BY 3.0 statement, 2026-08-29 snapshot semantics, CSV format/restrictions, and the pinned DGA GPL-2.0 revision before download.
- [ ] Add only scikit-learn as the new direct dependency and refresh the lock.
- [ ] Run locked sync and the existing 240-test baseline.
- [ ] Commit with `docs: approve milestone three data sources`.

### Task 2: Strict DNS event and combined native stream

**Files:**
- Modify: `src/sih26145/contracts/events.py`
- Create: `src/sih26145/zeek/emit_events.zeek`
- Modify: `src/sih26145/replay.py`
- Modify: `tests/unit/test_event_contracts.py`
- Create: `tests/integration/test_dns_zeek_policy.py`

**Interfaces:**
- Produces: `DnsEventV1`, `NetworkEvent = TcpSynAttemptV1 | DnsEventV1`, and a combined stream with one `control_v1` EOS.

- [ ] Add failing unit tests for a literal valid DNS line, normalization, UDP/TCP, invalid names, strict numeric fields, extra fields, and line bounds; run them and confirm missing `DnsEventV1` is the failure.
- [ ] Implement strict `DnsEventV1` and extend `parse_stream_line`; run the focused tests green.
- [ ] Add a failing native policy test using a minimal temporary DNS-query PCAP and assert one DNS record followed by consistent EOS.
- [ ] Implement `emit_events.zeek`, switch public replay to it, and run the policy plus frozen native tests green.
- [ ] Commit with `feat: add passive DNS event stream`.

### Task 3: Shared lexical features and strict DGA alert

**Files:**
- Create: `src/sih26145/ml/__init__.py`
- Create: `src/sih26145/ml/dns_features.py`
- Modify: `src/sih26145/contracts/alerts.py`
- Create: `tests/unit/test_dns_features.py`
- Create: `tests/unit/test_dga_alert_contracts.py`

**Interfaces:**
- Produces: `FEATURE_SCHEMA_VERSION`, 12 summary features plus 128 deterministic hashed character n-gram buckets, `FEATURE_NAMES`, `DnsLexicalFeatures`, `extract_dns_features(domain)`, `DgaEvidence`, and `DgaAlertV1`.

- [ ] Add failing feature tests with hand-derived vectors for `example.com`, digit/hyphen domains, entropy, bigram ratio, and consonant/digit runs.
- [ ] Implement the 12 ordered finite summary values and 128 normalized hashed 2-gram/3-gram buckets in `dns_features_v1`, then run focused tests green.
- [ ] Add failing alert tests for one literal DGA alert and every mismatch: class/detector/evidence, probability/threshold, model/feature version, query name, transport, and zero-span window.
- [ ] Extend `alert_v1` with typed DGA evidence while preserving scan/flood serialization; run all alert tests green.
- [ ] Commit with `feat: define shared DGA lexical evidence`.

### Task 4: Bounded dataset preparation and grouped training

**Files:**
- Create: `tools/prepare_dns_dataset.py`
- Create: `tools/train_dga_model.py`
- Create: `tests/unit/test_dns_dataset.py`
- Create: `tests/unit/test_dga_training.py`
- Create: `src/sih26145/artifacts/dga_logreg_v1.joblib`
- Create: `src/sih26145/artifacts/dga_logreg_v1.metadata.json`

**Interfaces:**
- Consumes: Majestic CSV, pinned local DGA checkout, and `extract_dns_features`.
- Produces: bounded ignored training CSV/manifest, trusted sklearn pipeline artifact, and strict evaluation metadata.

- [ ] Add failing preparation tests for literal miniature source files covering caps, family labels, normalization, hashes, deduplication, and conflicting-label rejection.
- [ ] Implement offline preparation with no network calls and run focused tests green.
- [ ] Add failing training tests proving fixed family-disjoint DGA split, stable benign hash split, no domain overlap, required metrics, artifact hash, and reload probability parity.
- [ ] Implement StandardScaler plus balanced Logistic Regression training, test evaluation, joblib persistence, strict metadata, and CPU batch timing; run focused tests green.
- [ ] After the documented provenance gate, download the Majestic snapshot to ignored `data/`, clone and detach the DGA repo at the pinned revision under ignored `data/`, prepare the bounded dataset, train the real model, and inspect the measured metadata.
- [ ] Commit code, tests, artifact, and metadata with `feat: train persisted DGA logistic model`; do not commit corpora or the upstream checkout.

### Task 5: Offline detector and streaming integration

**Files:**
- Create: `src/sih26145/ml/dga_model.py`
- Create: `src/sih26145/detection/dga.py`
- Modify: `src/sih26145/detection/pipeline.py`
- Modify: `src/sih26145/cli.py`
- Modify: `src/sih26145/replay.py`
- Create: `tests/unit/test_dga_model.py`
- Create: `tests/unit/test_dga_detector.py`
- Modify: `tests/unit/test_detection_pipeline.py`
- Modify: `tests/integration/test_replay_runner.py`

**Interfaces:**
- Produces: `DgaModel.load_packaged()`, `predict_probability(domain)`, `DgaDetector.process(DnsEventV1)`, and type-routed `DetectionPipeline.process(NetworkEvent)`.

- [ ] Add failing loader tests for valid packaged metadata/artifact plus hash, version, feature-order, label, and pipeline-shape failures.
- [ ] Implement one-time trusted local model load and exact feature/probability inference; run focused tests green with network access disabled.
- [ ] Add failing detector/pipeline tests for above/below threshold, typed evidence, deterministic severity, DNS-only routing, and unchanged SYN alert order.
- [ ] Implement stateless DGA detection and explicit event routing; run focused tests green.
- [ ] Add failing CLI/replay tests proving model validation occurs before Zeek and mixed events retain EOS accounting and alert-before-EOS order.
- [ ] Wire the packaged model into the CLI and run integration plus frozen e2e tests green.
- [ ] Commit with `feat: integrate offline streaming DGA inference`.

### Task 6: Deterministic native replay and submission evidence

**Files:**
- Create: `tools/generate_milestone3_fixtures.py`
- Create: `tests/fixtures/milestone3/benign_dns.pcap`
- Create: `tests/fixtures/milestone3/benign_dns.manifest.json`
- Create: `tests/fixtures/milestone3/dga_dns.pcap`
- Create: `tests/fixtures/milestone3/dga_dns.manifest.json`
- Create: `tests/unit/test_milestone3_fixture_generator.py`
- Create: `tests/e2e/test_milestone3.py`
- Modify: `.gitignore`
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/features.md`
- Create: `docs/evaluation.md`
- Create: `docs/limitations.md`
- Modify: `docs/requirements-traceability.md`
- Modify: `docs/ppt-notes.md`
- Modify: `PROGRESS.md`

**Interfaces:**
- Produces: reproducible offline DNS PCAPs and current measured submission evidence.

- [ ] Add failing generator tests for byte determinism, valid checksums, manifest hashes, no socket use, and `--check` drift detection; implement the minimal Ethernet/IPv4/UDP/DNS writer and run green.
- [ ] Generate one controlled benign query and one synthetic high-entropy query selected from outside training data; record actual model probabilities and expected outcomes in manifests.
- [ ] Add failing native e2e tests for strict DNS event parsing, one DGA alert before EOS, benign zero alerts, canonical CLI JSONL, and local inference with network access disabled; run green.
- [ ] Update only affected docs with actual sources, features, split, precision, recall, F1, FPR, artifact bytes, CPU inference measurements, limitations, exact commands, and honest 3/6 demonstrated class status.
- [ ] Run `uv sync --frozen --group dev`, full pytest, Ruff lint/format, strict mypy, all three fixture checks, actual benign/DGA CLI replay, strict alert validation, artifact integrity validation, `git diff --check`, and status inspection.
- [ ] Commit with `docs: verify milestone three DNS DGA path` and stop without push or merge.
