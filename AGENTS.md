# SIH26145 Repository Instructions

These instructions apply to the entire repository. System instructions and the user's current request always take precedence.

## Mission and Deadline

Build the smallest technically credible, end-to-end Smart India Hackathon 2026 MVP for `SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic`.

The user-imposed MVP and PPT deadline is **2026-09-01** (extended from the original 2026-08-31 by explicit user instruction on 2026-08-30), even if an official page displays a later idea-submission deadline. Treat **2026-08-31 as feature freeze**. Reserve 2026-09-01 for final verification, demo rehearsal, submission-blocking fixes, screenshots, documentation, PPT work, and packaging. Do not schedule experimental features for the final day.

Optimize every decision for a working, demonstrable, measurable, explainable, reproducible, and defensible MVP. This is not an enterprise NDR/IDS project. Do not generate the whole system blindly or add speculative infrastructure.

Milestone 1 port-scan detection is **VERIFIED, MERGED into `main` at `459924c3b699a011c06192f526786acd7a5318ea`, and FROZEN**. Preserve its evidence and do not redesign it unless later integration exposes a real regression or compliance defect.

## Deadline Execution Priority

Use this order when deciding what to do before feature freeze:

1. Official SIH26145 compliance.
2. Finish the submission-ready MVP by 2026-09-01.
3. Protect the 2026-08-31 feature freeze.
4. Complete the Tier-1 end-to-end pipeline.
5. Keep `PROGRESS.md` current.
6. Integrate genuine ML.
7. Correctness.
8. Streaming behavior.
9. Bounded state.
10. Evidence-bearing alerts.
11. Verification.
12. End-to-end demo reliability.
13. Measured benchmark.
14. Documentation and PPT evidence.
15. Minimize implementation time.
16. Minimize Codex usage.
17. Additional threat coverage.
18. Refactoring.
19. Architectural sophistication.
20. Experimental sophistication.

## Sources of Truth

Use this order when repository documents disagree:

1. The user's current explicit instructions.
2. The official problem statement in `docs/problem.md`.
3. Durable repository rules in this `AGENTS.md`.
4. Confirmed current state and decisions in `PROGRESS.md`.
5. Supporting research and other documentation.

Never weaken, omit, or silently reinterpret an official requirement for convenience. If compliance is difficult, identify the exact requirement, explain the constraint, compare compliant alternatives, choose the simplest compliant option, and document remaining limitations. Never claim unfinished behavior works or invent data, metrics, screenshots, or results.

## Starting or Resuming Work

At the beginning of every new conversation or implementation slice:

1. Print/confirm the working directory.
2. Read this file completely.
3. Read `docs/problem.md`, `PROGRESS.md`, and `docs/architecture.md` completely.
4. Inspect `git status`, relevant diffs, and recent commits.
5. Read the relevant source, tests, and supporting docs before proposing edits.
6. Verify drift-prone environment facts when they matter; do not trust an old progress snapshot blindly.
7. Continue the current highest-priority milestone instead of restarting or broadening the project.

Preserve unrelated or user-authored changes. Do not overwrite, revert, or delete them. Never push to a remote unless the user explicitly requests it.

## Milestone Branch and Worktree Policy

Every implementation milestone must use a new focused branch and a new linked worktree. Do not implement a new milestone directly on `main`, reuse a previous milestone branch, or reuse a previous milestone worktree.

Before milestone implementation begins:

1. Ensure the intended handoff and policy changes are committed on `main`; never create the milestone branch from a stale commit while required baseline changes remain only in the working tree.
2. Confirm `main` is the intended base and inspect its status, diff, and recent commits.
3. Verify `.worktrees/` is ignored by Git.
4. Create `feature/milestone-<number>-<slug>` with linked worktree `.worktrees/milestone-<number>-<slug>` from the updated `main` baseline.
5. Enter that worktree, synchronize the locked environment, and run the normal baseline verification suite before implementation.
6. Record the active branch, worktree path, base commit, and verification result in `PROGRESS.md`.

Keep one milestone per branch/worktree. After verification and merge, freeze that milestone and treat its branch/worktree as historical; the next milestone receives a fresh branch/worktree. Any exception requires the user's explicit current instruction.

## Non-Negotiable Operational Invariants

### Passive, read-only ingest

The detector consumes passive observations only. It must not:

- communicate back through the ingest path;
- probe or connect to observed hosts, IP addresses, or domains;
- initiate or complete handshakes toward observed endpoints;
- inject, modify, reset, or block traffic; or
- issue mitigation commands through the monitored path.

Treat observed addresses and domains as untrusted data, never as destinations. Network access used for development dependencies or model artifacts must be separate from observed traffic and must never be derived from observed values.

### No payload decryption

Do not introduce TLS interception, MITM proxies, certificate replacement, endpoint plaintext agents, private-key decryption, or any encryption bypass. TLS/QUIC detection may use only metadata that is legitimately visible in the capture, such as protocol versions, fingerprints, observable SNI/ALPN, packet-size/direction sequences, timing, counts, and duration. Verify feature observability before depending on it; modern TLS, QUIC, ECH, and encrypted DNS may hide fields.

### Streaming behavior

The operational path must process events incrementally and raise alerts with bounded latency. A whole-file PCAP report is not sufficient.

The approved MVP demonstration input is **deterministic incremental PCAP replay**. Live-interface capture is deferred until the replay pipeline is verified. Replay and future live ingest must feed the same event, rolling-state, feature, detector, and alert path. Avoid separate batch-only inference logic.

### Bounded and safe state

Traffic is untrusted. Validate malformed/missing fields, invalid addresses and domains, impossible timestamps, and extreme numeric values at the input boundary. Rolling state must have explicit time windows, expiry/cleanup, and sensible cardinality limits. No dictionary, queue, alert buffer, or per-host state may grow without a bound. Preserve deterministic behavior for replay.

### Evidence-first alerts

Every alert must answer why it fired using actual measured values. The common alert schema must include at least:

- timestamp;
- flow identifier;
- threat class;
- confidence; and
- supporting evidence.

Prefer source, destination, protocol, severity, detector, model version, and observation window when applicable. Validate confidence to `[0, 1]`. Never use example numbers as measured output.

## Official Threat Coverage and Deadline Tiers

The official problem requires all six threat classes:

1. Volumetric/protocol DDoS, including SYN floods, UDP reflection or amplification, and spoofed-source characteristics.
2. Botnet C2 beaconing using periodicity/inter-arrival behavior with realistic jitter.
3. DGA domains and DNS tunnelling.
4. Malware indicators in encrypted TLS/QUIC sessions using metadata only.
5. Reconnaissance and port scanning.
6. Data exfiltration using asymmetric volume and behavioral anomalies.

The official scope remains unchanged, but the remaining implementation order is deadline-driven:

- **Tier 1 — feature-freeze gate:** verified port scan; streaming SYN/DDoS; a provenance-recorded DNS/DGA dataset; one genuinely trained, evaluated, persisted, and locally integrated DNS/DGA model; standard alerts; minimal API; bounded alert storage; minimal dashboard; reproducible end-to-end demo; streaming proof; benchmark; synchronized documentation and PPT evidence.
- **Tier 2:** data exfiltration, only after every Tier-1 gate is safe.
- **Tier 3:** C2 beaconing, TLS/QUIC malware metadata, advanced DNS tunnelling, flow-export ingest, advanced UI/ML, and production infrastructure.

This changes execution priority, not the official problem statement. Label every unimplemented class `DEFERRED`, `FUTURE WORK`, or `NOT IMPLEMENTED`; never imply full threat coverage. A complete port-scan + streaming-DDoS + DNS/DGA-ML prototype is preferable to six incomplete detectors.

## Target Architecture

Start with the narrowest complete path:

```text
PCAP replay
  -> Zeek
  -> incremental structured events
  -> Python event processor
  -> bounded sliding windows
  -> scan features and detector
  -> validated evidence-bearing alert
```

The intended complete MVP path is:

```text
Passive traffic / deterministic PCAP replay
  -> protocol and flow parsing (prefer Zeek)
  -> versioned structured events
  -> streaming feature engine and bounded state
  -> statistical + behavioral + ML detectors
  -> common alert engine
  -> local API
  -> simple dashboard
```

Use the package-managed native Zeek 8.2.2 installation for PCAP replay. The
binary is `/opt/zeek/bin/zeek`, and `/opt/zeek/bin` is configured in the user's
zsh `PATH`. Invoke `zeek` through `PATH` in project commands rather than
hard-coding the absolute path. Do not add a Zeek container or install another
Zeek version unless the verified native installation becomes incompatible. A
simpler parser may replace Zeek only after explaining how it remains compliant
and why the change materially reduces delivery risk.

Keep components focused and testable. Do not create empty directories or interfaces with only one imagined implementation. Add a dependency, service, configuration surface, or abstraction only when required behavior or lifecycle cost justifies it.

## Hybrid Detection and ML Rules

Do not force all threats through one model. Prefer:

- scan: sliding-window fan-out behavior;
- DDoS: rates, ratios, entropy, and anomaly detection;
- DGA: supervised lexical ML;
- DNS tunnelling: statistics plus ML where evidence supports it;
- C2: timing/periodicity with jitter tolerance;
- exfiltration: volume asymmetry plus host/destination baselines; and
- encrypted malware: TLS/QUIC metadata ML only if time and data support it.

At least one model must be genuinely trained, validated, tested, exported, and used by local MVP inference. Prefer DGA/DNS unless dataset research shows a more practical target. Establish simple baselines before complex models. Engineered tabular features favor Logistic Regression, Random Forest, or XGBoost; use PyTorch only when data and evidence justify sequence learning.

Model selection must consider precision, recall, F1, false-positive rate, PR-AUC/ROC-AUC where useful, inference latency, throughput, model size, explainability, runtime dependencies, and training complexity. Do not select a model by accuracy alone. Preserve feature importance or other understandable evidence where practical.

### Training/runtime parity

Every deployed feature must be reproduced by the passive runtime pipeline from the same versioned definition. Use shared, versioned schemas such as `connection_event_v1`, `dns_event_v1`, `flow_features_v1`, and `alert_v1`. Never train on convenient columns that local inference cannot calculate.

Avoid leakage: split by PCAP, scenario/run, DGA or malware family, source host, or time as appropriate. Traffic from one generated run must not leak across train and test sets.

### Kaggle, CUDA, and Hugging Face

- Use CUDA only when it materially improves training; measure rather than assuming it helps.
- Use Kaggle primarily as temporary training compute, not durable storage.
- Persist valuable checkpoints/models, feature schemas, configs, and honest evaluation metadata to Hugging Face Hub.
- Never hard-code or print Hugging Face/Kaggle tokens. Use secrets or environment variables and document only variable names.
- Use the native model artifact format. Do not force `.pt` for non-PyTorch models.
- If PyTorch is used, maintain resumable `last.pt` and validation-selected `best.pt`, including optimizer/scheduler state and schema/config metadata.
- Upload recoverable state periodically at an appropriate cadence and support automatic resume where the framework permits it.
- Download the final model before the demo. Runtime inference must work locally without Internet and must not call Hugging Face per event.
- Benchmark CPU inference; do not require GPU inference unless measurements prove it necessary.

Never insert fake model names, versions, devices, datasets, or metrics into metadata. Record actual measured values only.

Keep training notebooks reproducible and split into understandable sections, not one giant cell. Include, when applicable: environment setup; configuration; CUDA detection; secure Hugging Face authentication; remote-checkpoint/resume detection; dataset loading; data-quality checks; feature extraction; grouped train/validation/test splitting; baseline and candidate models; training; validation; periodic checkpoint upload; final test evaluation; error analysis; model selection; final artifact upload; and an example using the exact exported inference path. A Kaggle restart should automatically download and resume from the strongest practical remote checkpoint when one exists.

## Dataset and Lab Safety

`docs/dataset-research.md` records the current official-resource finding. As of 2026-08-26, no downloadable official SIH26145 dataset was found; the official field contains truncated generation guidance, and an SIH-hosted 2024 drone PDF is unrelated.

Before importing any dataset or list:

1. verify its source and relation to SIH26145;
2. record licence and usage restrictions;
3. inspect formats and threat coverage;
4. check training/runtime feature parity; and
5. record limitations and bias.

Generate attack/suspicious traffic only inside an isolated environment under our control: isolated Docker networks, network namespaces, local VMs, or a dedicated local lab. Never target the public Internet, university networks, production systems, third parties, or any system without explicit authorization. Resolve exact endpoints before running a generator.

Record scenario ground truth before or during generation: dataset/scenario ID, class, generator, UTC start/end, endpoints, parameters, capture filename, duration/configuration, provenance, and notes. Keep large PCAPs, datasets, models, credentials, caches, and virtual environments out of Git. Commit small fixtures, manifests, schemas, and reproducible commands.

## Technology Direction

Prefer the following when they remain the simplest compliant choice:

- Python 3.12+ with `uv` and `pyproject.toml`;
- Zeek for passive protocol/flow analysis;
- Pydantic and FastAPI for schemas/API;
- NumPy, scikit-learn, and XGBoost for tabular ML;
- PyTorch only when justified;
- React, TypeScript, and Tailwind for the dashboard; and
- Bun for frontend dependency management and scripts; and
- pytest, Ruff, type hints, and structured logging for quality.

Use Bun commands and `bun.lock` for frontend work. Do not introduce npm, pnpm, Yarn, `package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock` unless the user explicitly changes this decision or a verified Bun incompatibility requires a documented exception.

If a simpler dashboard materially improves delivery probability, discuss and record the decision before changing direction. Avoid Kafka, Kubernetes, microservices, service meshes, complex authentication, cloud deployment, production SOC integrations, elaborate CI/CD, unnecessary databases, and large neural networks before submission.

Thresholds that reflect deployment behavior must be configurable and documented. Fixed protocol/schema invariants should remain code-owned rather than becoming unnecessary configuration.

## Usage and Approval Controls

After the initial mandatory context read, inspect only files relevant to the current milestone. Prefer targeted reads, existing abstractions, small diffs, focused tests, and actual execution. Avoid repeated repository-wide exploration, historical Milestone 1 re-audits, giant speculative plans, cosmetic refactors, and optional-feature investigation.

Do not implement multiple major milestones automatically. Default to inspect, plan the current milestone, report, and stop. After explicit approval, implement, test, verify, synchronize affected documentation and `PROGRESS.md`, report, and stop. Routine handoff maintenance, required backups, and formatting caused by the current edit do not need a separate approval cycle.

## Incremental Engineering Workflow

For each meaningful slice:

1. Inspect the repository and Git state.
2. Name the exact SIH requirement and immediate observable objective.
3. Trace the event/data flow and identify the layer that owns each invariant.
4. Briefly explain the proposed design, alternatives, and limitations.
5. Implement the smallest complete path, preferably test-first.
6. Run focused tests and confirm failures before fixes where applicable.
7. Run lint/type checks appropriate to the changed code.
8. Execute the real feature path and inspect actual output.
9. Fix root causes; add regression tests for useful failures.
10. Update requirements traceability and `PROGRESS.md` after a meaningful milestone.
11. Preserve PPT-ready evidence in `docs/ppt-notes.md` when results become available.
12. Report material changes, exact proof commands, unresolved risks, and the next highest-priority step.

Do not claim a build, test, detector, model, benchmark, or demo passes unless the exact relevant command ran successfully. Distinguish confirmed behavior, assumptions, and untested claims.

Use `git status` before substantial work. Keep changes logically scoped and do not include unrelated work in commits. Never push without an explicit request.

## Milestone Freeze Rule

Milestone 1's historical acceptance evidence remains in `PROGRESS.md`; do not put it back on the critical path. For each new milestone, stop polishing once the minimum implementation, focused tests, attack and benign observations, integration, SIH compliance, documentation, `PROGRESS.md`, and PPT evidence are verified. Merge and freeze it, then create a fresh branch/worktree for the next Tier-1 blocker.

## Performance, Documentation, and Submission Evidence

Before submission, define and measure a practical target using relevant units: Mbps, packets/sec, flows/sec, or events/sec. Measure detector and end-to-end alert latency (including P50/P95/P99 where practical), CPU, and memory. Record hardware, WSL/software versions, PCAP/scenario, replay configuration, detector configuration, and methodology. Never fabricate throughput.

Maintain these documents as the corresponding work begins:

- `docs/requirements-traceability.md`: official requirement, interpretation, implementation, honest status, verification command, and evidence.
- `docs/features.md`: versioned feature definitions and observability.
- `docs/evaluation.md`: split strategy, metrics, benchmarks, and error analysis.
- `docs/limitations.md`: quantified limitations and mitigations.
- `docs/ppt-notes.md`: architecture, methods, screenshots, alerts, metrics, innovations, limitations, and talking points.

Use only `PLANNED`, `IN PROGRESS`, `IMPLEMENTED`, `VERIFIED`, or `DEFERRED` in traceability. `VERIFIED` requires current evidence.

After meaningful milestones, include an honest SIH26145 compliance snapshot covering passive ingest, active probing, decryption, streaming, alert latency, alert schema/evidence, dataset research/provenance, ML training/storage/resume, offline inference, threat coverage, throughput, demo reproducibility, and PPT evidence.

## Environment and Installation Safety

Inspect tool availability before installation. Use repository `uv`/Make/Bun targets once they exist. Do not modify unrelated WSL configuration.

If root privileges are required, first show the exact command, why it is needed, and what it changes. If sandbox restrictions cause Docker, GPU, or local-network failures, verify outside the restricted sandbox before diagnosing application logic. Never expose secrets in commands, logs, examples, or Git.

## Mentoring and Decision Records

Teach while building without delaying delivery. For important components, briefly preserve:

1. what it does;
2. why it is needed;
3. why this approach was selected;
4. credible alternatives;
5. limitations; and
6. the SIH requirement it satisfies.

Keep `PROGRESS.md` factual and current. Update it after meaningful milestones, new verified environment facts, decisions, blockers, or changes to the ordered next steps. New conversations must be able to continue from it without relying on hidden chat context.

Preserve concise, evidence-backed answers for judge questions, especially: why Zeek rather than Suricata or a custom parser; why hybrid detection; what the genuine ML component is; why the selected model/CUDA path was appropriate; how passive operation and no-return-path safety are enforced; what remains visible under TLS 1.3/QUIC; how jitter and false positives are handled; how confidence is calculated; dataset provenance and leakage prevention; Kaggle versus Hugging Face responsibilities; checkpoint resume; offline inference; and the measured throughput and P95 alert latency.
