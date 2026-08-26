# SIH26145 Progress and Conversation Handoff

Last updated: **2026-08-26 (UTC)**

## Purpose

This is the factual handoff for new conversations. It records confirmed state, decisions, evidence, current gaps, and ordered next steps. Read `AGENTS.md`, `docs/problem.md`, and this file before acting. Re-check live Git and environment state because this snapshot can become stale.

## Current Phase

**Foundation / pre-implementation research and architecture.**

Environment inspection and official dataset-resource research are complete. The first implementation target remains Milestone 1:

```text
deterministic PCAP replay
  -> Zeek
  -> incremental structured connection events
  -> Python processor
  -> bounded sliding scan window
  -> validated evidence-bearing PORT_SCAN alert
```

No detector code, project scaffold, dependency manifest, tests, model, API, or dashboard exists yet.

## Authoritative Context

- Official problem statement: `docs/problem.md`
- Dataset/resource research: `docs/dataset-research.md`
- Repository-wide operating rules: `AGENTS.md`
- Repository: `/home/agntdrgn/WorkSpace/SIH26145`
- Git branch: `main`
- Current base commit: `e1b47ac` (`Add initial AGENTS and PROGRESS documentation for SIH26145 project`)
- Remote: `git@github.com:AgentPhoenix7/SIH26145.git`

The official problem requires:

- passive one-directional/read-only ingest;
- no active probing or return-path dependency;
- no TLS/QUIC payload decryption;
- incremental processing with bounded alert latency;
- detection of all six named threat classes;
- at least ingest, feature extraction, model inference, alerts, documentation, and a simple live-or-replay dashboard;
- standardized alerts with timestamp, flow ID, threat class, confidence, and supporting evidence; and
- a stated and demonstrated throughput target.

## Deadline and Scope Decisions

- User-imposed MVP and PPT deadline: **2026-08-31**.
- Feature freeze: **2026-08-30**.
- 2026-08-31 is reserved for verification, rehearsal, screenshots, documentation, PPT, packaging, and submission-blocking fixes.
- The live official page was observed to show an idea-submission deadline of 2026-09-20. The project continues to use the user's earlier 2026-08-31 delivery deadline.
- Primary MVP demonstration input: **deterministic incremental PCAP replay**.
- Live-interface capture: **deferred until replay is verified**.
- Replay and future live ingest must share the same event/feature/detector path.
- Native package-managed Zeek 8.2.2 is the selected parser for PCAP replay. `/opt/zeek/bin` is configured in the user's zsh `PATH`.
- Frontend dependency management and scripts will use **Bun**, not npm.
- The MVP is a hybrid statistical/behavioral/ML system, not a single-model IDS.
- At least one genuine trained/deployed model is required; DGA/DNS remains the preferred first ML target unless data research proves another target better.
- No project dependencies have been installed. The user added `/opt/zeek/bin` to zsh `PATH` so the existing Zeek package is discoverable.

## Repository State

Files currently present or being added:

- `README.md`: one-line project title only.
- `AGENTS.md`: durable repository instructions.
- `PROGRESS.md`: this handoff.
- `docs/problem.md`: user-provided official problem statement.
- `docs/dataset-research.md`: completed initial dataset/external-resource research.

There is no `pyproject.toml`, lockfile, source tree, test tree, Docker/Compose configuration, sample PCAP, model artifact, or frontend yet. Do not infer that any feature works.

At final verification for this update, `AGENTS.md` and `PROGRESS.md` were tracked and modified, while `docs/architecture.md` was new and untracked. Inspect current `git status` before continuing because the user may commit or edit these files between conversations.

## Confirmed Environment Snapshot

These facts were directly checked on 2026-08-26:

| Component | Confirmed state |
| --- | --- |
| Distribution | Ubuntu 26.04 LTS (`resolute`) under WSL2 |
| Kernel | `6.18.33.2-microsoft-standard-WSL2` |
| CPU | Intel Core i7-11800H, 8 cores / 16 logical CPUs |
| RAM | 7.6 GiB total, approximately 5.4 GiB available at inspection |
| Workspace disk | ext4, approximately 927 GiB available at inspection |
| Python | 3.13.15 at `/home/agntdrgn/.local/bin/python3` |
| uv | 0.12.5 |
| Git | 2.53.0 |
| Docker CLI/daemon | 29.7.2, daemon verified usable outside managed sandbox |
| Docker Compose | 5.5.0 |
| TShark | 4.6.4 |
| Zeek | 8.2.2 installed by the package manager at `/opt/zeek/bin/zeek`; interactive zsh resolves `zeek` through `PATH` |
| NVIDIA GPU | GeForce RTX 3050 Laptop GPU, 4 GiB VRAM, driver 610.62 |
| CUDA toolkit/NVCC | CUDA toolkit 13.3.1 installed; NVCC 13.3.73; CUDA libraries registered with `ldconfig`; `/usr/local/cuda/bin` is configured in the user's zsh `PATH` |
| Bun | 1.4.0 at `/home/agntdrgn/.bun/bin/bun`; selected for frontend dependencies and scripts |
| Node/npm | not installed and not selected for this project |
| Python PCAP libraries | Scapy, dpkt, and PyShark not installed |
| Other checked CLI tools | `openssl` and `ip` present; `tcpdump`, `dumpcap`, `capinfos`, `mergecap`, `editcap`, `jq`, `curl`, `wget`, `make`, `gcc`, and `g++` were not found in the inspected PATH |

Managed-sandbox caveats:

- Docker initially returned permission denied because the sandbox remapped the socket ownership/groups. An approved read-only check outside the sandbox confirmed a healthy Docker 29.7.2 daemon using `overlayfs`, 16 CPUs, and about 8.17 GB memory.
- `nvidia-smi` was blocked inside the sandbox. An approved check outside it confirmed the RTX 3050. Treat future Docker/GPU permission failures as possible sandbox constraints before blaming application logic.

## Completed Work and Evidence

### 2026-08-26 — repository and environment inspection

Completed:

- Confirmed working directory and Git repository.
- Confirmed only the initial README existed in committed history.
- Inspected OS, kernel, CPU, RAM, disk, Python, uv, Git, Docker/Compose, Zeek, TShark, GPU/CUDA, Bun, Node/npm, build tools, and relevant packet libraries.
- Verified Docker daemon and GPU availability outside the restricted sandbox.
- Confirmed the package-managed Zeek 8.2.2 installation and verified the user's zsh `PATH` entry for `/opt/zeek/bin`.
- Confirmed the installed CUDA toolkit packages (`cuda-toolkit` 13.3.1) and NVCC 13.3.73 at `/usr/local/cuda/bin/nvcc`. The user then requested adding `/usr/local/cuda/bin` to zsh `PATH`; a fresh interactive shell resolves `nvcc` through that entry.

No project dependency was installed during this work. Zeek and CUDA were already package-managed host tools; the user added the Zeek binary directory to their zsh `PATH`.

### 2026-08-26 — official dataset/external-resource research

Completed and recorded in `docs/dataset-research.md`:

- Fetched and inspected the exact SIH26145 record from <https://sih.gov.in/sih2026PS>.
- Confirmed the official `Dataset Link` field contains truncated synthetic/lab generation guidance rather than a valid downloadable artifact.
- Inspected raw HTML and confirmed the page renders that guidance as a malformed `href`, not a real external resource URL.
- Rejected <https://sih.gov.in/dataset/Data_set.pdf> as unrelated SIH 2024 SVAMITVA drone `.tif`/`.shp` data.
- Determined that no official PCAP, flow records, CSV, schema, labels, domain lists, or dataset-specific licence are currently provided.
- Recommended controlled labelled lab captures plus separately licensed public sources, with scenario-level provenance and shared runtime/training feature definitions.

The unrelated PDF was downloaded only to `/tmp` for inspection and was not added to Git. No traffic generator ran and no dataset was imported.

### 2026-08-26 — architecture decision

The user approved deterministic incremental PCAP replay as the primary MVP demonstration input. Live capture is deferred until the replay pipeline is verified.

The user also approved the native-Zeek stdout JSONL design for Milestone 1. `docs/architecture.md` now defines the event and EOS schemas, subprocess and failure behavior, strict capture-time ordering, bounded scan state, initial thresholds, cooldown, confidence/severity calculation, alert schema, passive security boundary, generated-fixture provenance, and verification strategy.

A read-only Zeek 8.2.2 probe against the installed `nmap-vsn.pcap` confirmed that `connection_SYN_packet` with `pkt$is_orig` emits 17 immediate SYN events and that a `zeek_done` handler emits after them. This verifies the proposed Zeek event mechanism only; it is not a project end-to-end test or a dataset selection. The installed PCAP remains unsuitable as a committed fixture because it is below the initial fan-out thresholds and redistribution provenance has not been established.

## Current SIH26145 Compliance Snapshot

Do not upgrade any status without current evidence.

```text
Read-only ingest:             NOT TESTED
No active probing:            NOT TESTED
No payload decryption:        NOT APPLICABLE YET
Streaming processing:         NOT TESTED
Bounded alert latency:        NOT TESTED
Structured alerts:            NOT TESTED
Supporting evidence:          NOT TESTED
Official dataset checked:     YES
Dataset provenance recorded:  NO DATASET YET
ML model trained:             NO
Model persisted safely:       NO
Training resumable:           NOT APPLICABLE YET
Offline inference:            NOT TESTED
Threat coverage:              0 / 6
Throughput measured:          NO
Demo reproducible:            NO
PPT evidence captured:        NO
```

## Immediate Next Objective

Review and then plan implementation of only Milestone 1 using the verified native Zeek 8.2.2 installation. The approved design is recorded in `docs/architecture.md`:

1. A small Zeek policy handles originator `connection_SYN_packet` events and emits versioned JSON Lines immediately as packets are processed.
2. Python validates each line, owns bounded sliding-window state, deduplicates retransmitted SYNs by Zeek flow UID, and produces evidence-bearing alerts.
3. An explicit end-of-stream record proves scan alerts are emitted before PCAP completion rather than being derived from a completed `conn.log`.

No Zeek package, image, CUDA package, or sudo action is needed. CUDA is not required for Milestone 1.

## Milestone 1 Acceptance Conditions

Milestone 1 is complete only when all are true:

- [ ] A deterministic PCAP passes through Zeek.
- [ ] Zeek produces structured connection events.
- [ ] Python consumes those events incrementally rather than loading an entire finished report.
- [ ] Rolling scan state tracks source IP, destination hosts/ports, SYN count, attempt rate, and observation window.
- [ ] State expires and has explicit cardinality/resource bounds.
- [ ] Configurable scan thresholds exist.
- [ ] Controlled scan traffic raises a validated `PORT_SCAN` alert.
- [ ] A benign fixture does not trivially raise the same alert.
- [ ] The common alert schema includes timestamp, flow ID, threat class, confidence, severity, detector/version, window, and actual evidence.
- [ ] Important parsing, expiry, threshold, and alert-validation behavior has focused tests.
- [ ] The end-to-end replay command is reproducible.
- [ ] Requirements traceability and this file are updated with exact evidence.

After these conditions are sufficiently reliable, move directly to SYN/DDoS rather than polishing scan detection indefinitely.

## Ordered MVP Work

This is an execution order, not a claim that later work is designed or complete.

### MVP NOW

1. **Milestone 1 design review:** review `docs/architecture.md`; do not scaffold until its schemas, thresholds, failure behavior, and verification approach are accepted.
2. **Milestone 1 implementation plan:** translate the approved design into small test-first tasks with exact files, commands, and verification.
3. **Foundation with first vertical slice:** add only the Python/uv structure, dependencies, configuration, tests, and documentation required by Milestone 1; avoid empty future directories.
4. **Reproducible fixtures/lab:** create or obtain tiny benign and scan PCAPs safely; record scenario manifests and provenance; keep large captures out of Git.
5. **SYN/DDoS:** extend the proven event/window path with rates, ratios, and source/destination entropy; add benign and attack evidence.
6. **DNS feature parity and data:** add versioned passive DNS events/features; identify licensed benign/DGA sources; generate DNS-tunnelling scenarios; split by scenario/family.
7. **Genuine ML:** train and compare a baseline plus a practical tree model; evaluate honestly; export the selected model and schema; integrate and benchmark offline local inference with evidence.
8. **Exfiltration:** implement outbound/inbound asymmetry and baseline-aware evidence using controlled scenarios.
9. **C2 beaconing:** add jitter-tolerant inter-arrival/periodicity detection if core paths are stable.
10. **API/dashboard:** expose validated alerts and provide the simplest reliable replay visualization with threat, severity, confidence, evidence, and time.
11. **End-to-end evaluation:** measure false positives, throughput, events/flows per second, alert latency, CPU, memory, and model inference on documented hardware/configuration.
12. **Feature freeze:** stabilize the demo, capture screenshots/plots, finish traceability, limitations, README, PPT notes, and rehearsal steps.

## Deadline Schedule

The original delivery schedule remains the planning baseline, but current evidence and blockers take precedence over pretending a calendar item is done:

- **2026-08-26 — foundation:** inspection, resource research, architecture, Zeek-to-Python replay, structured alerts, and first scan detector. Inspection and resource research are complete; the architecture is documented and awaits written-spec review, while implementation remains.
- **2026-08-27 — core detection/data:** stabilize bounded streaming state; complete scan and SYN-flood detection; add UDP-flood coverage if practical; establish controlled dataset generation/import and DNS training data.
- **2026-08-28 — ML:** finalize DNS/DGA data and grouped splits; train and compare practical models; use CUDA only when beneficial; persist artifacts to Hugging Face; integrate and benchmark offline local inference.
- **2026-08-29 — exfiltration/C2/dashboard:** implement exfiltration, add C2 if core paths are stable, build the simplest reliable dashboard, and exercise a complete replay demo. Attempt TLS/QUIC metadata coverage only if the core MVP is stable.
- **2026-08-30 — feature freeze:** no major features; benchmark, evaluate false positives, fix bugs, stabilize/rehearse the demo, capture evidence, and finish README/docs/PPT.
- **2026-08-31 — submission:** verification and submission-blocking fixes only; final rehearsal, screenshots, README, PPT, and package.

### POST-SUBMISSION OR STRETCH ONLY

- Live-interface capture after replay is verified.
- TLS/QUIC encrypted-malware metadata detector unless core requirements are already stable and an honest dataset/feature path exists.
- FUSE, inline enforcement, mitigation, production SOC integrations, cloud deployment, Kafka, Kubernetes, service meshes, complex authentication, distributed microservices, or enterprise-scale tuning.

Inline enforcement, active probing, payload decryption, and return-path actions are not merely deferred; they are out of scope and violate the problem.

## Open Decisions and Risks

- **Zeek event streaming:** the stdout JSONL mechanism is designed but not yet implemented or tested in the project.
- **Dataset:** no official artifact exists; every supplemental source needs licence/provenance review.
- **Threat coverage:** encrypted-session coverage has no explicit official generator and is the highest deadline risk.
- **ML:** DGA corpus and benign-domain source are not selected; no measured model feasibility or metrics exist.
- **Dashboard:** React/TypeScript with Bun is preferred. A simpler UI may still be appropriate if it materially protects the deadline, after discussion.
- **Resources:** only about 7.6 GiB WSL RAM and 4 GiB GPU VRAM were observed; avoid large local training workloads.
- **Benchmark:** no throughput or latency target has been selected or measured.
- **Official source:** re-check the SIH26145 dataset field before feature freeze in case the malformed/truncated resource is corrected.

## Documentation Still Needed

Create these only when the corresponding work begins; do not add empty files:

- `docs/features.md`
- `docs/requirements-traceability.md`
- `docs/evaluation.md`
- `docs/limitations.md`
- `docs/ppt-notes.md`
- reproducible dataset manifests under a minimal `data/` or `data_generation/` structure

## Handoff Checklist for Every New Conversation

1. Confirm the repository path.
2. Read `AGENTS.md`, `docs/problem.md`, and `PROGRESS.md` completely.
3. Inspect current `git status`, diffs, recent commits, source, and tests.
4. Treat this file as a snapshot and verify any environment fact needed now.
5. State the immediate requirement and smallest complete objective before editing.
6. Do not install tools, generate attack traffic, download large data, train a model, commit, or push based only on this handoff; first inspect exact scope, safety, and current user authorization.
7. After meaningful work, update confirmed state, evidence commands, compliance status, decisions, blockers, and ordered next steps here.
