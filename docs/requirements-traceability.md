# SIH26145 Requirements Traceability

Last verified: **2026-08-28 (UTC)**

Status vocabulary is restricted to `PLANNED`, `IN PROGRESS`, `IMPLEMENTED`, `VERIFIED`, and `DEFERRED`. `VERIFIED` below means current command or inspection evidence exists for the precise row; it does not imply the entire official solution is complete.

## Operational and Prototype Requirements

| Official requirement | Milestone interpretation | Implementation / evidence | Status |
| --- | --- | --- | --- |
| Read-only, unidirectional ingest | Replay must consume a PCAP without any return-path action. | Native `zeek -D -b -r` reads the committed fixture; the policy emits metadata only; e2e replay passes. | VERIFIED |
| No active probing, handshake completion, inline block, or mitigation | Observed addresses remain values and never become destinations or commands. | Runner invokes only local Zeek with an argument vector; policy and detector open no network path; process-boundary tests pass. | VERIFIED |
| No payload decryption | Scan and SYN-flood detection must depend only on observable SYN metadata. | `tcp_syn_attempt_v1` contains timestamp, UID, endpoints, ports, and transport; the verified path has no payload or decryption component. | VERIFIED |
| Streaming, not whole-file batch reporting | An alert must be delivered before the Zeek EOS record is accepted, and a stalled record must not block forever. | Native port-scan and SYN-flood replay tests both observe `alert,end_of_stream`; focused integration coverage proves a flushed partial pre-EOS record reaches a named inactivity timeout and the direct child is reaped. | VERIFIED |
| Bounded alert latency | Operational alerting must have a stated and measured bound. | Incremental callback and flush are implemented, but wall-clock detector/end-to-end latency and P50/P95/P99 are not measured. | PLANNED |
| Bounded and safe state | Windows, deduplication, cooldown, input lines, and child pipes require explicit limits and failure behavior. | Focused tests cover the source-keyed scan and target-keyed SYN-flood limits, retry-safe cooldown-capacity rollback, expiry, exact boundaries, finite derived-rate validation, achievable thresholds, window/UID-TTL consistency, the private 64-KiB stderr tail, bounded pre-EOS record inactivity, pre-EOS terminate-to-kill grace, and one absolute post-EOS deadline. | VERIFIED |
| Standardized alert schema | Alert includes timestamp, flow ID, class, confidence, and supporting evidence. | Actual port-scan and SYN-flood CLI lines validate as strict `alert_v1` and include detector, source, protocol, severity, window, thresholds, and typed measured evidence. | VERIFIED |
| Defined and demonstrated throughput target | State sustained traffic rate and methodology. | No throughput, CPU, memory, or latency benchmark has been run. | PLANNED |
| Working ingest, feature extraction, model inference, and alert prototype | Full prototype must include a genuine deployed model. | Ingest, port-scan and SYN-flood features, heuristic detection, and alert output work; genuine ML training/export/offline inference remains absent. | IN PROGRESS |
| Model/features/training-validation documentation | Preserve shared features, grouped splits, metrics, selection, and limitations. | Scan feature semantics are documented; no model or training evaluation exists yet. | IN PROGRESS |
| Simple live or replay dashboard | Display detections with severity and confidence. | No API or dashboard exists; Bun is reserved for later frontend work. | PLANNED |

## Required Threat Coverage

| Named threat class | Intended method | Evidence | Status |
| --- | --- | --- | --- |
| Volumetric/protocol DDoS: SYN flood, UDP reflection/amplification, spoofed-source characteristics | Destination SYN rate, unique-source count, and source entropy on the streaming path. | Native exact-threshold SYN-flood replay emits one typed alert before EOS; 99-event and distributed-benign fixtures emit none. Entropy is distribution evidence, not proof of spoofing. UDP reflection/amplification and stronger spoofed-source inference remain deferred. | IN PROGRESS |
| Botnet C2 beaconing | Jitter-tolerant periodicity/inter-arrival analysis. | No C2 events, features, detector, or scenario exists. | PLANNED |
| DGA domains and DNS tunnelling | Passive DNS lexical/statistical features plus genuine supervised ML where supported. | No DNS runtime schema, licensed corpus, model, or tunnelling scenario exists. | PLANNED |
| Encrypted-session malware indicators | Visible TLS/QUIC metadata only, never decrypted payload. | No TLS/QUIC feature or detector exists. | PLANNED |
| Reconnaissance and port scanning | Per-source deduplicated SYN fan-out across destination ports or hosts. | Native vertical/horizontal replay tests, bounded state tests, strict alert validation, and one actual threshold alert pass. | VERIFIED |
| Data exfiltration | Asymmetric flow volume and baseline-aware outbound/inbound behavior. | No byte-volume event, baseline, detector, or controlled scenario exists. | PLANNED |

Demonstrated detector coverage spans **2 of 6 named classes: reconnaissance/port scanning and the SYN-flood subset of volumetric/protocol DDoS**. The DDoS class is not complete because UDP reflection/amplification is deferred.

## Reproduction Evidence

Run from the repository root with native Zeek resolvable through `PATH`:

```bash
uv sync --frozen --group dev
uv run pytest -m "not e2e" -v
uv run pytest -m e2e -v
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests tools
uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1 --check
uv run python tools/generate_milestone2_fixtures.py --output tests/fixtures/milestone2 --check
uv run sih26145-replay tests/fixtures/milestone1/vertical_at_threshold.pcap > /tmp/sih26145-scan-alerts.jsonl
uv run sih26145-replay tests/fixtures/milestone1/benign.pcap > /tmp/sih26145-benign-alerts.jsonl
uv run sih26145-replay tests/fixtures/milestone2/syn_flood_at_threshold.pcap > /tmp/sih26145-flood-alerts.jsonl
uv run sih26145-replay tests/fixtures/milestone2/syn_flood_below.pcap > /tmp/sih26145-flood-below-alerts.jsonl
uv run sih26145-replay tests/fixtures/milestone2/benign_distributed.pcap > /tmp/sih26145-flood-benign-alerts.jsonl
uv run python -c 'from pathlib import Path; from sih26145.contracts.alerts import AlertV1; scan=Path("/tmp/sih26145-scan-alerts.jsonl").read_text().splitlines(); flood=Path("/tmp/sih26145-flood-alerts.jsonl").read_text().splitlines(); assert len(scan)==len(flood)==1; assert AlertV1.model_validate_json(scan[0]).threat_class=="PORT_SCAN"; assert AlertV1.model_validate_json(flood[0]).threat_class=="SYN_FLOOD"; assert Path("/tmp/sih26145-benign-alerts.jsonl").read_bytes()==Path("/tmp/sih26145-flood-below-alerts.jsonl").read_bytes()==Path("/tmp/sih26145-flood-benign-alerts.jsonl").read_bytes()==b""'
```

Fresh 2026-08-28 Milestone 2 evidence: all 238 tests passed; Ruff lint passed; Ruff confirmed 41 files formatted; strict mypy found no issues in 30 source files; both fixture checks passed. The SYN-flood threshold fixture SHA-256 is `712bb6ea6da09fe4b7cb7af184f00110dc755d32a667e68e2e94cdb08b1be76d`; native replay processed 100 events and emitted one 795-byte schema-valid alert, while the 99-event and distributed-benign outputs were exactly zero bytes. Native callback order was `alert,end_of_stream`. Milestone 1's merged evidence remains preserved in `PROGRESS.md`.
