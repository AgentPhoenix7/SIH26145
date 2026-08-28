# SIH26145 Requirements Traceability

Last verified: **2026-08-28 (UTC)**

Status vocabulary is restricted to `PLANNED`, `IN PROGRESS`, `IMPLEMENTED`, `VERIFIED`, and `DEFERRED`. `VERIFIED` below means current command or inspection evidence exists for the precise row; it does not imply the entire official solution is complete.

## Operational and Prototype Requirements

| Official requirement | Milestone interpretation | Implementation / evidence | Status |
| --- | --- | --- | --- |
| Read-only, unidirectional ingest | Replay must consume a PCAP without any return-path action. | Native `zeek -D -b -r` reads the committed fixture; the policy emits metadata only; e2e replay passes. | VERIFIED |
| No active probing, handshake completion, inline block, or mitigation | Observed addresses remain values and never become destinations or commands. | Runner invokes only local Zeek with an argument vector; policy and detector open no network path; process-boundary tests pass. | VERIFIED |
| No payload decryption | Scan detection must depend only on observable SYN metadata. | `tcp_syn_attempt_v1` contains timestamp, UID, endpoints, ports, and transport; the verified path has no payload or decryption component. | VERIFIED |
| Streaming, not whole-file batch reporting | An alert must be delivered before the Zeek EOS record is accepted. | `test_native_scan_replay_emits_exact_deterministic_evidence_before_eos` passes; direct evidence recorded `order=alert,end_of_stream`. | VERIFIED |
| Bounded alert latency | Operational alerting must have a stated and measured bound. | Incremental callback and flush are implemented, but wall-clock detector/end-to-end latency and P50/P95/P99 are not measured. | PLANNED |
| Bounded and safe state | Windows, deduplication, cooldown, input lines, and child pipes require explicit limits and failure behavior. | Focused unit/integration tests cover named limits, expiry, exact boundaries, the private 64-KiB stderr tail, pre-EOS terminate-to-kill grace, and one absolute post-EOS deadline with no fresh cleanup budget. | VERIFIED |
| Standardized alert schema | Alert includes timestamp, flow ID, class, confidence, and supporting evidence. | One actual CLI line validates as strict `alert_v1` and includes detector, source, protocol, severity, window, and typed scan evidence. | VERIFIED |
| Defined and demonstrated throughput target | State sustained traffic rate and methodology. | No throughput, CPU, memory, or latency benchmark has been run. | PLANNED |
| Working ingest, feature extraction, model inference, and alert prototype | Full prototype must include a genuine deployed model. | Ingest, scan features, heuristic detection, and alert output work; genuine ML training/export/offline inference remains absent. | IN PROGRESS |
| Model/features/training-validation documentation | Preserve shared features, grouped splits, metrics, selection, and limitations. | Scan feature semantics are documented; no model or training evaluation exists yet. | IN PROGRESS |
| Simple live or replay dashboard | Display detections with severity and confidence. | No API or dashboard exists; Bun is reserved for later frontend work. | PLANNED |

## Required Threat Coverage

| Named threat class | Intended method | Evidence | Status |
| --- | --- | --- | --- |
| Volumetric/protocol DDoS: SYN flood, UDP reflection/amplification, spoofed-source characteristics | Rates, ratios, source entropy, and anomaly evidence on the streaming path. | No DDoS detector or controlled DDoS scenario exists. | PLANNED |
| Botnet C2 beaconing | Jitter-tolerant periodicity/inter-arrival analysis. | No C2 events, features, detector, or scenario exists. | PLANNED |
| DGA domains and DNS tunnelling | Passive DNS lexical/statistical features plus genuine supervised ML where supported. | No DNS runtime schema, licensed corpus, model, or tunnelling scenario exists. | PLANNED |
| Encrypted-session malware indicators | Visible TLS/QUIC metadata only, never decrypted payload. | No TLS/QUIC feature or detector exists. | PLANNED |
| Reconnaissance and port scanning | Per-source deduplicated SYN fan-out across destination ports or hosts. | Native vertical/horizontal replay tests, bounded state tests, strict alert validation, and one actual threshold alert pass. | VERIFIED |
| Data exfiltration | Asymmetric flow volume and baseline-aware outbound/inbound behavior. | No byte-volume event, baseline, detector, or controlled scenario exists. | PLANNED |

Current named threat coverage is exactly **1 of 6: reconnaissance/port scanning**.

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
uv run sih26145-replay tests/fixtures/milestone1/vertical_at_threshold.pcap > /tmp/sih26145-scan-alerts.jsonl
uv run sih26145-replay tests/fixtures/milestone1/benign.pcap > /tmp/sih26145-benign-alerts.jsonl
uv run python -c 'from pathlib import Path; from sih26145.contracts.alerts import AlertV1; lines=Path("/tmp/sih26145-scan-alerts.jsonl").read_text().splitlines(); assert len(lines)==1; AlertV1.model_validate_json(lines[0]); assert Path("/tmp/sih26145-benign-alerts.jsonl").read_bytes()==b""'
```

Fresh 2026-08-28 evidence: all 175 tests passed, including the large-epoch microsecond-span regression and 19 native e2e tests; Ruff and mypy passed; fixture check passed; the committed vertical fixture SHA-256 was `1a1a615d3ed57fd929f993057e068daa812d5a19b022a4d7b7355d7892c93266`; native replay processed 20 events and emitted one schema-valid alert; benign output was exactly zero bytes; observed callback order was `alert,end_of_stream`.
