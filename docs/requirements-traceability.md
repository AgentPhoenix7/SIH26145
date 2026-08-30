# SIH26145 Requirements Traceability

Last verified: **2026-08-30 (UTC)**

Status vocabulary is restricted to `PLANNED`, `IN PROGRESS`, `IMPLEMENTED`, `VERIFIED`, and `DEFERRED`. `VERIFIED` below means current command or inspection evidence exists for the precise row; it does not imply the entire official solution is complete.

## Operational and Prototype Requirements

| Official requirement | Milestone interpretation | Implementation / evidence | Status |
| --- | --- | --- | --- |
| Read-only, unidirectional ingest | Replay must consume a PCAP without any return-path action. | Native `zeek -D -b -r` reads the committed fixture; the policy emits metadata only; e2e replay passes. | VERIFIED |
| No active probing, handshake completion, inline block, or mitigation | Observed addresses and domains remain values and never become destinations or commands. | Runner invokes only local Zeek with an argument vector; socket-disabled DGA inference and process-boundary tests pass; no resolver or enrichment path exists. | VERIFIED |
| No payload decryption | Scan and SYN-flood detection must depend only on observable SYN metadata. | `tcp_syn_attempt_v1` contains timestamp, UID, endpoints, ports, and transport; the verified path has no payload or decryption component. | VERIFIED |
| Streaming, not whole-file batch reporting | An alert must be delivered before the Zeek EOS record is accepted, and a stalled record must not block forever. | Native port-scan, SYN-flood, and DGA replay tests observe `alert,end_of_stream`; focused integration coverage proves mixed SYN/DNS accounting and bounded partial-record failure/cleanup. | VERIFIED |
| Bounded alert latency | Operational alerting must have a stated and measured bound. | `tools/run_benchmark.py` measured post-validation detector-to-emission wall-clock latency (from the start of `DetectionPipeline.process()` through real JSON serialization + write/flush into a real, actively drained OS pipe, not detector time alone) over one 21,431-event deterministic replay producing 51 real alerts: P50 `0.86` ms, P95 `1.02` ms, P99 `1.05` ms (per-metric median across a predefined, unselected batch of 5 consecutive runs; see `docs/evaluation.md` for the full 5-run table, the run-selection-bias fix, and the sample-size caveat on the P95/P99 figures). This excludes the raw JSONL line read and JSON/Pydantic contract validation the frozen, unmodified `run_command` path already performs before that timer starts, so it does not cover the full record-availability-to-alert-availability interval the official requirement states; that remaining segment is not yet separately measured. | IMPLEMENTED |
| Bounded and safe state | Windows, deduplication, cooldown, input lines, child pipes, alert storage, and browser work require explicit limits and failure behavior. | Detector/process limits retain their focused coverage. The local store deeply revalidates model instances, is fixed at 100, and has tested oldest-first eviction and newest-first bounded snapshots. The API caps requested alerts at 100, and the dashboard renders and polls for at most 50. | VERIFIED |
| Standardized alert schema | Alert includes timestamp, flow ID, class, confidence, and supporting evidence. | Actual port-scan, SYN-flood, and DGA CLI lines validate as strict `alert_v1`; DGA evidence includes model/feature versions, threshold, query, and recomputed lexical summaries. | VERIFIED |
| Defined and demonstrated throughput target | State sustained traffic rate and methodology. | Deterministic sustained-load replay (`tools/generate_benchmark_fixture.py`, `tools/run_benchmark.py`) measured `12,600-16,250` events/sec (`5.5-7.1` Mbps, computed from actual traffic bytes, not pcap file size) across a predefined, unselected batch of 5 consecutive runs (median `~14,800` events/sec, `~6.4` Mbps), median combined CPU `2.13` s and median combined peak RSS upper bound `~265.6` MiB (Python component medians `1.33` s CPU / `~138.9` MiB RSS, Zeek component medians `0.78` s CPU / `~126.7` MiB RSS — each computed independently across the 5 runs, so they do not necessarily sum exactly to the combined figures); see `docs/evaluation.md` for full methodology, the complete 5-run table, and scope limitations. | VERIFIED |
| Working ingest, feature extraction, model inference, and alert prototype | Full prototype must include a genuine deployed model. | Native replay emits strict SYN/DNS events; shared `dns_features_v1` feeds packaged `dga_logreg_v1`; local offline inference emits one actual DGA alert. | VERIFIED |
| Model/features/training-validation documentation | Preserve shared features, grouped splits, metrics, selection, and limitations. | Dataset provenance, 140 ordered features, family-disjoint split, held-out precision/recall/F1/FPR, artifact integrity, CPU inference, and limitations are recorded. | VERIFIED |
| Simple live or replay dashboard | Display detections with severity and confidence. | Loopback FastAPI routes run only fixed committed replays through the existing callback path; replay mutation requires a non-safelisted action header, accepts only the loopback Host, and rejects foreign browser Origins. The static dashboard displayed actual `PORT_SCAN`, `SYN_FLOOD`, and `DGA` values, severity, confidence, identity, endpoints/query, and evidence. Desktop and 390-pixel browser inspections found no horizontal/card overflow or console errors. | VERIFIED |

## Required Threat Coverage

| Named threat class | Intended method | Evidence | Status |
| --- | --- | --- | --- |
| Volumetric/protocol DDoS: SYN flood, UDP reflection/amplification, spoofed-source characteristics | Destination SYN rate, unique-source count, and source entropy on the streaming path. | Native exact-threshold SYN-flood replay emits one typed alert before EOS; 99-event and distributed-benign fixtures emit none. Entropy is distribution evidence, not proof of spoofing. UDP reflection/amplification and stronger spoofed-source inference remain deferred. | IN PROGRESS |
| Botnet C2 beaconing | Jitter-tolerant periodicity/inter-arrival analysis. | No C2 events, features, detector, or scenario exists; the dashboard labels it `DEFERRED`. | DEFERRED |
| DGA domains and DNS tunnelling | Passive DNS lexical/statistical features plus genuine supervised ML where supported. | DGA is verified through strict request events, provenance-backed grouped training, packaged offline Logistic Regression, typed evidence, and native benign/DGA replay. DNS tunnelling is not implemented. | IN PROGRESS |
| Encrypted-session malware indicators | Visible TLS/QUIC metadata only, never decrypted payload. | No TLS/QUIC feature or detector exists; the dashboard labels it `DEFERRED`. | DEFERRED |
| Reconnaissance and port scanning | Per-source deduplicated SYN fan-out across destination ports or hosts. | Native vertical/horizontal replay tests, bounded state tests, strict alert validation, and one actual threshold alert pass. | VERIFIED |
| Data exfiltration | Asymmetric flow volume and baseline-aware outbound/inbound behavior. | No byte-volume event, baseline, detector, or controlled scenario exists; the dashboard labels it `DEFERRED`. | DEFERRED |

Demonstrated detector coverage spans **3 of 6 named classes: reconnaissance/port scanning, the SYN-flood subset of volumetric/protocol DDoS, and DGA lexical detection**. DDoS is incomplete because UDP reflection/amplification is deferred; the combined DGA/DNS-tunnelling class is incomplete because tunnelling is deferred.

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
uv run python tools/generate_milestone3_fixtures.py --output tests/fixtures/milestone3 --check
uv run pytest tests/unit/test_alert_store.py tests/integration/test_api.py tests/e2e/test_milestone4.py -v
uv run sih26145-dashboard
uv run sih26145-replay tests/fixtures/milestone1/vertical_at_threshold.pcap > /tmp/sih26145-scan-alerts.jsonl
uv run sih26145-replay tests/fixtures/milestone1/benign.pcap > /tmp/sih26145-benign-alerts.jsonl
uv run sih26145-replay tests/fixtures/milestone2/syn_flood_at_threshold.pcap > /tmp/sih26145-flood-alerts.jsonl
uv run sih26145-replay tests/fixtures/milestone2/syn_flood_below.pcap > /tmp/sih26145-flood-below-alerts.jsonl
uv run sih26145-replay tests/fixtures/milestone2/benign_distributed.pcap > /tmp/sih26145-flood-benign-alerts.jsonl
uv run sih26145-replay tests/fixtures/milestone3/dga_dns.pcap > /tmp/sih26145-dga-alerts.jsonl
uv run sih26145-replay tests/fixtures/milestone3/benign_dns.pcap > /tmp/sih26145-dns-benign-alerts.jsonl
uv run python tools/generate_benchmark_fixture.py --output tests/fixtures/benchmark
uv run python tools/run_benchmark.py --pcap tests/fixtures/benchmark/sustained_load.pcap
```

The benchmark fixture is not committed, so it is generated without `--check` (which requires the file to already exist); rerunning the same command afterward with `--check` appended proves byte-determinism.

Milestone 3 measured evidence: artifact SHA-256 `0627eea04dec557ccf4e6ab2382b6d1e432380bcfa140908dd0da68798e03f47`, precision `0.7188`, recall `0.2513`, F1 `0.3724`, and FPR `0.0722`. Native synthetic replay processed one DNS event and emitted one 987-byte schema-valid DGA alert with probability `0.9999563398163442` before EOS; native `example.com` replay emitted exactly zero bytes. Milestones 1 and 2 evidence remains preserved in `PROGRESS.md`.

Milestone 5 measured evidence: full method, per-run table (5 runs), and scope limitations are recorded in `docs/evaluation.md`.
