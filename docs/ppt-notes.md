# PPT Evidence Notes

Last verified: **2026-08-27 (UTC)**

These are presentation-ready facts for Milestone 1. No screenshot, performance measurement, model metric, or dashboard is claimed here.

## Verified Demo Story

```text
deterministic IPv4 PCAP replay
  -> native Zeek 8.2.2 originator-SYN policy
  -> flushed tcp_syn_attempt_v1 JSON Lines
  -> strict Python validation
  -> bounded capture-time fan-out window
  -> port_scan_window 1.0.0
  -> strict alert_v1 JSON Line
```

The detector is passive and local: it reads a PCAP, does not contact observed endpoints, does not complete handshakes, and does not decrypt payloads. The scan alert callback was observed before the end-of-stream record, demonstrating incremental detection rather than a post-run `conn.log` report.

## Actual Threshold Alert

The committed `vertical_at_threshold.pcap` has SHA-256 `1a1a615d3ed57fd929f993057e068daa812d5a19b022a4d7b7355d7892c93266`. A verified native replay processed 20 SYN events and emitted exactly one alert with these actual fields:

| Field | Actual value |
| --- | --- |
| Schema | `alert_v1` |
| Timestamp | `2023-11-14T22:13:24.750000Z` |
| Flow ID | `CNG7101ClFJPhG5ukb` |
| Threat class | `PORT_SCAN` |
| Source | `192.0.2.10` |
| Protocol | `tcp` |
| Detector | `port_scan_window` `1.0.0` |
| Severity | `MEDIUM` |
| Confidence | `0.75` heuristic score |
| Configured window | `10.0` capture-time seconds |
| Deduplicated attempts | `20` |
| Unique destination hosts | `1` |
| Unique destination ports | `15` |
| Unique destination endpoints | `15` |
| Fixed-window attempt rate | `2.0` attempts per configured second |
| Observed span | `4.75` capture-time seconds |

The public replay uses `zeek -D -b -r`; `-D` preserves the real Zeek UID across identical controlled replays. The UID is not durable across different captures, versions, or replay modes.

The benign fixture processed 10 events and produced exactly zero alert bytes. This is a deterministic fixture result, not a measured production false-positive rate.

## Demo Commands

```bash
uv sync --frozen --group dev
uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1 --check
uv run sih26145-replay tests/fixtures/milestone1/vertical_at_threshold.pcap
uv run sih26145-replay tests/fixtures/milestone1/benign.pcap
```

Expected demo behavior: the vertical command prints one compact alert JSON line; the benign command prints nothing and exits successfully. Native `zeek` must resolve through `PATH`.

## Judge Talking Points

- Why Zeek: packet parsing and immediate SYN event emission are mature, while Python retains auditable schema, state, heuristic, and evidence ownership.
- Why hybrid detection: scan fan-out is clearer as a bounded behavioral rule; the required genuine ML component is planned for passive DNS/DGA features and does not exist yet.
- Why evidence first: the alert carries the actual triggering UID, source, capture-time window, attempts, fan-out cardinalities, thresholds, rate, span, and deterministic endpoint samples.
- How state is safe: hard bounds cover input lines, source/attempt/UID/cooldown state, stderr retention, and post-EOS process cleanup. State pressure fails with a named invariant instead of silently discarding evidence.
- What remains: five threat classes, genuine ML, offline model inference, API/dashboard, throughput and latency benchmarking, and screenshots.

## Evidence Still Needed Before Final PPT

- Dashboard and terminal screenshots after those artifacts actually exist.
- Measured detector/end-to-end P50/P95/P99 latency, sustained traffic rate, CPU, and memory with methodology.
- Genuine model dataset provenance, grouped split, metrics, error analysis, artifact version, and offline inference proof.
- Controlled evidence for SYN/DDoS, DNS/DGA or tunnelling, exfiltration, and any later C2/TLS coverage.
