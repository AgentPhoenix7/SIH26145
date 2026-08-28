# PPT Evidence Notes

Last verified: **2026-08-28 (UTC)**

These are presentation-ready facts for verified Milestones 1 and 2. No screenshot, performance measurement, model metric, or dashboard is claimed here.

## Verified Demo Story

```text
deterministic IPv4 PCAP replay
  -> native Zeek 8.2.2 originator-SYN policy
  -> flushed tcp_syn_attempt_v1 JSON Lines
  -> strict Python validation
  -> synchronous detector pipeline
     -> bounded source fan-out / port_scan_window 1.0.0
     -> bounded target SYN rate / syn_flood_window 1.0.0
  -> strict alert_v1 JSON Line
```

The detectors are passive and local: they read validated metadata from a PCAP replay, do not contact observed endpoints, do not complete handshakes, and do not decrypt payloads. Both scan and SYN-flood alert callbacks were observed before the end-of-stream record, demonstrating incremental detection rather than a post-run `conn.log` report.

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

## Actual SYN-Flood Threshold Alert

The committed `syn_flood_at_threshold.pcap` has SHA-256 `712bb6ea6da09fe4b7cb7af184f00110dc755d32a667e68e2e94cdb08b1be76d`. A verified native replay processed 100 SYN events and emitted exactly one 795-byte alert with these actual fields:

| Field | Actual value |
| --- | --- |
| Schema | `alert_v1` |
| Timestamp | `2023-11-14T22:13:24.950000Z` |
| Flow ID | `CGiXw92rB7j9RuZuK4` |
| Threat class | `SYN_FLOOD` |
| Triggering source | `192.0.2.20` |
| Target | `198.51.100.20:443` |
| Detector | `syn_flood_window` `1.0.0` |
| Severity | `MEDIUM` |
| Confidence | `0.75` heuristic score |
| Configured window | `10.0` capture-time seconds |
| Deduplicated SYN events | `100` |
| Unique sources | `20` |
| Source-IP entropy | `4.321928094887363` bits |
| Fixed-window SYN rate | `10.0` events per configured second |
| Observed span | `4.95` capture-time seconds |

The 99-event below-threshold capture and the 100-event distributed-benign capture both produced exactly zero alert bytes. This is controlled scenario evidence, not a measured production false-positive rate. Source entropy describes distribution characteristics and does not prove spoofing.

## Demo Commands

```bash
uv sync --frozen --group dev
uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1 --check
uv run python tools/generate_milestone2_fixtures.py --output tests/fixtures/milestone2 --check
uv run sih26145-replay tests/fixtures/milestone1/vertical_at_threshold.pcap
uv run sih26145-replay tests/fixtures/milestone1/benign.pcap
uv run sih26145-replay tests/fixtures/milestone2/syn_flood_at_threshold.pcap
uv run sih26145-replay tests/fixtures/milestone2/benign_distributed.pcap
```

Expected demo behavior: each threshold command prints one compact class-specific alert JSON line; each benign command prints nothing and exits successfully. Native `zeek` must resolve through `PATH`.

## Judge Talking Points

- Why Zeek: packet parsing and immediate SYN event emission are mature, while Python retains auditable schema, state, heuristic, and evidence ownership.
- Why hybrid detection: scan fan-out and SYN floods are clearer as bounded behavioral rules; the required genuine ML component is planned for passive DNS/DGA features and does not exist yet.
- Why evidence first: alerts carry actual triggering UIDs, capture-time windows, thresholds, rates, spans, deterministic samples, plus source fan-out or target/source-distribution evidence as appropriate.
- How state is safe: hard bounds cover input lines, source/target event windows, UID/cooldown state, stderr retention, and process cleanup. State pressure fails with a named invariant instead of silently discarding evidence.
- What remains: four untouched threat classes, UDP reflection/amplification within DDoS, genuine ML, offline model inference, API/dashboard, throughput and latency benchmarking, and screenshots.

## Evidence Still Needed Before Final PPT

- Dashboard and terminal screenshots after those artifacts actually exist.
- Measured detector/end-to-end P50/P95/P99 latency, sustained traffic rate, CPU, and memory with methodology.
- Genuine model dataset provenance, grouped split, metrics, error analysis, artifact version, and offline inference proof.
- Controlled evidence for DNS/DGA or tunnelling, exfiltration, and any later C2/TLS coverage; UDP reflection/amplification remains deferred within DDoS.
