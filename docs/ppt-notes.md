# PPT Evidence Notes

Last verified: **2026-08-30 (UTC)**

These are presentation-ready facts for Milestones 1 through 4. Actual local dashboard screenshots are recorded below. No end-to-end performance measurement is claimed here.

## Verified Demo Story

```text
deterministic IPv4 PCAP replay
  -> native Zeek 8.2.2 SYN + DNS request policy
  -> flushed versioned JSON Lines
  -> strict Python validation
  -> synchronous detector pipeline
     -> bounded source fan-out / port_scan_window 1.0.0
     -> bounded target SYN rate / syn_flood_window 1.0.0
     -> local dns_features_v1 + dga_logreg_v1
  -> strict alert_v1 JSON Line
  -> bounded 100-alert in-memory store
  -> loopback API + same-origin static dashboard
```

The detectors are passive and local: they read validated metadata from a PCAP replay, do not contact observed endpoints or domains, do not complete handshakes, and do not decrypt payloads. Scan, SYN-flood, and DGA callbacks were observed before end-of-stream, demonstrating incremental detection rather than a post-run report. Runtime DGA inference opens no socket and requires no Internet access.

## Actual Local Dashboard Evidence

The local server binds to `127.0.0.1:8000`, accepts only seven fixed fixture identifiers, and feeds the existing replay runner's alert callback into a 100-record in-memory store. The browser requests at most 50 newest-first records and renders actual `alert_v1` values using text-only DOM assignment.

Browser inspection exercised all three alert fixtures through the real controls and observed three stored cards in this order: `DGA`, `SYN_FLOOD`, `PORT_SCAN`. It also exercised offline failure and recovery states. At 1440×1000 and 390×844 there was no horizontal overflow; all cards stayed within the narrow viewport; no console error or framework overlay was observed.

- [PPT-ready dashboard overview](screenshots/milestone4-dashboard-empty.png)
- [PPT-ready actual alert evidence](screenshots/milestone4-dashboard-alerts.png)

The dashboard states the honest boundary on-screen: UDP reflection/amplification and DNS tunnelling are `NOT IMPLEMENTED`; C2 beaconing, TLS/QUIC malware metadata, and data exfiltration are `DEFERRED`.

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

The committed `syn_flood_at_threshold.pcap` has SHA-256 `712bb6ea6da09fe4b7cb7af184f00110dc755d32a667e68e2e94cdb08b1be76d`. A verified native replay processed 100 SYN events and emitted exactly one 794-byte alert with these actual fields:

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
| Source-IP entropy | `4.32192809488736` bits |
| Fixed-window SYN rate | `10.0` events per configured second |
| Observed span | `4.95` capture-time seconds |

The 99-event below-threshold capture and the 100-event distributed-benign capture both produced exactly zero alert bytes. This is controlled scenario evidence, not a measured production false-positive rate. Source entropy describes distribution characteristics and does not prove spoofing.

## Actual DNS/DGA ML Evidence

The committed model is a 5,825-byte `StandardScaler` + balanced Logistic Regression artifact with SHA-256 `0627eea04dec557ccf4e6ab2382b6d1e432380bcfa140908dd0da68798e03f47`. It was trained on 27,723 selected domains with whole-family DGA holdout and zero train/test domain overlap.

| Held-out metric | Actual value |
| --- | ---: |
| Precision | `0.7187797902764538` |
| Recall | `0.25133333333333335` |
| F1 | `0.37243763892319093` |
| False-positive rate | `0.07223310479921645` |

The weak recall and `7.22%` controlled-source FPR are stated openly. The model is a minimum genuine ML demonstration, not a production verdict.

Native replay of the 124-byte synthetic fixture emitted one 987-byte strict alert before EOS:

| Field | Actual value |
| --- | --- |
| Threat class | `DGA` |
| Query | `x9q7z8v6k5j4m3n2.example` |
| Flow ID | `CJKFoj4bpHEhTeaRoj` |
| Source / protocol | `192.0.2.10` / `udp` |
| Detector / model | `dga_logistic_regression` `1.0.0` / `dga_logreg_v1` |
| Feature schema | `dns_features_v1` (140 values) |
| Confidence / probability | `0.9999563398163442` |
| Severity | `CRITICAL` |
| Decision threshold | `0.5` |

The controlled `example.com` fixture received probability `0.0018385042677530868` and emitted exactly zero bytes. These two fixtures are demonstration evidence, not a production error-rate estimate.

## Demo Commands

```bash
uv sync --frozen --group dev
uv run python tools/generate_milestone1_fixtures.py --output tests/fixtures/milestone1 --check
uv run python tools/generate_milestone2_fixtures.py --output tests/fixtures/milestone2 --check
uv run python tools/generate_milestone3_fixtures.py --output tests/fixtures/milestone3 --check
uv run sih26145-replay tests/fixtures/milestone1/vertical_at_threshold.pcap
uv run sih26145-replay tests/fixtures/milestone1/benign.pcap
uv run sih26145-replay tests/fixtures/milestone2/syn_flood_at_threshold.pcap
uv run sih26145-replay tests/fixtures/milestone2/benign_distributed.pcap
uv run sih26145-replay tests/fixtures/milestone3/dga_dns.pcap
uv run sih26145-replay tests/fixtures/milestone3/benign_dns.pcap
uv run sih26145-dashboard
```

Expected demo behavior: each threshold command prints one compact class-specific alert JSON line; each benign command prints nothing and exits successfully. Native `zeek` must resolve through `PATH`.

## Judge Talking Points

- Why Zeek: packet parsing and immediate SYN event emission are mature, while Python retains auditable schema, state, heuristic, and evidence ownership.
- Why hybrid detection: scan fan-out and SYN floods are clearer as bounded behavioral rules; DGA uses the genuine supervised ML path because lexical patterns benefit from grouped training and probability inference.
- Why Logistic Regression: it is CPU-friendly, explainable, only 5.8 KiB, and sufficient to prove real training/export/offline integration. Its weak recall/FPR are disclosed instead of hidden or used to justify deadline-risky model expansion.
- How leakage is limited: DGA families, not rows, are held out; benign rows use stable hash buckets; domain overlap is zero. This does not guarantee unseen-family or production generalization.
- Why evidence first: alerts carry actual triggering UIDs, capture-time windows, thresholds, rates, spans, deterministic samples, plus source fan-out or target/source-distribution evidence as appropriate.
- How state is safe: hard bounds cover input lines, source/target event windows, UID/cooldown state, stderr retention, and process cleanup. State pressure fails with a named invariant instead of silently discarding evidence.
- What remains: three untouched classes, UDP reflection/amplification, DNS tunnelling, end-to-end throughput and latency benchmarking, and the final PPT assembly.

## Evidence Still Needed Before Final PPT

- Measured detector/end-to-end P50/P95/P99 latency, sustained traffic rate, CPU, and memory with methodology.
- Controlled evidence for exfiltration and any later C2/TLS coverage; UDP reflection/amplification and DNS tunnelling remain deferred.
- Final PPT assembly and demo rehearsal using only the verified evidence above.
