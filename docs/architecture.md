# Streaming Detection and Local Dashboard Architecture

Status: **implemented for Milestones 1–4: port scan, SYN flood, DNS/DGA replay, and local dashboard**

Designed: **2026-08-26**

Last verified: **2026-08-30**

## Objective

Milestones 1 through 4 share one passive streaming path:

```text
deterministic PCAP replay
  -> native Zeek SYN and DNS request events
  -> versioned JSON Lines
  -> Python validation
  -> synchronous detector pipeline
     -> bounded per-source scan window
     -> bounded per-target SYN-flood window
     -> stateless local DGA Logistic Regression
  -> validated PORT_SCAN / SYN_FLOOD / DGA alerts
  -> bounded in-memory alert store
  -> loopback API
  -> same-origin static dashboard
```

It demonstrates passive ingest, incremental processing, bounded state or bounded per-record ML work, standardized evidence for port scans, SYN floods, and DGA-like DNS queries, and actual replayed alerts on a local dashboard. UDP reflection/amplification, DNS tunnelling, and the remaining three named classes do not exist.

## Decision and Alternatives

Use the package-managed native Zeek 8.2.2 installation. One small Zeek policy emits originator TCP SYN attempts and DNS requests to standard output as JSON Lines. A Python runner starts Zeek without a shell, validates each line, and passes accepted events to one synchronous pipeline. SYN records retain the frozen scan/flood order; DNS records route only to a preloaded local DGA detector.

This boundary was selected because it is immediate and testable. Two alternatives were rejected for Milestone 1:

- `conn.log` tailing can delay unanswered SYN observations until connection expiry or end of input, so it does not prove bounded streaming latency.
- Broker, sockets, queues, and a long-running event bus add lifecycle and failure modes that the first local replay path does not need.

The native Zeek dependency is already installed. No container, extra Zeek package, sudo action, or network access is required.

## Approved Implementation Clarifications

The verified implementation preserves the six clarifications approved before coding:

1. The Zeek policy flushes stdout after every SYN record and after EOS so Python can consume events incrementally.
2. The bounded scan window owns the capture-time watermark and rejects timestamp regression before state mutation.
3. Cooldown state is a separately bounded map and permits re-alerting exactly at the configured capture-time boundary.
4. One original two-second post-EOS deadline covers child exit, stdout completion, and stderr-drainer shutdown; cleanup does not create a fresh post-EOS budget.
5. Scan thresholds and confidence are explicit heuristics for controlled fixtures, not production-calibrated values or ML output.
6. End-to-end fixtures are IPv4; IPv6 contract, detector, and deterministic-sample behavior is covered by unit tests.

## Component Ownership

| Component | Owns | Must not own |
| --- | --- | --- |
| Replay runner | Zeek process lifecycle, pipe draining, stream order, EOS consistency, and run success/failure | Packet parsing, event-time state, or detection heuristics |
| Zeek policy | Passive packet parsing and `tcp_syn_attempt_v1` / request-only `dns_event_v1` emission | Alerting, thresholds, long-lived aggregation, lookups, or network actions |
| Input schema | Trust-boundary validation and schema-version discrimination | Detection policy |
| Detector pipeline | Synchronous fan-out of one validated event and deterministic zero/one/two-alert batching before the next record | Detector policy, state, or process lifecycle |
| Scan detector | Event-time watermark, deduplication, expiry, bounded rolling state, thresholding, cooldown, and alert evidence | Process management or packet parsing |
| SYN-flood detector | Destination-keyed event-time state, deduplication, entropy, rate/source thresholds, cooldown, and alert evidence | Process management, packet parsing, or spoofing claims |
| DGA model loader | Packaged metadata/artifact integrity, compatibility, sklearn pipeline shape, and local probability inference | Network retrieval, observed-domain lookup, or detection policy |
| DGA detector | Stateless threshold decision, severity, and measured lexical/model evidence for one DNS event | DNS parsing, rolling state, enrichment, or network access |
| Alert schema | Common output validation and detector-specific typed evidence | Detector state |
| Runtime factory | Construction of the existing three-detector pipeline for CLI and API callers | A second detector or replay implementation |
| Alert store | Strict validation, thread-safe bounded retention, oldest-first eviction, and newest-first snapshots | Persistence, detector logic, or unbounded history |
| Local API | Loopback serving, fixed fixture selection, replay serialization, callback-to-store wiring, and fixed safe errors | Arbitrary paths, executable selection, observed-host access, or detector duplication |
| Static dashboard | Same-origin controls, bounded polling/rendering, honest coverage, and actual alert/evidence presentation | Alert synthesis, remote assets, production SOC workflows, or unsupported coverage claims |

The pipeline is one concrete in-process composition, not a plugin system or service boundary. The replay runner accepts the historical scan-only detector for frozen regression tests or the three-detector pipeline used by the public CLI.

## Milestone 4 Local API and Dashboard

`AlertStore` validates each `AlertV1` before mutation and keeps a locked `deque(maxlen=100)`. Existing model instances are serialized and revalidated through the strict JSON contract so pre-insertion mutation cannot bypass validation; accepted records are then deep-copied to break caller references. Appending at capacity deterministically evicts the oldest record. Snapshots are newest-first, return deep copies, and reject limits outside `1..capacity`; the public route defaults to 50.

`POST /api/replays/{fixture_id}` accepts one enum drawn from seven committed alert/comparison fixtures. It also requires the fixed non-safelisted `X-SIH26145-Action: run-approved-fixture` header; same-origin JavaScript sends it, while an ordinary cross-origin webpage cannot issue the action without a CORS preflight that the server does not allow. Trusted-host validation accepts only `127.0.0.1`, closing the DNS-rebinding hostname path, and any supplied browser `Origin` must equal `http://127.0.0.1:8000`. The server resolves the fixed relative path beneath the configured repository root, requires a regular file, constructs the existing three-detector pipeline, and passes `AlertStore.add` as the existing replay callback. It never accepts a path, command, executable, observed host, or observed domain from the caller. One fixed replay runs synchronously at a time. `GET /api/alerts` returns unchanged strict alerts plus bounded count/capacity metadata.

`sih26145-dashboard` binds Uvicorn to `127.0.0.1:8000`. Three small trusted package assets are loaded once and returned by async routes without AnyIO threadpool file work, which avoids the managed Python 3.13 thread-handoff defect observed during regression testing. The browser uses non-overlapping three-second `setTimeout` polling, pauses during replay, requests at most 50 alerts, and builds every alert-derived node with `textContent`. There is no frontend dependency, build step, remote resource, WebSocket, database, or persistent storage.

The API is intentionally a single-process local demonstration. Restarting clears alerts, and a synchronous fixture replay temporarily blocks that one event loop while the dashboard waits. This is documented deadline-scoped behavior, not a production concurrency or durability claim.

## Milestone 2 SYN-Flood Extension

Milestone 2 reuses `tcp_syn_attempt_v1` and the Zeek policy unchanged. A target is `(destination IP, destination TCP port)`. The new rolling window counts distinct Zeek UIDs per target, unique source IPs, fixed-window SYN rate, Shannon entropy over per-source event counts, observed span, and up to 10 deterministically sorted source samples.

Default configurable policy is a 10-second capture-time window, at least 100 deduplicated SYN events, at least 20 unique sources, and a 30-second per-target cooldown. Both event and source gates must be true. Source entropy is supporting distribution evidence only; it is not labelled as proof of spoofing. UDP reflection/amplification is deferred.

The SYN-flood state owns the same zero-lateness and exact-boundary semantics as the scan state, but keeps an independent watermark, UID TTL map, target map, global event queue, source counters, and cooldown map. Code-owned limits are 4,096 active targets, 8,192 events per target, 100,000 total events, 200,000 retained UIDs, 4,096 cooldown targets, and a 60-second UID TTL. A limit raises its stable name rather than evicting evidence. If cooldown capacity rejects a newly triggering target, the immediately inserted event, source counter, and UID are rolled back before failure propagates.

Each target also maintains `sum(count * log2(count))` as source counts change. Entropy is therefore derived as `log2(events) - sum(count * log2(count)) / events` with constant work per accepted or expired observation instead of rescanning every source. The detector sorts the full source set for its deterministic 10-address sample only after the event reaches both thresholds, clears cooldown, and passes cooldown-capacity checks, immediately before constructing an alert.

At threshold, confidence is `0.75`:

```text
event_strength = min(events / (2 * minimum_syn_events), 1)
source_strength = min(unique_sources / (2 * minimum_unique_sources), 1)
confidence = round(0.50 + 0.25 * event_strength + 0.25 * source_strength, 4)
```

Severity uses the existing common bands: `MEDIUM` below `0.85`, `HIGH` below `0.95`, and `CRITICAL` otherwise. This is an explainable heuristic, not a calibrated probability or ML output.

Offline Milestone 2 fixtures use RFC 5737 IPv4 addresses and valid generated Ethernet/IPv4/TCP checksums. The exact-threshold scenario has 100 events from 20 sources to one target; comparison scenarios have 99 events to that target and 100 events distributed across 10 targets. No generator transmits packets.

## Native Zeek Replay

The runner resolves `zeek` through `PATH` and invokes an argument vector, equivalent to:

```text
zeek -D -b -r <input.pcap> <absolute-path-to-combined-policy>
```

The runner never constructs a shell command. The PCAP path is data, not executable text. Zeek runs in a newly created temporary working directory so any incidental files cannot pollute the repository. Deterministic mode (`-D`) makes identical controlled replays preserve the real Zeek-generated UID and therefore produce reproducible alert JSON. A Zeek UID is still not a durable identity across different captures, Zeek versions, or replay modes. Bare mode (`-b`) avoids loading site policy or default logging that could contaminate the JSONL stdout contract. The controlled fixtures contain valid checksums, so replay does not use `-C` to ignore checksum validation.

The Zeek policy handles `connection_SYN_packet(c, pkt)` and `dns_request(c, msg, query, qtype, qclass)`. It emits only originator SYNs and request metadata, explicitly enables the DNS analyzer for UDP/TCP port 53, writes one compact JSON object per line, and calls `flush_all()` after each line. It performs no lookup, aggregation, response wait, or network action.

At `zeek_done` priority `-100`, the policy emits and flushes exactly one end-of-stream record. This is an internal stream sentinel, not a detector alert.

## Zeek-to-Python Stream Contract

### SYN attempt record

```json
{
  "schema_version": "tcp_syn_attempt_v1",
  "event_type": "tcp_syn_attempt",
  "ts": 1317146840.497541,
  "uid": "C9e2pMxSR3KXn846a",
  "src_ip": "192.0.2.10",
  "src_port": 58024,
  "dst_ip": "198.51.100.20",
  "dst_port": 443,
  "transport": "tcp"
}
```

Semantics:

- `ts` is the capture timestamp in Unix seconds from Zeek `network_time()`.
- `uid` is Zeek's connection UID and becomes the alert's triggering flow ID.
- Source and destination are Zeek's originator and responder endpoints.
- A retransmitted originator SYN normally retains the same Zeek UID. The Zeek policy emits it, while Python deduplicates it. Keeping that responsibility in Python makes the behavior directly unit-testable.

Validation is strict: the record must be a JSON object with no unknown fields; schema and event literals must match; timestamp must be finite and between the Unix epoch and `9999-12-31T23:59:59Z`; IP addresses must parse as IPv4 or IPv6; ports must be integers from 0 through 65535; UID must contain 1 through 128 printable non-whitespace characters; and transport must be `tcp`.

### End-of-stream record

```json
{
  "schema_version": "control_v1",
  "event_type": "end_of_stream",
  "emitted_events": 25,
  "last_event_ts": 1317146842.499724
}
```

`last_event_ts` is required when `emitted_events` is positive and omitted when it is zero. A successful replay requires exactly one sentinel, a zero Zeek exit status, a count equal to all preceding SYN and DNS records, a matching last timestamp, and no stdout data after the sentinel. Missing, duplicate, premature, or inconsistent sentinels fail the run.

### DNS request record

`dns_event_v1` carries the same capture timestamp, Zeek UID, and validated client/server endpoints plus UDP/TCP transport, normalized query name, query type, and query class. Names are lowercase ASCII LDH labels without a terminal dot. Unknown fields, malformed endpoints, non-finite timestamps, invalid codes, underscores, Unicode, and overlong names fail at the input boundary.

## Milestone 3 DGA Model Path

Offline preparation selects 20,000 Majestic domains and 7,723 example domains from eight pinned DGA families. The 27,723-row prepared dataset is ignored; only the 5,825-byte joblib artifact and strict metadata sidecar are packaged. Whole DGA families are held out, benign rows use stable SHA-256 buckets, and train/test domains do not overlap.

Both training and runtime import `dns_features_v1`: 12 explainable lexical summaries followed by 128 normalized hashed character 2-gram/3-gram buckets. The loader verifies artifact schema, model/feature versions, ordered feature names, labels, fixed threshold, byte count, SHA-256, and the fitted `StandardScaler`/`LogisticRegression` shape before Zeek starts. Joblib is used only for this trusted packaged artifact.

Each validated DNS request is independently transformed into one fixed 140-value vector. Probability below `0.5` produces no alert; probability at or above it emits one `DGA` `alert_v1` whose confidence is the model probability and whose typed evidence records the query, query type, threshold, model/feature versions, and recomputed lexical summaries. There is no rolling DNS state, network access, resolver call, remote inference, or Internet requirement.

## Incremental Process and Failure Semantics

The runner consumes stdout one bounded line at a time and submits a validated event to the detector before reading the next line. Before EOS, selector-driven chunk reads accumulate at most one bounded record plus already-readable following bytes. Each byte received resets a two-second inactivity deadline; if no stdout progress completes the next record within that inactivity bound, the run fails with `pre_end_of_stream_timeout` and enters the existing direct-child cleanup path. This avoids blocking indefinitely when Zeek flushes a partial line and stalls. Alerts are serialized and flushed immediately. Consequently, a threshold crossed before the Zeek sentinel produces an alert before replay completion; no completed `conn.log` is involved.

Zeek stderr is drained concurrently to prevent a full pipe from deadlocking stdout consumption. Only the private, byte-exact latest 64 KiB tail is retained on `ReplayError`; child stderr is never echoed publicly. Alert JSON is written only to stdout. CLI stderr contains only trusted, fixed failure or invariant diagnostics and never includes observed values or child stderr.

The input line limit is 16 KiB including the terminating newline. A blank, oversized, unterminated, invalid-UTF-8, malformed JSON, unknown schema, invalid field, timestamp regression, unexpected stdout record, or two seconds without stdout progress before EOS is fatal. Once EOS is accepted, one original two-second deadline covers child exit, stdout EOF/no-data-after-EOS validation, stderr-drainer shutdown, and any required direct-child termination. None of those stages receives a fresh timeout budget: when that deadline is exhausted, the runner kills and reaps only the direct child immediately. The separate two-second terminate-to-kill failure-cleanup grace applies only to failures before EOS, including pre-EOS inactivity expiry. A non-zero Zeek exit, broken pipe, missing sentinel, callback failure, or named state-limit failure is fatal. Named state-limit failures propagate intact so the CLI can report the exact trusted invariant. Alerts already emitted remain evidence from an incomplete run, but the run is explicitly marked failed and must not be reported as a successful replay.

CLI process status is stable: invalid configuration or an invalid PCAP path exits `2`; runtime, child-process, stream-contract, callback, timestamp, or state-limit failure exits `1`; a successful replay exits `0`.

## Event Time and Ordering

All windows use capture time, never wall-clock processing time. The runner rejects any event timestamp below the preceding stream event, including across SYN and DNS record types. Each stateful SYN detector also owns a watermark equal to its greatest accepted `ts`; allowed lateness is zero. Equal timestamps preserve input order. Regression fails before detector mutation, while the runner continues to own subprocess stream order, alert batching, and EOS consistency.

Strict monotonic input is appropriate for deterministic PCAP fixtures, avoids silently distorting rate calculations, and allows immediate alerting without a reorder buffer. A future live or merged-capture ingest may add a bounded lateness heap in the runner while leaving the schema and detector unchanged. That extension is not part of Milestone 1.

## Bounded Scan State

The detector maintains an insertion-ordered map of active source IPs. Each source owns a capture-time-ordered deque of accepted attempts plus counters for destination IPs, destination ports, and `(destination IP, destination port)` pairs. A global TTL map holds recently seen UIDs.

Before each event, the detector advances to the event watermark and expires:

- source attempts older than the 10-second scan window;
- sources with no remaining attempts; and
- deduplication UIDs older than 60 seconds.

Expiry updates all counters, so unique counts always describe the current window. The following hard limits bound untrusted state:

| Limit | Initial value |
| --- | ---: |
| Active sources | 4,096 |
| Attempts for one source | 4,096 |
| Attempts across all sources | 100,000 |
| Retained deduplication UIDs | 200,000 |
| Retained cooldown sources | 4,096 |

Expiry runs before a limit check. If a valid event would still exceed a limit, the run fails with a named resource-limit diagnostic instead of silently evicting evidence or growing memory without bound. When the detector must insert an event to determine that it crosses the alert threshold but the cooldown-source map is full, it rolls back that immediately preceding attempt, its counters, and its UID before raising. Capture-time expiry and watermark advancement remain valid, while retrying the rejected event cannot be mistaken for a duplicate. These are safety constants for the first prototype, not user-facing tuning knobs. Their actual memory cost must be measured before claiming a throughput capacity.

The first occurrence of a UID within its 60-second TTL enters the source window. Further occurrences do not change attempt counts or fan-out evidence. Detector construction rejects a scan window longer than the effective UID TTL, so a UID cannot expire while its original attempt remains active and delayed TCP retransmissions cannot become fresh attempts in the same window.

Cooldown state is a separate expiry-ordered `source IP -> last alert timestamp` map. Expiry compares `watermark - last alert timestamp` directly with the cooldown, avoiding loss of small positive durations when they are added to large epoch timestamps. It therefore suppresses every event with elapsed time below the cooldown and permits a re-alert exactly at the configured boundary. The map is limited to 4,096 entries and fails without partial mutation if a new alert would exceed that limit after expiry.

## Detection Rule

Initial configurable defaults are:

| Parameter | Default |
| --- | ---: |
| Window | 10 seconds |
| Minimum deduplicated attempts | 20 |
| Minimum unique destination ports | 15 |
| Minimum unique destination hosts | 15 |
| Per-source alert cooldown | 30 seconds |

Milestone 1 exposes these values as replay CLI options that populate one validated scan-configuration record; it does not introduce a configuration file. Durations must be finite, the window must be positive, cooldown must be non-negative, and all count thresholds must be positive integers. Detector construction normalizes the effective scan window to six decimal places, matching the microsecond precision of alert timestamps, before using it for membership, rates, duration validation, or reporting. A positive input that normalizes to zero is rejected. Construction also rejects a window that could make the maximum derived attempt rate non-finite, a window longer than the UID deduplication TTL, or any threshold above the effective per-source attempt capacity. That capacity is the minimum of the per-source attempt, total-attempt, and retained-UID limits; it is 4,096 with the defaults. Invalid combinations exit `2` before Zeek starts.

A source triggers `PORT_SCAN` when, within the active window:

```text
attempts >= 20
AND (unique destination ports >= 15 OR unique destination hosts >= 15)
```

This recognizes vertical fan-out across ports and horizontal fan-out across hosts. Requiring both a minimum attempt count and fan-out reduces alerts from a few ordinary connections. These are starting values for controlled fixtures, not validated production thresholds. Later evaluation must measure false positives and tune them from scenario-labelled data.

Cooldown suppresses duplicate alert emission for the same source and detector for 30 capture-time seconds. State and evidence continue updating during cooldown. If the condition still holds after cooldown, the next accepted event may emit a new alert.

## Confidence, Severity, and Evidence

For a triggered alert:

```text
attempt_strength = min(attempts / (2 * minimum_attempts), 1)
fanout_strength = min(
    max(unique_ports / minimum_ports, unique_hosts / minimum_hosts) / 2,
    1,
)
confidence = round(0.50 + 0.25 * attempt_strength + 0.25 * fanout_strength, 4)
```

At the exact default threshold the score is `0.75`; stronger observations rise to at most `1.0`. This is an explainable heuristic score, not a calibrated probability or an ML result. Severity is `MEDIUM` below `0.85`, `HIGH` from `0.85` to below `0.95`, and `CRITICAL` from `0.95` onward.

Evidence contains actual current-window values:

- deduplicated attempt count;
- unique destination host, port, and endpoint counts;
- fixed-window attempt rate (`attempts / window_seconds`);
- observed span from the oldest to triggering event, derived from the same microsecond-normalized UTC timestamps carried by the alert window;
- the threshold values used;
- at most 10 destination endpoint samples, sorted for deterministic output.

No example value may be copied into a real alert as if it were measured.

## `alert_v1` Contract

```json
{
  "schema_version": "alert_v1",
  "timestamp": "2026-08-26T15:00:00.123456Z",
  "flow_id": "C9e2pMxSR3KXn846a",
  "threat_class": "PORT_SCAN",
  "protocol": "tcp",
  "confidence": 0.75,
  "severity": "MEDIUM",
  "detector": {
    "name": "port_scan_window",
    "version": "1.0.0"
  },
  "source": {
    "ip": "192.0.2.10"
  },
  "window": {
    "start": "2026-08-26T14:59:51.000000Z",
    "end": "2026-08-26T15:00:00.123456Z",
    "configured_seconds": 10.0
  },
  "evidence": {
    "deduplicated_attempts": 20,
    "unique_destination_hosts": 1,
    "unique_destination_ports": 15,
    "unique_destination_endpoints": 15,
    "attempt_rate_per_second": 2.0,
    "observed_span_seconds": 9.123456,
    "thresholds": {
      "minimum_attempts": 20,
      "minimum_unique_destination_ports": 15,
      "minimum_unique_destination_hosts": 15
    },
    "destination_samples": [
      {"ip": "198.51.100.20", "port": 22},
      {"ip": "198.51.100.20", "port": 23}
    ]
  }
}
```

The timestamp and `flow_id` come from the event that crossed the threshold. Timestamps are UTC RFC 3339 strings derived from capture time. Pydantic must reject unknown fields, non-finite values, invalid IPs/timestamps, an empty flow ID, an unsupported threat class, protocol, or severity, confidence outside `[0, 1]`, an inverted window, negative evidence, or evidence inconsistent with the window. Detector-specific evidence is a typed port-scan evidence record rather than an unvalidated arbitrary dictionary.

## Passive-Security Boundary

The entire path is local and read-only with respect to observed traffic:

- Zeek reads a PCAP file; neither Zeek policy nor Python opens a network socket.
- Observed IP addresses, ports, UIDs, and future domains are parsed only as values. They are never interpolated into commands, URLs, filenames, or network destinations.
- The runner starts only the configured local `zeek` executable with explicit arguments.
- There is no probing, handshake completion, packet injection, blocking, mitigation, network callback to an observed host, payload decryption, or Internet inference.

The local API opens only a loopback display service. Its only replay inputs are code-owned fixture identifiers, and observed hosts/domains never become network destinations, so it does not create a return path to monitored systems.

## Deterministic Fixtures and Provenance

Do not commit the installed `nmap-vsn.pcap`: it has only 17 SYN attempts, does not meet the initial thresholds, and its provenance/licence has not been established for redistribution.

Instead, a small reproducible generator writes PCAP bytes directly to a file using the Python standard library. For Milestone 1 it constructs valid Ethernet, IPv4, and TCP checksums entirely offline. IPv6 acceptance remains covered by schema and detector unit tests; an IPv6 PCAP encoder is deferred until a later end-to-end requirement needs it. The generator never opens a raw or ordinary network socket. Addresses come from documentation-only ranges such as `192.0.2.0/24` and `198.51.100.0/24`.

Committed fixture manifests record generator version, scenario label, parameters, expected outcome, timestamp range, endpoints, packet count, capture hash, and provenance. The fixtures are:

- benign activity that stays below both fan-out thresholds;
- a vertical scan with 20 attempts across exactly 15 unique ports that alerts before EOS;
- a horizontal scan with 20 attempts across exactly 15 destination hosts;
- retransmitted SYNs sharing a Zeek UID that do not inflate attempts; and
- boundary cases immediately below and at each threshold.

No packet is transmitted while generating or testing these fixtures.

## Verification Strategy

Focused schema tests cover valid records plus unknown fields, invalid JSON, invalid IPs/ports/timestamps/confidence, oversized lines, and EOS invariants.

Detector unit tests use constructed validated events and cover:

- vertical and horizontal threshold crossings;
- no alert immediately below thresholds;
- UID retransmission deduplication;
- exact window-boundary expiry;
- per-source isolation;
- cooldown and re-alert timing;
- confidence, severity, evidence, and deterministic samples;
- timestamp regression; and
- every state limit without excessive allocations.

Runner integration tests use a tiny fake child process to cover incremental line handling, stderr draining, non-zero exit, malformed output, missing or duplicate EOS, count mismatch, timeout, pre-EOS terminate-to-kill grace, and post-EOS immediate kill/reap after deadline exhaustion. They do not need Zeek for every failure branch.

Native-Zeek end-to-end tests replay generated scan, SYN-flood, DNS/DGA, below-threshold, and benign PCAPs through the real policy and Python runner. All three alerting classes assert that `alert_v1` appears before Python accepts `end_of_stream`; comparison fixtures assert successful completion with no alert. The final proof runs tests, lint, type checks, all fixture checks, real replay commands, artifact integrity validation, and strict validation of actual emitted JSON.

## Acceptance and Known Limitations

Milestones 1 and 2 are complete only while their acceptance checkboxes in `PROGRESS.md` remain backed by current command evidence. Documentation alone does not advance a runtime compliance status.

Known limitations of this slice are explicit:

- It detects scan fan-out, destination-centric SYN floods, and DGA-like lexical DNS names. UDP reflection/amplification, DNS tunnelling, and three official classes are not implemented.
- Held-out DGA recall is `0.2513` and false-positive rate is `0.0722` on controlled sources; the model is not a production verdict.
- The confidence score is heuristic and thresholds are not calibrated against production traffic.
- Strict timestamp ordering rejects merged or malformed captures with time regressions instead of reordering them.
- Failing on state pressure preserves bounded memory and result integrity but stops the current prototype run; a measured live deployment will need a bounded degradation policy and health telemetry.
- Zeek UID deduplication handles TCP SYN retransmissions within one Zeek run; it is not a durable identity across separate replays.
- The API/store/dashboard are local, process-only, unauthenticated, and non-persistent; one synchronous fixture replay temporarily pauses same-origin polling.
- No throughput or latency claim exists until measured on the documented hardware.

The user approved the Milestone 1 design at `docs/superpowers/plans/2026-08-26-milestone-1-streaming-port-scan.md` and approved the deadline-scoped Milestone 2 plan recorded in `PROGRESS.md`. Each implementation was completed test-first in its dedicated branch/worktree and verified on 2026-08-28 with native Zeek replay, focused and full tests, Ruff, mypy, deterministic fixture checks, and actual alert-schema validation.
