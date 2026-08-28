# Milestone 1 Architecture: Streaming Port-Scan Detection

Status: **implemented and verified for Milestone 1 port-scan replay**

Designed: **2026-08-26**

Last verified: **2026-08-28**

## Objective

Milestone 1 is the smallest complete SIH26145 path:

```text
deterministic PCAP replay
  -> native Zeek packet events
  -> versioned JSON Lines
  -> Python validation
  -> bounded per-source scan window
  -> validated PORT_SCAN alerts
```

It demonstrates passive ingest, incremental processing, bounded state, and an evidence-bearing standardized alert. It does not claim that the remaining five official threat classes, ML inference, API, or dashboard exist.

## Decision and Alternatives

Use the package-managed native Zeek 8.2.2 installation. A small Zeek policy emits originator TCP SYN attempts to standard output as JSON Lines. A Python runner starts Zeek without a shell, validates each line, and passes accepted events directly to a bounded scan detector.

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
| Replay runner | Zeek process lifecycle, pipe draining, stream order, EOS consistency, and run success/failure | Packet parsing, event-time state, or scan heuristics |
| Zeek policy | Passive packet parsing and `tcp_syn_attempt_v1` emission | Alerting, thresholds, long-lived aggregation, or network actions |
| Input schema | Trust-boundary validation and schema-version discrimination | Detection policy |
| Scan detector | Event-time watermark, deduplication, expiry, bounded rolling state, thresholding, cooldown, and alert evidence | Process management or packet parsing |
| Alert schema | Common output validation | Detector-specific state |

Each boundary has one concrete implementation in Milestone 1. No interface or service layer is needed until a second implementation requires one.

## Native Zeek Replay

The runner resolves `zeek` through `PATH` and invokes an argument vector, equivalent to:

```text
zeek -D -b -r <input.pcap> <absolute-path-to-emit-syn-policy>
```

The runner never constructs a shell command. The PCAP path is data, not executable text. Zeek runs in a newly created temporary working directory so any incidental files cannot pollute the repository. Deterministic mode (`-D`) makes identical controlled replays preserve the real Zeek-generated UID and therefore produce reproducible alert JSON. A Zeek UID is still not a durable identity across different captures, Zeek versions, or replay modes. Bare mode (`-b`) avoids loading site policy or default logging that could contaminate the JSONL stdout contract. The controlled fixtures contain valid checksums, so replay does not use `-C` to ignore checksum validation.

The Zeek policy handles `connection_SYN_packet(c, pkt)`. That Zeek event covers both SYN and SYN-ACK packets, so the policy emits only when `pkt$is_orig` is true. It converts Zeek ports to integer counts and writes one compact JSON object per line. It calls `flush_all()` after each line so delivery remains incremental when stdout is a pipe. It performs no aggregation and contacts no endpoint.

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

`last_event_ts` is required when `emitted_events` is positive and omitted when it is zero. A successful replay requires exactly one sentinel, a zero Zeek exit status, a count equal to the preceding SYN records, a matching last timestamp, and no stdout data after the sentinel. Missing, duplicate, premature, or inconsistent sentinels fail the run.

## Incremental Process and Failure Semantics

The runner consumes stdout one bounded line at a time and submits a validated event to the detector before reading the next line. Alerts are serialized and flushed immediately. Consequently, a threshold crossed before the Zeek sentinel produces an alert before replay completion; no completed `conn.log` is involved.

Zeek stderr is drained concurrently to prevent a full pipe from deadlocking stdout consumption. Only the private, byte-exact latest 64 KiB tail is retained on `ReplayError`; child stderr is never echoed publicly. Alert JSON is written only to stdout. CLI stderr contains only trusted, fixed failure or invariant diagnostics and never includes observed values or child stderr.

The input line limit is 16 KiB including the terminating newline. A blank, oversized, unterminated, invalid-UTF-8, malformed JSON, unknown schema, invalid field, timestamp regression, or unexpected stdout record is fatal. Once EOS is accepted, one original two-second deadline covers child exit, stdout EOF/no-data-after-EOS validation, stderr-drainer shutdown, and any required direct-child termination. None of those stages receives a fresh timeout budget: when that deadline is exhausted, the runner kills and reaps only the direct child immediately. The separate two-second terminate-to-kill failure-cleanup grace applies only to failures before EOS. A non-zero Zeek exit, broken pipe, missing sentinel, callback failure, or named state-limit failure is fatal. Named state-limit failures propagate intact so the CLI can report the exact trusted invariant. Alerts already emitted remain evidence from an incomplete run, but the run is explicitly marked failed and must not be reported as a successful replay.

CLI process status is stable: invalid configuration or an invalid PCAP path exits `2`; runtime, child-process, stream-contract, callback, timestamp, or state-limit failure exits `1`; a successful replay exits `0`.

## Event Time and Ordering

All windows use capture time, never wall-clock processing time. The concrete scan-window state engine owns the Milestone 1 watermark, which is the greatest accepted `ts`, and allowed lateness is zero. Equal timestamps preserve input order. Any record with `ts` below the watermark fails before it mutates detector state. The runner propagates that failure and owns only subprocess stream order and EOS consistency.

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

Expiry runs before a limit check. If a valid event would still exceed a limit, the run fails with a named resource-limit diagnostic instead of silently evicting evidence or growing memory without bound. These are safety constants for the first prototype, not user-facing tuning knobs. Their actual memory cost must be measured before claiming a throughput capacity.

The first occurrence of a UID within its 60-second TTL enters the source window. Further occurrences do not change attempt counts or fan-out evidence. Detector construction rejects a scan window longer than the effective UID TTL, so a UID cannot expire while its original attempt remains active and delayed TCP retransmissions cannot become fresh attempts in the same window.

Cooldown state is a separate expiry-ordered `source IP -> last alert timestamp` map. Entries expire at `last alert timestamp + cooldown`; expiry therefore permits a re-alert exactly at the configured cooldown boundary. The map is limited to 4,096 entries and fails without partial mutation if a new alert would exceed that limit after expiry.

## Detection Rule

Initial configurable defaults are:

| Parameter | Default |
| --- | ---: |
| Window | 10 seconds |
| Minimum deduplicated attempts | 20 |
| Minimum unique destination ports | 15 |
| Minimum unique destination hosts | 15 |
| Per-source alert cooldown | 30 seconds |

Milestone 1 exposes these values as replay CLI options that populate one validated scan-configuration record; it does not introduce a configuration file. Durations must be finite, the window must be positive, cooldown must be non-negative, and all count thresholds must be positive integers. Detector construction also rejects a window that could make the maximum derived attempt rate non-finite, a window longer than the UID deduplication TTL, or any threshold above the effective per-source attempt capacity. That capacity is the minimum of the per-source attempt, total-attempt, and retained-UID limits; it is 4,096 with the defaults. Invalid combinations exit `2` before Zeek starts.

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

Later API and dashboard work may open a loopback service for local display, but that is outside this milestone and never creates a return path to observed hosts.

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

Native-Zeek end-to-end tests replay the generated benign and scan PCAPs through the real policy and Python runner. The scan test records callback/output order and asserts that `alert_v1` appears before Python accepts `end_of_stream`. The benign test asserts successful completion and no `PORT_SCAN` alert. The final proof runs tests, lint, type checks, the real replay command, and inspects the actual emitted JSON rather than trusting status documentation.

## Acceptance and Known Limitations

Milestone 1 is complete only while every acceptance checkbox in `PROGRESS.md` remains backed by current command evidence. Documentation alone does not advance a runtime compliance status.

Known limitations of this slice are explicit:

- It detects scan fan-out only; it does not yet detect the other five official threat classes.
- The confidence score is heuristic and thresholds are not calibrated against production traffic.
- Strict timestamp ordering rejects merged or malformed captures with time regressions instead of reordering them.
- Failing on state pressure preserves bounded memory and result integrity but stops the current prototype run; a measured live deployment will need a bounded degradation policy and health telemetry.
- Zeek UID deduplication handles TCP SYN retransmissions within one Zeek run; it is not a durable identity across separate replays.
- No throughput or latency claim exists until measured on the documented hardware.

The user approved this design and the detailed plan at `docs/superpowers/plans/2026-08-26-milestone-1-streaming-port-scan.md` on 2026-08-26. The implementation was completed test-first in the isolated `feature/milestone-1-port-scan` worktree and verified on 2026-08-28 with native Zeek replay, focused tests, Ruff, mypy, deterministic-fixture checking, and actual alert-schema validation.
