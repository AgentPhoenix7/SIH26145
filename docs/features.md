# Versioned Features

Last verified: **2026-08-29 (UTC)**

## Scope and Observability

Milestones 1 through 3 implement passive reconnaissance/port-scan, SYN-flood, and DNS/DGA detection. Native Zeek emits `tcp_syn_attempt_v1` originator-SYN metadata and request-only `dns_event_v1` metadata. Every feature comes from the validated passive record; no detector requires payload decryption, a completed handshake, active probing, DNS resolution, enrichment, or a return path.

The committed PCAP fixtures are IPv4. Strict event contracts and detector state have focused IPv6 unit coverage, but native IPv6 replay is not yet an end-to-end claim.

## `tcp_syn_attempt_v1`

Each accepted record is one observed originator SYN. The contract rejects unknown fields, invalid or non-finite timestamps, invalid IP addresses, ports outside `0..65535`, non-printable or whitespace-containing UIDs, non-TCP transport, and input lines larger than 16 KiB.

`uid` is the real Zeek connection UID. The public replay path uses `zeek -D -b -r` so identical controlled replays are reproducible. A UID is not durable across different captures, Zeek versions, or replay modes.

## Port-Scan Feature Definition

The following values form the typed `alert_v1` port-scan evidence. All values describe the triggering source's active capture-time window after UID deduplication.

| Feature | Definition | Unit / bound |
| --- | --- | --- |
| Deduplicated attempts | Count of accepted originator SYN events with distinct Zeek UIDs in the active source window. A repeated UID within the 60-second deduplication TTL does not add an attempt. | Integer; bounded by per-source and global attempt limits |
| Unique destination hosts | Cardinality of destination IP addresses among active attempts. | Integer from `0` to attempts |
| Unique destination ports | Cardinality of destination TCP ports among active attempts. | Integer from `0` to attempts |
| Unique destination endpoints | Cardinality of `(destination IP, destination port)` pairs among active attempts. | Integer from `0` to attempts; at least the host and port cardinalities |
| Fixed-window attempt rate | `deduplicated_attempts / effective_configured_window_seconds`. The effective window is the configured value normalized to microsecond precision; the rate is deliberately not divided by observed span. | Attempts per configured second; finite and non-negative |
| Observed span | Difference between the microsecond-normalized UTC timestamps used as the alert window end and start. | Capture-time seconds from `0` through the configured window; consistent with serialized `alert_v1` timestamps |
| Destination samples | First 10 unique endpoints in deterministic IPv4-before-IPv6, numeric-IP, then port order. | At most 10 unique endpoint records |

The default scan rule is:

```text
deduplicated_attempts >= 20
AND (
  unique_destination_ports >= 15
  OR unique_destination_hosts >= 15
)
```

The vertical threshold fixture therefore contains 20 attempts across exactly 15 unique destination ports. The horizontal threshold fixture contains 20 attempts across exactly 15 unique destination hosts. These thresholds are configurable CLI policy values and are not production calibrated.

## SYN-Flood Feature Definition

The following values form typed `alert_v1` SYN-flood evidence. All values describe one destination `(IP, port)` capture-time window after UID deduplication.

| Feature | Definition | Unit / bound |
| --- | --- | --- |
| Deduplicated SYN events | Count of accepted originator SYN events with distinct Zeek UIDs for the target. | Integer; bounded by per-target and global event limits |
| Unique sources | Cardinality of source IP addresses sending active SYN events to the target. | Integer from `0` to SYN events |
| Source-IP entropy | Shannon entropy `-sum(p_i * log2(p_i))` over active per-source event counts. It describes source distribution; it is not proof that addresses are spoofed. | Bits from `0` through `log2(unique_sources)` |
| Fixed-window SYN rate | `deduplicated_syn_events / effective_configured_window_seconds`; deliberately not divided by observed span. | SYN events per configured second; finite and non-negative |
| Observed span | Difference between the microsecond-normalized triggering and oldest active event timestamps. | Capture-time seconds from `0` through the configured window |
| Target | Destination IP and TCP port owning the rolling window. | One validated IPv4/IPv6 endpoint |
| Source samples | First 10 unique sources in deterministic IPv4-before-IPv6, numeric-IP order. | At most 10 unique IP addresses |

Runtime state maintains `sum(count * log2(count))` when one source count is incremented, expired, or rolled back, then derives the same Shannon entropy as `log2(events) - sum(count * log2(count)) / events`. This avoids a full source scan for every accepted event. Deterministic source sampling still uses the complete active source set, but sorting is deferred until an alert has passed its thresholds, cooldown, and cooldown-capacity checks.

The default SYN-flood rule is:

```text
deduplicated_syn_events >= 100
AND unique_sources >= 20
```

The exact-threshold fixture has 100 SYN events from 20 uniformly represented RFC 5737 sources to `198.51.100.20:443` in 4.95 capture-time seconds. The 99-event fixture and a 100-event fixture distributed across 10 targets do not alert. These are controlled-fixture outcomes, not production calibration or a false-positive-rate measurement.

## Capture-Time Boundaries and Bounds

The watermark is the greatest accepted capture timestamp; allowed lateness is zero. Equal timestamps retain input order. A lower timestamp fails before state mutation.

For a 10-second window at watermark `t`, events with timestamps lower than `t - 10` expire. An event exactly at `t - 10` remains included and expires only when the watermark advances beyond that boundary. UID deduplication similarly retains a UID at exactly its 60-second TTL boundary and permits reuse only after the boundary. Each detector owns the same zero-lateness capture-time rule and maintains independent state from the shared validated event.

Configuration validation keeps these features internally achievable and finite. The effective scan window is normalized to six decimal places so state membership, fixed-window rate, serialized alert duration, and duration validation share the alert timestamp precision. A positive configured value that normalizes to zero is invalid. The effective window cannot exceed the UID TTL, every attempt/fan-out threshold must fit within the effective attempt capacity, and the maximum capacity divided by the window must be finite. Under default limits, the effective capacity is 4,096 attempts and the maximum window is 60 seconds.

Cooldown is capture-time based and source scoped. Suppression and expiry compare `event_ts - last_alert_ts` directly with `cooldown_seconds`, so even a positive cooldown smaller than a large epoch timestamp's floating-point ULP remains effective. A source is suppressed below the cooldown and may alert again exactly at the configured boundary. Cooldown entries expire and are hard-limited to 4,096. The other code-owned limits are 4,096 active sources, 4,096 attempts per source, 100,000 attempts overall, and 200,000 retained UIDs. An event that would exceed a limit fails with the named invariant and does not silently evict or partially insert evidence. If a newly inserted threshold event discovers a full cooldown map, its attempt, counters, and UID are rolled back so the rejected event remains retry-safe.

SYN-flood cooldown is capture-time based and target scoped with the same exact-boundary behavior. Its code-owned limits are 4,096 active targets, 8,192 events per target, 100,000 events overall, 200,000 retained UIDs, and 4,096 cooldown targets. A cooldown-capacity rejection rolls back the triggering target event, source counter, and UID.

## Confidence and Severity

Confidence is an explainable heuristic score, not a probability and not ML output:

```text
attempt_strength = min(attempts / (2 * minimum_attempts), 1)
fanout_strength = min(
  max(unique_ports / minimum_ports, unique_hosts / minimum_hosts) / 2,
  1,
)
confidence = round(0.50 + 0.25 * attempt_strength + 0.25 * fanout_strength, 4)
```

At the exact default threshold, confidence is `0.75`. Severity is `MEDIUM` below `0.85`, `HIGH` from `0.85` to below `0.95`, and `CRITICAL` from `0.95` onward.

SYN-flood confidence uses the same transparent shape with its two required gates:

```text
event_strength = min(events / (2 * minimum_syn_events), 1)
source_strength = min(unique_sources / (2 * minimum_unique_sources), 1)
confidence = round(0.50 + 0.25 * event_strength + 0.25 * source_strength, 4)
```

It is also `0.75` at the exact threshold and uses the same severity bands.

## `dns_event_v1` and `dns_features_v1`

One DNS record contains capture timestamp, Zeek UID, client/server endpoints, UDP or TCP transport, a lowercase query name without a terminal dot, and positive 16-bit query type/class codes. The LDH-only boundary rejects non-ASCII names, underscores, empty/overlong labels, names over 253 bytes, unknown fields, and invalid endpoints or timestamps. This intentionally excludes service labels and Unicode presentation names from the MVP.

Training and runtime import the same `extract_dns_features` implementation. Dots are excluded from character summaries, and hashed n-grams never cross label boundaries.

| Ordered summary feature | Definition |
| --- | --- |
| Domain length | Characters excluding dots |
| Label count | Number of dot-separated labels |
| Longest / mean label length | Maximum label length and domain length divided by label count |
| Digit / hyphen / vowel ratio | Matching characters divided by domain length |
| Unique-character ratio | Distinct characters divided by domain length |
| Character entropy | Shannon entropy over domain characters excluding dots |
| Unique-bigram ratio | Distinct adjacent label-internal bigrams divided by total bigrams |
| Longest consonant / digit run | Longest label-internal consecutive run of each type |

The model vector appends 128 deterministic BLAKE2b-hashed character 2-gram and 3-gram frequency buckets, producing 140 ordered finite values. Bucket counts are normalized by total label-internal n-grams. Alerts retain the 12 readable summaries and the contract recomputes them from the recorded query; the sparse buckets are not emitted.

`dga_logreg_v1` is a `StandardScaler` plus class-balanced Logistic Regression artifact loaded once before Zeek starts. A probability at or above `0.5` emits `DGA`; confidence equals that probability. Severity remains `MEDIUM` below `0.85`, `HIGH` below `0.95`, and `CRITICAL` otherwise. The detector is stateless and bounded by the strict 253-byte input name and fixed 140-value vector.

## Version and Parity Status

Runtime event contracts are `tcp_syn_attempt_v1` and `dns_event_v1`; the common output remains `alert_v1`. Detector identities are `port_scan_window`, `syn_flood_window`, and `dga_logistic_regression`, all version `1.0.0`. The SYN detectors remain heuristic and frozen. Only DGA uses genuine ML, with model `dga_logreg_v1` and shared feature schema `dns_features_v1`.
