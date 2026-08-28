# Versioned Features

Last verified: **2026-08-28 (UTC)**

## Scope and Observability

Milestone 1 implements only passive reconnaissance/port-scan detection. Native Zeek reads a PCAP and emits `tcp_syn_attempt_v1` metadata for originator TCP SYN packets. The runtime uses capture timestamp, Zeek UID, source/destination IP, source/destination port, and transport. It does not require payloads, decryption, a completed handshake, active probes, or a return path to an observed endpoint.

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

## Capture-Time Boundaries and Bounds

The watermark is the greatest accepted capture timestamp; allowed lateness is zero. Equal timestamps retain input order. A lower timestamp fails before state mutation.

For a 10-second window at watermark `t`, attempts with timestamps lower than `t - 10` expire. An attempt exactly at `t - 10` remains included and expires only when the watermark advances beyond that boundary. UID deduplication similarly retains a UID at exactly its 60-second TTL boundary and permits reuse only after the boundary.

Configuration validation keeps these features internally achievable and finite. The effective scan window is normalized to six decimal places so state membership, fixed-window rate, serialized alert duration, and duration validation share the alert timestamp precision. A positive configured value that normalizes to zero is invalid. The effective window cannot exceed the UID TTL, every attempt/fan-out threshold must fit within the effective attempt capacity, and the maximum capacity divided by the window must be finite. Under default limits, the effective capacity is 4,096 attempts and the maximum window is 60 seconds.

Cooldown is capture-time based and source scoped. Suppression and expiry compare `event_ts - last_alert_ts` directly with `cooldown_seconds`, so even a positive cooldown smaller than a large epoch timestamp's floating-point ULP remains effective. A source is suppressed below the cooldown and may alert again exactly at the configured boundary. Cooldown entries expire and are hard-limited to 4,096. The other code-owned limits are 4,096 active sources, 4,096 attempts per source, 100,000 attempts overall, and 200,000 retained UIDs. An event that would exceed a limit fails with the named invariant and does not silently evict or partially insert evidence. If a newly inserted threshold event discovers a full cooldown map, its attempt, counters, and UID are rolled back so the rejected event remains retry-safe.

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

## Version and Parity Status

The runtime event contract is `tcp_syn_attempt_v1`; the alert contract is `alert_v1`; the detector identifies itself as `port_scan_window` version `1.0.0`. No training dataset or model consumes these scan features yet. DNS/DGA ML must define a separate shared feature version that local passive inference can reproduce exactly.
