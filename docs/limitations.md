# MVP Limitations

Last verified: **2026-08-30 (UTC)**

- Demonstrated coverage is 3/6 named classes: port scanning, the SYN-flood subset of DDoS, and DGA lexical detection. UDP reflection/amplification, stronger spoofing inference, DNS tunnelling, C2 beaconing, encrypted-session malware metadata, and data exfiltration are not implemented.
- The DGA model's held-out recall is `0.2513` and false-positive rate is `0.0722` on a controlled source mixture. It is not suitable for autonomous blocking or a production verdict. The passive MVP only emits intelligence and never blocks traffic.
- Majestic popularity is an imperfect benign proxy. The eight DGA example families are synthetic and narrow; labels do not prove current registration, infection, ownership, or malicious use. Unseen family generalization is weak despite family-disjoint testing.
- DNS input is deliberately ASCII LDH-only. Service labels with underscores, internationalized presentation names, malformed compression, encrypted DNS, and names hidden by the capture environment are outside the current event contract. The model uses request names only and does not implement DNS tunnelling or response behavior.
- Runtime joblib loading is safe only for the trusted artifact shipped with this source tree. The loader validates the packaged metadata and SHA-256 before deserialization; it is not an upload endpoint for untrusted model files.
- SYN thresholds and confidence values are fixture-oriented heuristics, not production-calibrated probabilities. Source-IP entropy describes distribution and does not prove spoofing.
- Replay accepts zero timestamp lateness. A regressing merged capture fails instead of being reordered. Zeek UIDs deduplicate within one run but are not durable across captures, versions, or replay modes.
- Hard state and process limits preserve bounded memory and evidence integrity by stopping the current run with a named failure. No production degradation policy or health telemetry exists.
- Native fixtures are IPv4. Strict contracts and SYN detector state have IPv6 unit coverage, but native IPv6 replay is not demonstrated.
- The measured `2.34` microseconds/domain figure is batch model inference only. End-to-end flows/second or Mbps, alert-latency percentiles, CPU, and memory remain unmeasured.
- The API is a loopback-only, unauthenticated local demo service, not a remote or multi-user deployment. It accepts only the `127.0.0.1` Host, rejects any supplied browser Origin other than `http://127.0.0.1:8000`, exposes only fixed committed fixture identifiers, and requires a non-safelisted action header. It must be launched from the repository root so those fixtures resolve.
- Alert storage is process-local and non-persistent. It retains at most 100 strict alerts, evicts the oldest first, and is cleared on server restart; the dashboard requests and renders at most 50 newest-first rows.
- A fixed fixture replay runs synchronously in the single local server event loop. Dashboard polling deliberately pauses until it completes. This keeps the MVP small but is not a production concurrency design.
- Actual empty and three-alert dashboard screenshots exist, but no final PPT deck or end-to-end throughput/latency evidence exists yet.
