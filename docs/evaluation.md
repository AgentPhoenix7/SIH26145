# DNS/DGA Model Evaluation and End-to-End Benchmark

Last verified: **2026-08-30 (UTC)**

## Method

The committed `dga_logreg_v1` artifact is one fixed CPU candidate: `StandardScaler` followed by `LogisticRegression(class_weight="balanced", random_state=26145, max_iter=2000)`. Training and runtime use the same 140-value `dns_features_v1` extractor. The decision threshold is fixed at `0.5`; no second model class or threshold sweep was selected from test results.

The prepared dataset contains 20,000 Majestic domains labelled as a benign proxy and 7,723 generated example domains from eight pinned DGA families. DGA rows are split by whole family using seed `26145`; `kraken_v1` and `simda` are test-only, with no DGA family overlap. Unique benign rows use a stable SHA-256 bucket split. Train and test domain overlap is zero.

## Held-Out Results

The held-out set contains 7,084 domains. These metrics describe only the controlled source mixture and must not be presented as production DNS performance.

| Metric | Measured value |
| --- | ---: |
| Precision | `0.7187797902764538` |
| Recall | `0.25133333333333335` |
| F1 | `0.37243763892319093` |
| False-positive rate | `0.07223310479921645` |
| True negatives | `3789` |
| False positives | `295` |
| False negatives | `2246` |
| True positives | `754` |

Recall is weak and the false-positive rate is too high for an unattended production detector. The model remains the MVP choice because it is the smallest genuinely trained, explainable, CPU-friendly path and the deadline does not justify adding another model class or selecting against the held-out test set. Alerts mean lexical similarity to the training DGA class, not confirmed malware.

## Artifact and CPU Inference

| Item | Measured value |
| --- | --- |
| Artifact | `src/sih26145/artifacts/dga_logreg_v1.joblib` |
| Size | `5,825` bytes |
| SHA-256 | `0627eea04dec557ccf4e6ab2382b6d1e432380bcfa140908dd0da68798e03f47` |
| Environment | Python `3.13.15`, scikit-learn `1.9.0`, WSL2 Linux x86-64 |
| Timed batch | 7,084 test domains, 20 repetitions |
| Median batch time | `0.01658300400004009` seconds |
| Median inference time | `2.340909655567489` microseconds/domain |
| Derived throughput | `427184.36297686916` domains/second |

This is model batch inference only. It excludes Zeek, JSON validation, lexical extraction outside the timed matrix, process startup, alert serialization, CPU utilization, and memory. It is not the required end-to-end traffic-throughput benchmark, which remains unmeasured.

## Replay Evidence

The 124-byte synthetic DNS PCAP has SHA-256 `6d05f57fc1c181f1dfa550ef06796d33cfdf4fa1e694235b04ef73db94410fa3`. Its hand-authored reserved-domain query is absent from the prepared training CSV and receives probability `0.9999563398163442`; native replay emits one 987-byte strict `DGA` alert before EOS. The 111-byte `example.com` PCAP has SHA-256 `d33c5044bf410e55b733aa9bc82f9bf6fbf42436a0333114c3bb89a84cd1a274`, receives probability `0.0018385042677530868`, and emits zero alert bytes.

Both are deterministic controlled examples, not estimates of production true-positive or false-positive rates.

## Milestone 5: End-to-End Throughput, Alert Latency, CPU, and Memory

### Benchmark Method

`tools/generate_benchmark_fixture.py` deterministically generates one offline PCAP (`tests/fixtures/benchmark/sustained_load.pcap`, generated on demand, not committed) mixing:

- 20,000 background TCP SYN packets across 400 source and 200 destination addresses (one fixed destination port), constructed so no source exceeds 15 attempts/ports/hosts and no destination exceeds 100 events/20 sources — i.e. deliberately below every configured `PORT_SCAN`/`SYN_FLOOD` threshold;
- 199 distinct benign DNS queries;
- one exact copy of the verified Milestone 1 `vertical_at_threshold` port-scan pattern (20 attempts, 15 ports, 1 source);
- one exact copy of the verified Milestone 2 `syn_flood_at_threshold` pattern (100 events, 20 sources, 1 target); and
- one exact copy of the verified Milestone 3 benign/DGA DNS pair.

`tools/run_benchmark.py` replays this PCAP once through the unmodified `sih26145.runtime.build_detection_pipeline` output via the existing `sih26145.replay.run_replay`/`run_command` path. It measures, without touching any detector, contract, or replay-runner code:

- **event processing latency**: wall-clock time for `DetectionPipeline.process` to return for one validated event (a `TimingPipeline` subclass of the frozen `DetectionPipeline` timing each call; subclassing, not wrapping, is required because `run_command` only routes DNS events to a detector that `isinstance`-checks true as `DetectionPipeline`);
- **alert latency**: the same measurement, restricted to the events that produced an alert — because the emit callback runs immediately after `process` returns for that event, this is the actual event-to-alert time;
- **throughput**: total events processed and PCAP bytes divided by total wall-clock replay time (`events/sec`, `Mbps`); and
- **CPU/memory**: `resource.getrusage(RUSAGE_SELF)` before/after the run, for this Python process only — it excludes the separate native Zeek child process, whose cost is already reflected in the wall-clock throughput figure.

Exact commands:

```bash
uv run python tools/generate_benchmark_fixture.py --output tests/fixtures/benchmark
uv run python tools/run_benchmark.py --pcap tests/fixtures/benchmark/sustained_load.pcap
```

### Benchmark Results

Three consecutive runs on the recorded hardware (WSL2 Linux 6.18.33.2-microsoft-standard-WSL2 x86-64, 16 logical CPUs, Python `3.13.15`, native Zeek `8.2.2`), each replaying the identical 20,321-event / 1,428,710-byte PCAP and each producing exactly 3 alerts (`PORT_SCAN`, `SYN_FLOOD`, `DGA`):

| Metric | Run 1 | Run 2 | Run 3 |
| --- | ---: | ---: | ---: |
| Wall-clock seconds | `1.5279686940002648` | `1.389276164999501` | `1.3819525090002571` |
| Throughput (events/sec) | `13299.356249766513` | `14627.041413330013` | `14704.557405305322` |
| Throughput (Mbps) | `7.480310326304381` | `8.227075572122915` | `8.270674951246008` |
| Event latency P50 (ms) | `0.02022700027737301` | `0.02150999989680713` | `0.020941000002494548` |
| Event latency P95 (ms) | `0.03764499979297398` | `0.03272499998274725` | `0.03325400030007586` |
| Event latency P99 (ms) | `0.46988899975985754` | `0.3515155995046368` | `0.35421979973761997` |
| Alert latency P50 (ms) | `0.4157579996899585` | `0.35051699978794204` | `0.3752349994101678` |
| Alert latency P95 (ms) | `0.9318422995420406` | `0.8929757994337706` | `0.9213559000272653` |
| Alert latency P99 (ms) | `0.9777164595288923` | `0.9411943594022887` | `0.9698999800821184` |
| CPU user seconds | `1.2765019999999998` | `1.1296470000000003` | `1.084359` |
| CPU system seconds | `0.12413199999999999` | `0.132637` | `0.12412299999999998` |
| Peak RSS (KiB) | `143556` | `143484` | `143412` |

Run-to-run variance is consistent with cold-start effects in run 1 (Python/model warm-up dominates the first replay's CPU time and P99 tail); runs 2-3 are the more representative steady-state figures. Sustained throughput on this hardware is approximately **13,300-14,700 events/sec** (**7.5-8.3 Mbps**), with detector-side (non-I/O) per-event processing at sub-millisecond P99 and alert latency (event acceptance to alert availability) under 1 ms at P99. Peak process memory stayed at approximately 140 MiB, dominated by the loaded scikit-learn pipeline and Python/numpy/scikit-learn runtime, not by any unbounded per-event state.

### Scope and Limitations

- This is single-process, single-replay, CPU-only measurement of the existing three detectors against one deterministic capture; it is not a claim about live-capture ingestion, multi-core scaling, or sustained multi-hour operation.
- CPU/RSS cover the Python process only; the separate native Zeek child process is unmeasured directly, though its cost is included in wall-clock throughput.
- "Alert latency" here is processing latency for the causing event, not full request-to-dashboard latency; the API/dashboard poll on a fixed interval and were not included in this measurement.
- The 20,000-event background load is synthetic and address-space-bounded (RFC 5737 ranges); it demonstrates sustained processing rate, not realistic production traffic mix or volume.
- Figures are specific to the recorded hardware/software above and will differ elsewhere; rerun the two commands above to reproduce them.
