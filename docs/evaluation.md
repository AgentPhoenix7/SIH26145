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

This is model batch inference only. It excludes Zeek, JSON validation, lexical extraction outside the timed matrix, process startup, alert serialization, CPU utilization, and memory. It is not the required end-to-end traffic-throughput benchmark; that benchmark is measured separately below (see "Milestone 5: End-to-End Throughput, Alert Latency, CPU, and Memory").

## Replay Evidence

The 124-byte synthetic DNS PCAP has SHA-256 `6d05f57fc1c181f1dfa550ef06796d33cfdf4fa1e694235b04ef73db94410fa3`. Its hand-authored reserved-domain query is absent from the prepared training CSV and receives probability `0.9999563398163442`; native replay emits one 987-byte strict `DGA` alert before EOS. The 111-byte `example.com` PCAP has SHA-256 `d33c5044bf410e55b733aa9bc82f9bf6fbf42436a0333114c3bb89a84cd1a274`, receives probability `0.0018385042677530868`, and emits zero alert bytes.

Both are deterministic controlled examples, not estimates of production true-positive or false-positive rates.

## Milestone 5: End-to-End Throughput, Alert Latency, CPU, and Memory

### Benchmark Method

`tools/generate_benchmark_fixture.py` deterministically generates one offline PCAP (`tests/fixtures/benchmark/sustained_load.pcap`, generated on demand, not committed) mixing:

- 20,000 background TCP SYN packets across 400 source and 200 destination addresses. Measured directly by instrumenting the real `PortScanDetector`/`SynFloodDetector` against this exact traffic: within any 10-second rolling window, a source reaches up to 26 attempts (above `PORT_SCAN`'s `minimum_attempts=20`) but only 1 unique destination port and 1 unique destination host (both far under `unique_ports>=15`/`unique_hosts>=15`, so that condition alone already prevents a `PORT_SCAN` alert regardless of attempt count); a destination receives up to 51 events within its rolling window (already below `SYN_FLOOD`'s `minimum_syn_events=100`, not merely close to it — the window is 10 seconds but the full 20,000-event background block spans about 20 seconds, so at most half of any one destination's total traffic falls inside one window) from only 2 unique sources (also far under `unique_sources>=20`), so both halves of `SYN_FLOOD`'s AND condition fail;
- 199 distinct benign DNS queries;
- 10 independent copies of the verified Milestone 1 `vertical_at_threshold` port-scan pattern (20 attempts, 15 unique ports each — the exact Milestone 1 threshold shape), each from its own unused source address so every incident fires its own alert without relying on cooldown expiry;
- 10 independent copies of the verified Milestone 2 `syn_flood_at_threshold` pattern (100 events, 20 unique sources each), each against its own unused target address; and
- one benign control query plus the verified Milestone 3 DGA domain and further deterministic high-entropy candidate domains, kept only when the actual packaged `dga_logreg_v1` model scores them above its own decision threshold (31 qualified in the current fixture) — so every embedded "DGA" packet is a genuine, model-verified trigger, not an assumed one.

Using several independent alert-triggering incidents per class (51 total: 10 `PORT_SCAN` + 10 `SYN_FLOOD` + 31 `DGA`), rather than one alert per class, is what makes the alert-latency P95/P99 figures below more than an interpolation over a handful of points — see Scope and Limitations for how much confidence that sample size still supports.

`tools/run_benchmark.py` replays this PCAP once through the unmodified `sih26145.runtime.build_detection_pipeline` output via the existing `sih26145.replay.run_replay`/`run_command` path. It measures, without touching any detector, contract, or replay-runner code:

- **event processing latency**: wall-clock time for `DetectionPipeline.process` to return for one validated event (a `TimingPipeline` subclass of the frozen `DetectionPipeline` timing each call; subclassing, not wrapping, is required because `run_command` only routes DNS events to a detector that `isinstance`-checks true as `DetectionPipeline`);
- **alert latency**: wall-clock time from that same `process` call's start to the moment the alert has actually been serialized and written+flushed by an emit callback that performs the identical work as the real CLI's `sih26145.cli.emit_alert` (JSON serialization, then write and flush — into a real OS pipe drained by a background reader thread, exercising the same kernel write/consume path as the real CLI's `sys.stdout` when piped to a consumer, rather than an always-instant `os.devnull` sink, while keeping the benchmark's own output clean). Because `run_command` calls the emit callback immediately after `process` returns for the causing event, and finishes all of one event's emits before reading the next line, this is genuinely the event-acceptance-to-alert-availability interval, not detector time alone;
- **throughput**: total events processed and PCAP bytes divided by total wall-clock replay time (`events/sec`, `Mbps`); and
- **CPU/memory**: `resource.getrusage(RUSAGE_SELF)` before/after the run, for this Python process only — it excludes the separate native Zeek child process, whose cost is already reflected in the wall-clock throughput figure.

Exact commands:

```bash
uv run python tools/generate_benchmark_fixture.py --output tests/fixtures/benchmark
uv run python tools/run_benchmark.py --pcap tests/fixtures/benchmark/sustained_load.pcap
```

### Benchmark Results

Three consecutive runs on the recorded hardware (WSL2 Linux 6.18.33.2-microsoft-standard-WSL2 x86-64, 16 logical CPUs, Python `3.13.15`, native Zeek `8.2.2`), each replaying the identical 21,431-event / 1,507,321-byte PCAP and each producing exactly 51 alerts (10 `PORT_SCAN`, 10 `SYN_FLOOD`, 31 `DGA`):

| Metric | Run 1 | Run 2 | Run 3 | Per-metric median |
| --- | ---: | ---: | ---: | ---: |
| Wall-clock seconds | `1.3595791780007858` | `1.5187772850003967` | `1.4144621340001322` | `1.4144621340001322` |
| Throughput (events/sec) | `15762.965737319944` | `14110.692997357017` | `15151.342326423844` | `15151.342326423844` |
| Throughput (Mbps) | `8.869338538805593` | `7.939655220743474` | `8.52519675864216` | `8.52519675864216` |
| Event latency P50 (ms) | `0.019316001271363348` | `0.02198799847974442` | `0.021190000552451238` | `0.021190000552451238` |
| Event latency P95 (ms) | `0.03622800068114884` | `0.03471099989837967` | `0.03504550022626063` | `0.03504550022626063` |
| Event latency P99 (ms) | `0.35029579958063567` | `0.4650234988730519` | `0.4234039011862481` | `0.4234039011862481` |
| Alert latency P50 (ms) | `0.8388999995077029` | `0.7856600004743086` | `0.6848800003353972` | `0.7856600004743086` |
| Alert latency P95 (ms) | `0.9878585005935747` | `0.946268999541644` | `0.8249559996329481` | `0.946268999541644` |
| Alert latency P99 (ms) | `1.0792134999064729` | `0.9611939995011198` | `0.8763784999246127` | `0.9611939995011198` |
| CPU (user + system) seconds | `1.268416` | `1.4173379999999995` | `1.324026` | `1.324026` |
| Peak RSS (KiB) | `141636` | `141832` | `141732` | `141732` |

Each column's median is computed independently per metric (not by picking one "representative" run), so the median column does not correspond to any single run. Sustained throughput on this hardware is approximately **14,100-15,800 events/sec** (**7.9-8.9 Mbps**; median **~15,150 events/sec**, **~8.5 Mbps**), with detector-side (non-I/O) per-event processing under 0.5 ms at P99, and full event-acceptance-to-alert-availability latency (detector work plus actual JSON serialization and write+flush into a real, actively drained OS pipe) around 0.9-1.0 ms at P95/P99. Peak process memory stayed at approximately 138-139 MiB (median `141732` KiB ≈ `138.4` MiB), dominated by the loaded scikit-learn pipeline and Python/numpy/scikit-learn runtime, not by any unbounded per-event state.

### Scope and Limitations

- This is single-process, single-replay, CPU-only measurement of the existing three detectors against one deterministic capture; it is not a claim about live-capture ingestion, multi-core scaling, or sustained multi-hour operation.
- Alert-latency percentiles are computed from 51 alert observations per run (10 `PORT_SCAN` + 10 `SYN_FLOOD` + 31 `DGA`). This is the largest sample practical from a fast, fully deterministic offline fixture, and is far more supportive of a P95/P99 claim than a single alert per class, but 51 points is still a small sample for a 99th-percentile estimate — treat the P95/P99 figures as indicative of this fixture's behavior, not as a large-scale statistical characterization of production tail latency.
- CPU/RSS cover the Python process only; the separate native Zeek child process is unmeasured directly, though its cost is included in wall-clock throughput.
- Alert latency covers event acceptance through actual JSON serialization and write+flush into a real, actively drained OS pipe (mirroring the real CLI's emission code path and its consumed-write semantics); it does not cover full request-to-dashboard latency — the API/dashboard poll on a fixed interval and were not included in this measurement.
- The 20,000-event background load and the DGA candidate domains are synthetic, address-space-bounded (RFC 5737) or PRNG-generated; they demonstrate sustained processing rate and genuine model-triggering behavior, not realistic production traffic mix or volume.
- Figures are specific to the recorded hardware/software above and will differ elsewhere; rerun the two commands above to reproduce them.
