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
- 10 independent copies of the verified Milestone 1 `vertical_at_threshold` port-scan pattern (20 attempts, 15 unique ports each — the exact Milestone 1 threshold shape), each from its own unused source address so every incident fires its own alert without relying on cooldown expiry;
- 10 independent copies of the verified Milestone 2 `syn_flood_at_threshold` pattern (100 events, 20 unique sources each), each against its own unused target address; and
- one benign control query plus the verified Milestone 3 DGA domain and further deterministic high-entropy candidate domains, kept only when the actual packaged `dga_logreg_v1` model scores them above its own decision threshold (31 qualified in the current fixture) — so every embedded "DGA" packet is a genuine, model-verified trigger, not an assumed one.

Using several independent alert-triggering incidents per class (51 total: 10 `PORT_SCAN` + 10 `SYN_FLOOD` + 31 `DGA`), rather than one alert per class, is what makes the alert-latency P95/P99 figures below more than an interpolation over a handful of points — see Scope and Limitations for how much confidence that sample size still supports.

`tools/run_benchmark.py` replays this PCAP once through the unmodified `sih26145.runtime.build_detection_pipeline` output via the existing `sih26145.replay.run_replay`/`run_command` path. It measures, without touching any detector, contract, or replay-runner code:

- **event processing latency**: wall-clock time for `DetectionPipeline.process` to return for one validated event (a `TimingPipeline` subclass of the frozen `DetectionPipeline` timing each call; subclassing, not wrapping, is required because `run_command` only routes DNS events to a detector that `isinstance`-checks true as `DetectionPipeline`);
- **alert latency**: wall-clock time from that same `process` call's start to the moment the alert has actually been serialized and written+flushed by an emit callback that performs the identical work as the real CLI's `sih26145.cli.emit_alert` (JSON serialization, then write and flush — to `os.devnull` instead of the terminal, so the benchmark's own output stays clean). Because `run_command` calls the emit callback immediately after `process` returns for the causing event, and finishes all of one event's emits before reading the next line, this is genuinely the event-acceptance-to-alert-availability interval, not detector time alone;
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
| Wall-clock seconds | `1.4972120430002178` | `1.3710026990002007` | `1.262704711999504` | `1.3710026990002007` |
| Throughput (events/sec) | `14313.937761985315` | `15631.62495276522` | `16972.29747884905` | `15631.62495276522` |
| Throughput (Mbps) | `8.054014831350274` | `8.795437097821669` | `9.549792509212349` | `8.795437097821669` |
| Event latency P50 (ms) | `0.021727000785176642` | `0.019453000277280807` | `0.01889000031951582` | `0.019453000277280807` |
| Event latency P95 (ms) | `0.0348990001839411` | `0.032185999771172646` | `0.029844999971828656` | `0.032185999771172646` |
| Event latency P99 (ms) | `0.40978139977596767` | `0.3319017000649186` | `0.33041010019587763` | `0.3319017000649186` |
| Alert latency P50 (ms) | `0.8233239996116026` | `0.627475000328559` | `0.6756940001650946` | `0.6756940001650946` |
| Alert latency P95 (ms) | `1.018835000195395` | `0.8100005002233956` | `0.8157224997376034` | `0.8157224997376034` |
| Alert latency P99 (ms) | `1.0478935000719503` | `0.8733835002203705` | `0.8570174995838897` | `0.8733835002203705` |
| CPU (user + system) seconds | `1.3842870000000005` | `1.2693199999999996` | `1.1575029999999997` | `1.2693199999999996` |
| Peak RSS (KiB) | `143780` | `143952` | `143768` | `143780` |

Each column's median is computed independently per metric (not by picking one "representative" run), so the median column does not correspond to any single run. Sustained throughput on this hardware is approximately **14,300-17,000 events/sec** (**8.1-9.5 Mbps**; median **~15,600 events/sec**, **~8.8 Mbps**), with detector-side (non-I/O) per-event processing under 0.5 ms at P99, and full event-acceptance-to-alert-availability latency (detector work plus actual JSON serialization and write+flush) around 0.7-1.0 ms at P95/P99. Peak process memory stayed at approximately 140 MiB, dominated by the loaded scikit-learn pipeline and Python/numpy/scikit-learn runtime, not by any unbounded per-event state.

### Scope and Limitations

- This is single-process, single-replay, CPU-only measurement of the existing three detectors against one deterministic capture; it is not a claim about live-capture ingestion, multi-core scaling, or sustained multi-hour operation.
- Alert-latency percentiles are computed from 51 alert observations per run (10 `PORT_SCAN` + 10 `SYN_FLOOD` + 31 `DGA`). This is the largest sample practical from a fast, fully deterministic offline fixture, and is far more supportive of a P95/P99 claim than a single alert per class, but 51 points is still a small sample for a 99th-percentile estimate — treat the P95/P99 figures as indicative of this fixture's behavior, not as a large-scale statistical characterization of production tail latency.
- CPU/RSS cover the Python process only; the separate native Zeek child process is unmeasured directly, though its cost is included in wall-clock throughput.
- Alert latency covers event acceptance through actual JSON serialization and write+flush (mirroring the real CLI's emission code path, aimed at `os.devnull`); it does not cover full request-to-dashboard latency — the API/dashboard poll on a fixed interval and were not included in this measurement.
- The 20,000-event background load and the DGA candidate domains are synthetic, address-space-bounded (RFC 5737) or PRNG-generated; they demonstrate sustained processing rate and genuine model-triggering behavior, not realistic production traffic mix or volume.
- Figures are specific to the recorded hardware/software above and will differ elsewhere; rerun the two commands above to reproduce them.
