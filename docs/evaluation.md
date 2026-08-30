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
- **throughput**: total events processed divided by total wall-clock replay time (`events/sec`); and megabits/sec computed from the fixture's own manifest-recorded `total_captured_bytes` (the sum of captured Ethernet frame lengths, computed once by `tools/generate_benchmark_fixture.py`) divided by wall-clock time — not the pcap *file* size, which also counts the 24-byte global header plus a 16-byte record header per packet: for this fixture's 21,431 packets that is 342,920 bytes of pure capture-format overhead (`24 + 21431*16`) out of `1,507,321` total file bytes, so using the file size would report capture-file read rate rather than network traffic rate; and
- **CPU/memory**: `resource.getrusage` sampled around the actual replay, once for the process performing it (`RUSAGE_SELF`) and once for the native Zeek child it spawns and fully waits for (`RUSAGE_CHILDREN`). Validating the candidate PCAP against the fixture generator's current output (`tools/generate_benchmark_fixture.py --fixture-info`) and performing/measuring the replay itself (`_measure_replay`) each run in their own dedicated subprocess, so the generator's own ~21,431-packet object-graph construction — which is unrelated to the detector replay being measured — cannot inflate either the reported Python or the reported Zeek figures the way sharing one process would (a review finding on PR #5 caught exactly this: an earlier revision validated in-process before sampling `RUSAGE_SELF`, and a first attempted fix moved that work into a subprocess reaped *before* Zeek, which instead inflated the reported Zeek RSS through `RUSAGE_CHILDREN`'s cross-child high-water mark). The replay-measuring subprocess spawns no child other than Zeek, so its `RUSAGE_CHILDREN` reliably isolates Zeek's own contribution. Combined CPU seconds are a straightforward sum of both; combined peak RSS is reported as a conservative upper bound (the two processes' peaks are not necessarily simultaneous, so the true combined peak can only be lower).

Exact commands:

```bash
uv run python tools/generate_benchmark_fixture.py --output tests/fixtures/benchmark
uv run python tools/run_benchmark.py --pcap tests/fixtures/benchmark/sustained_load.pcap
```

### Benchmark Results

**Run-selection policy (PR #5 review comment `r3889981882`):** the table below reports a predefined, fixed-size batch of **5 consecutive runs** of `tools/run_benchmark.py`, taken in full — no run is selected, reordered, or discarded by its own result. An earlier revision of this document instead hand-picked the 3 lowest-wall-clock runs out of a larger unshown batch, which systematically biases throughput up and latency down versus genuinely repeated performance; that selection is not used here or anywhere else in this repository's benchmark evidence.

Five runs on the recorded hardware (WSL2 Linux 6.18.33.2-microsoft-standard-WSL2 x86-64, 16 logical CPUs, Python `3.13.15`, native Zeek `8.2.2`), each replaying the identical 21,431-event / 1,507,321-file-byte / 1,164,401-traffic-byte PCAP and each producing exactly 51 alerts (10 `PORT_SCAN`, 10 `SYN_FLOOD`, 31 `DGA`), measured back to back after the Mbps-basis fix described above:

| Metric | Run 1 | Run 2 | Run 3 | Run 4 | Run 5 | Per-metric median |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Wall-clock seconds | `1.6984185520013853` | `1.3288530280005943` | `1.4654914329985331` | `1.4495518250005262` | `1.3212461350012745` | `1.4495518250005262` |
| Throughput (events/sec) | `12618.20884772255` | `16127.441897954131` | `14623.763413034876` | `14784.569706565835` | `16220.293427749044` | `14784.569706565835` |
| Throughput (Mbps) | `5.48463627474107` | `7.009961074488242` | `6.356371514871438` | `6.426267650000454` | `7.050319961761716` | `6.426267650000454` |
| Event latency P50 (ms) | `0.02164599936804734` | `0.01878200055216439` | `0.02012200275203213` | `0.02105299790855497` | `0.01982500180019997` | `0.02012200275203213` |
| Event latency P95 (ms) | `0.03662249946501106` | `0.032302499676006846` | `0.0349375004589092` | `0.03347650090290699` | `0.03278500116721261` | `0.03347650090290699` |
| Event latency P99 (ms) | `0.43326030099706275` | `0.4223625994200122` | `0.3720998007338503` | `0.4056084006151651` | `0.3611190008086852` | `0.4056084006151651` |
| Alert latency P50 (ms) | `1.0537359994486906` | `0.7429260003846139` | `0.8806789992377162` | `0.8623049980087671` | `0.8414309995714575` | `0.8623049980087671` |
| Alert latency P95 (ms) | `1.2616905005415902` | `0.936526999794296` | `1.0854489992198069` | `1.015873498545261` | `1.0179249984503258` | `1.0179249984503258` |
| Alert latency P99 (ms) | `1.4682225009892136` | `0.995628999589826` | `1.2046859992551617` | `1.049311500537442` | `1.0392329986643745` | `1.049311500537442` |
| Python CPU (user + system) seconds | `1.4483790000000005` | `1.2209809999999999` | `1.32757` | `1.350709` | `1.235373` | `1.32757` |
| Zeek CPU (user + system) seconds | `0.88591` | `0.720517` | `0.8203750000000001` | `0.7824249999999999` | `0.702801` | `0.7824249999999999` |
| Combined CPU seconds | `2.3342890000000005` | `1.941498` | `2.147945` | `2.133134` | `1.938174` | `2.133134` |
| Python peak RSS (KiB) | `142056` | `142204` | `142108` | `142216` | `142392` | `142204` |
| Zeek peak RSS (KiB) | `129708` | `130044` | `129632` | `129780` | `129884` | `129780` |
| Combined peak RSS, upper bound (KiB) | `271764` | `272248` | `271740` | `271996` | `272276` | `271996` |

Each column's median is computed independently per metric across all 5 runs (not by picking one "representative" run), so the median column does not correspond to any single run. Sustained throughput on this hardware in this measurement session ranged **12,600-16,250 events/sec** (**5.5-7.1 Mbps**; median **~14,800 events/sec**, **~6.4 Mbps**) across the 5 runs, event-processing-latency stayed under 0.5 ms at P99 in every run, and full event-acceptance-to-alert-availability latency ranged roughly 0.94-1.47 ms at P95/P99 (median P95 `1.02` ms, median P99 `1.05` ms). Median combined CPU across both processes was `2.13` s (Python `1.33` s + Zeek `0.78` s); median combined peak RSS upper bound was `271996` KiB ≈ `265.6` MiB (Python `~138.9` MiB + Zeek `~126.7` MiB, not necessarily simultaneous). The spread between the fastest and slowest of the 5 runs (`12,618` to `16,220` events/sec, roughly ±13% around the median) reflects ordinary background contention on a shared development host and is disclosed here rather than narrowed by post-hoc run selection.

**Mbps basis fix (PR #5 review comment `r3889932943`):** Mbps is computed from `traffic_bytes` (`1,164,401` bytes — the sum of captured Ethernet frame lengths, recorded once in the fixture's own manifest by the generator itself), not `pcap_bytes` (the pcap *file* size, `1,507,321` bytes for this fixture, which also counts a 24-byte global header plus a 16-byte record header per packet — `342,920` bytes of pure capture-format overhead, none of it network traffic).

### Scope and Limitations

- This is single-replay measurement of the existing three detectors against one deterministic capture, across two processes (the Python detector pipeline and the native Zeek child it spawns); it is not a claim about live-capture ingestion, multi-core scaling, or sustained multi-hour operation.
- Alert-latency percentiles are computed from 51 alert observations per run (10 `PORT_SCAN` + 10 `SYN_FLOOD` + 31 `DGA`). This is the largest sample practical from a fast, fully deterministic offline fixture, and is far more supportive of a P95/P99 claim than a single alert per class, but 51 points is still a small sample for a 99th-percentile estimate — treat the P95/P99 figures as indicative of this fixture's behavior, not as a large-scale statistical characterization of production tail latency. The ~13% spread between the fastest and slowest of the 5 reported runs shows those tail figures are also sensitive to ordinary host contention, not just to the pipeline's own behavior.
- CPU and peak RSS are reported separately for the process performing the replay (`RUSAGE_SELF`) and the Zeek child it spawns (`RUSAGE_CHILDREN`); combined CPU is an exact sum, but combined peak RSS is an upper bound, since the two processes' peaks need not occur at the same instant. That process is a dedicated worker subprocess `tools/run_benchmark.py` spawns for exactly this purpose (see Benchmark Method above); it never calls the fixture generator itself, so neither figure is inflated by the generator's own object-graph construction.
- Alert latency covers event acceptance through actual JSON serialization and write+flush into a real, actively drained OS pipe (mirroring the real CLI's emission code path and its consumed-write semantics); it does not cover full request-to-dashboard latency — the API/dashboard poll on a fixed interval and were not included in this measurement.
- The 20,000-event background load and the DGA candidate domains are synthetic, address-space-bounded (RFC 5737) or PRNG-generated; they demonstrate sustained processing rate and genuine model-triggering behavior, not realistic production traffic mix or volume.
- Figures are specific to the recorded hardware/software above and will differ elsewhere; rerun the two commands above to reproduce them.
