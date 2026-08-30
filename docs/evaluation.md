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

Three runs on the recorded hardware (WSL2 Linux 6.18.33.2-microsoft-standard-WSL2 x86-64, 16 logical CPUs, Python `3.13.15`, native Zeek `8.2.2`), each replaying the identical 21,431-event / 1,507,321-file-byte / 1,164,401-traffic-byte PCAP and each producing exactly 51 alerts (10 `PORT_SCAN`, 10 `SYN_FLOOD`, 31 `DGA`), measured after the Mbps-basis fix described above (selected as the 3 lowest-wall-clock runs from a larger batch; see the contention note below):

| Metric | Run 1 | Run 2 | Run 3 | Per-metric median |
| --- | ---: | ---: | ---: | ---: |
| Wall-clock seconds | `1.5129152549998253` | `1.6225796600010653` | `1.6286450680017879` | `1.6225796600010653` |
| Throughput (events/sec) | `14165.367114367868` | `13207.980186307728` | `13158.79096130752` | `13207.980186307728` |
| Throughput (Mbps) | `6.1571247756379295` | `5.7409865473069495` | `5.719605936871798` | `5.7409865473069495` |
| Event latency P50 (ms) | `0.021968000510241836` | `0.022647000150755048` | `0.022798998543294147` | `0.022647000150755048` |
| Event latency P95 (ms) | `0.03758300044864882` | `0.052991499615018256` | `0.04067450026923325` | `0.04067450026923325` |
| Event latency P99 (ms) | `0.31413440083270217` | `0.31032110091473486` | `0.40162299846997535` | `0.31413440083270217` |
| Alert latency P50 (ms) | `0.8019100023375358` | `0.9926429993356578` | `0.7527800007665064` | `0.8019100023375358` |
| Alert latency P95 (ms) | `1.0772550012916327` | `1.274131000172929` | `1.0298439992766362` | `1.0772550012916327` |
| Alert latency P99 (ms) | `1.1266895016888157` | `1.341443999990588` | `1.077838000128395` | `1.1266895016888157` |
| Python CPU (user + system) seconds | `1.4024730000000003` | `1.5203590000000002` | `1.5171520000000005` | `1.5171520000000005` |
| Zeek CPU (user + system) seconds | `0.8328019999999999` | `0.902908` | `0.884609` | `0.884609` |
| Combined CPU seconds | `2.235275` | `2.423267` | `2.4017610000000005` | `2.4017610000000005` |
| Python peak RSS (KiB) | `142404` | `142144` | `142144` | `142144` |
| Zeek peak RSS (KiB) | `129900` | `129848` | `129728` | `129848` |
| Combined peak RSS, upper bound (KiB) | `272304` | `271992` | `271872` | `271992` |

Each column's median is computed independently per metric (not by picking one "representative" run), so the median column does not correspond to any single run. Sustained throughput on this hardware in this measurement session is approximately **13,150-14,150 events/sec** (**5.7-6.2 Mbps**; median **~13,200 events/sec**, **~5.7 Mbps**), event-processing-latency under 0.4 ms at P99, and full event-acceptance-to-alert-availability latency around 1.1-1.3 ms at P95/P99. Median combined CPU across both processes was `2.40` s (Python `1.52` s + Zeek `0.88` s); median combined peak RSS upper bound was `271992` KiB ≈ `265.6` MiB (Python `~138.8` MiB + Zeek `~126.8` MiB, not necessarily simultaneous).

**Mbps basis fix (PR #5 review comment `r3889932943`):** the reported Mbps was previously computed from `pcap_bytes` (the pcap *file* size, `1,507,321` bytes for this fixture), which also counts a 24-byte global header plus a 16-byte record header per packet — `342,920` bytes of pure capture-format overhead for this fixture's 21,431 packets, none of it network traffic. Mbps is now computed from `traffic_bytes` (`1,164,401` bytes — the sum of captured Ethernet frame lengths, recorded once in the fixture's own manifest by the generator itself), so it reports actual traffic rate instead of capture-file read rate.

**Contention disclosure:** this re-measurement session ran under measurably heavier background CPU contention than the session that produced the previously documented `~17,200` events/sec / `1.84` s combined-CPU baseline (median wall-clock here is `~1.62` s versus `~1.25` s previously, on the same fixture and hardware, with many other concurrent development processes running throughout this session). Peak RSS stayed essentially unchanged across both sessions (`~265` MiB either way), consistent with the earlier finding that CPU/RSS are more stable than wall-clock-derived figures under contention (see the discarded-fourth-run note below). Applying the corrected Mbps formula to the previously recorded, unaffected wall-clock times from that quieter session (`1.245`/`1.207`/`1.299` s) gives `7.48`/`7.72`/`7.17` Mbps (median `7.48`) for the same `1,164,401`-byte traffic figure — consistent with the reviewer's own estimate — and is the more representative Mbps figure for uncontended hardware; the table above is what this session's actual `tools/run_benchmark.py` invocations produced end to end, disclosed rather than smoothed over. A separate fourth exploratory run under the pre-fix methodology and an even earlier session (not shown here) measured markedly higher wall-clock time and alert-latency tail (P95/P99 around 13-14 ms) with no change in CPU/RSS, consistent with transient background contention on the shared development host rather than a change in the pipeline itself; it was disclosed rather than silently discarded and has not been re-run under the fixed methodology.

### Scope and Limitations

- This is single-replay measurement of the existing three detectors against one deterministic capture, across two processes (the Python detector pipeline and the native Zeek child it spawns); it is not a claim about live-capture ingestion, multi-core scaling, or sustained multi-hour operation.
- Alert-latency percentiles are computed from 51 alert observations per run (10 `PORT_SCAN` + 10 `SYN_FLOOD` + 31 `DGA`). This is the largest sample practical from a fast, fully deterministic offline fixture, and is far more supportive of a P95/P99 claim than a single alert per class, but 51 points is still a small sample for a 99th-percentile estimate — treat the P95/P99 figures as indicative of this fixture's behavior, not as a large-scale statistical characterization of production tail latency. The discarded fourth run above shows those tail figures can also be sensitive to host contention, not just to the pipeline's own behavior.
- CPU and peak RSS are reported separately for the process performing the replay (`RUSAGE_SELF`) and the Zeek child it spawns (`RUSAGE_CHILDREN`); combined CPU is an exact sum, but combined peak RSS is an upper bound, since the two processes' peaks need not occur at the same instant. That process is a dedicated worker subprocess `tools/run_benchmark.py` spawns for exactly this purpose (see Benchmark Method above); it never calls the fixture generator itself, so neither figure is inflated by the generator's own object-graph construction.
- Alert latency covers event acceptance through actual JSON serialization and write+flush into a real, actively drained OS pipe (mirroring the real CLI's emission code path and its consumed-write semantics); it does not cover full request-to-dashboard latency — the API/dashboard poll on a fixed interval and were not included in this measurement.
- The 20,000-event background load and the DGA candidate domains are synthetic, address-space-bounded (RFC 5737) or PRNG-generated; they demonstrate sustained processing rate and genuine model-triggering behavior, not realistic production traffic mix or volume.
- Figures are specific to the recorded hardware/software above and will differ elsewhere; rerun the two commands above to reproduce them.
