# DNS/DGA Model Evaluation

Last verified: **2026-08-29 (UTC)**

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
