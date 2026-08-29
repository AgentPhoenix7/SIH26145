# Milestone 3 DNS/DGA ML Design

Status: approved minimum design for implementation on `feature/milestone-3-dns-dga`

## Goal and Scope

Build the smallest genuine passive DNS/DGA ML path that trains, evaluates, persists, and locally runs one CPU Logistic Regression model inside the existing incremental Zeek replay pipeline. Preserve Milestones 1 and 2 unchanged for SYN-only input.

This milestone implements DGA query detection only. Advanced DNS tunnelling, response-behaviour models, online enrichment, remote inference, API, dashboard, general benchmarking, CUDA, deep learning, databases, and additional threat classes are excluded.

## Source and Licence Decision

The benign source is the Majestic Million CSV at `https://downloads.majestic.com/majestic_million.csv`. The live source page states that it is licensed under Creative Commons Attribution 3.0 Unported and identified the 2026-08-29 build at research time. The downloaded snapshot is retained only under ignored `data/`; its retrieval time, byte size, SHA-256, format, selected row count, attribution, and source URL are recorded. Redistribution of the full CSV is unnecessary and excluded.

The DGA source is `baderj/domain_generation_algorithms` pinned to commit `0faef452d267a62a94124ef2806bc4a72e0913bd`. Its repository licence is GNU GPL v2. The preparation step reads selected family-specific example-domain lists from a local pinned checkout and produces labels locally. The GPL source checkout and its lists remain outside Git under ignored `data/`. The project records attribution, revision, selected files, hashes, counts, and the fact that generated output may still require licence review before redistribution. Only a small trained model and metadata are committed; no upstream source code or full list is redistributed.

Limitations are explicit: Majestic popularity is an imperfect proxy for benign DNS; DGA families are algorithm examples rather than observed operational traffic; family coverage is narrow; labels can contain inactive or registered domains; the model does not establish maliciousness; and the legal treatment of trained weights is not asserted beyond recording the source licences and attribution.

## Passive Event Contract

Add `dns_event_v1` for one observed DNS request with these fields:

- `schema_version="dns_event_v1"` and `event_type="dns_query"`;
- capture timestamp and Zeek connection UID;
- client/server IP addresses and ports;
- observed transport, restricted to `udp` or `tcp`;
- normalized lowercase query name without a terminal dot;
- strict positive 16-bit query type and query class values.

The input boundary rejects unknown fields, non-finite or impossible timestamps, invalid addresses/ports, invalid UIDs, non-ASCII or non-hostname query labels, empty labels, labels over 63 bytes, and names over 253 bytes. This deliberate LDH-only MVP limitation excludes service labels containing underscores and Unicode presentation names; it is safer and matches the training/runtime feature domain.

A new combined Zeek policy emits existing `tcp_syn_attempt_v1` records and request-only `dns_event_v1` records incrementally, then one unchanged `control_v1` record whose count and final timestamp cover both event types. It performs no DNS lookup, response wait, aggregation, or network action.

## Shared Lexical Features

One `dns_features_v1` implementation is imported by both training and runtime. It accepts the same normalized query name and returns 12 ordered finite summary values with exact names:

1. domain length excluding dots;
2. label count;
3. longest label length;
4. mean label length;
5. digit ratio;
6. hyphen ratio;
7. vowel ratio;
8. unique-character ratio;
9. Shannon character entropy;
10. unique adjacent-bigram ratio;
11. longest consonant run;
12. longest digit run.

The model vector appends 128 deterministic BLAKE2b-hashed character 2-gram and 3-gram frequency buckets. N-grams never cross DNS label boundaries, bucket values are normalized by the query's n-gram count, and the complete vector therefore has 140 finite values. Typed alerts retain the 12 human-readable values rather than emitting all 128 sparse buckets; runtime validation still recomputes the summary from the recorded query.

Every value is derived only from the passively observed DNS query. There is no WHOIS, resolver lookup, allowlist call, response-dependent feature, wall-clock feature, or Internet inference.

## Dataset Preparation and Leakage Control

The offline preparation tool accepts explicit local Majestic CSV and pinned DGA checkout paths. It reads at most 20,000 unique valid Majestic domains and at most 2,000 unique valid domains per selected DGA family. It produces an ignored CSV with normalized domain, binary label, family/group, and source identifier plus a manifest containing hashes and row accounting. Conflicting duplicate labels fail rather than silently selecting one.

The initial DGA families are selected only from pinned, family-labelled example lists with enough valid rows. DGA train/test membership is family-disjoint: whole families are assigned by a fixed seed and no family appears in both sets. Benign domains are unique and assigned by a stable SHA-256 bucket, with no domain overlap. One fixed Logistic Regression candidate and a fixed `0.5` threshold avoid test-driven model or threshold selection.

## Training, Artifact, and Evaluation

Training calls `dns_features_v1`, then fits `StandardScaler` and `LogisticRegression(class_weight="balanced", random_state=26145, max_iter=2000)` on CPU. The persisted trusted artifact is a joblib pipeline. A strict JSON metadata sidecar records:

- model, feature-schema, artifact-schema, and training-code versions;
- ordered feature names, preprocessing, labels, threshold, and classifier parameters;
- source URLs, licences, revision/snapshot hashes, selected files, counts, and split strategy;
- train/test class and family counts;
- precision, recall, F1, false-positive rate, confusion matrix, artifact bytes, SHA-256, and measured batch CPU inference throughput/latency;
- Python, scikit-learn, platform, and UTC training timestamp.

Accuracy is not a selection metric. The test set is evaluated once after fitting. Metrics describe only this controlled dataset and must not be presented as production performance.

## Runtime Detection and Alert

The CLI loads the packaged artifact and metadata once before Zeek starts. Loading validates the artifact hash, metadata versions, feature order, labels, threshold, and expected sklearn pipeline shape. Runtime does not use the network.

`DetectionPipeline.process` routes SYN events to the two frozen detectors and DNS events to one DGA detector. The DGA detector is stateless and performs bounded work on one query. A probability at or above the recorded threshold emits one strict `alert_v1` with threat class `DGA`, the Zeek UID, client IP, DNS transport, model probability as confidence, detector/model identity, a zero-span capture-time window, and typed evidence containing the query, query type, threshold, feature/model versions, and measured lexical feature values.

The alert means lexical similarity to the training DGA class, not proof of malware or domain ownership. Severity uses the existing confidence bands. Below-threshold DNS queries emit no alert.

## Verification and Acceptance

Acceptance requires all of the following current evidence:

- provenance/licence/format/restriction documentation precedes corpus import;
- strict contract tests cover valid UDP/TCP DNS requests and malformed/unbounded input;
- feature tests use hand-calculated literals and prove training/runtime parity;
- preparation tests prove bounds, normalization, deduplication, provenance accounting, and conflicting-label rejection;
- training tests prove family disjointness, no domain overlap, required metrics, artifact integrity, and local reload parity;
- detector/alert tests prove threshold, below-threshold, typed evidence, and no state growth;
- native generated DNS PCAP replay emits one schema-valid DGA alert before EOS while benign replay emits zero bytes;
- existing Milestone 1 and 2 tests and fixture checks remain green;
- full pytest, Ruff lint/format, strict mypy, locked sync, artifact verification, real replay, and `git diff --check` pass;
- affected architecture, features, evaluation, limitations, traceability, README, PPT notes, dataset research, and `PROGRESS.md` contain measured facts only.
