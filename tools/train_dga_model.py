"""Train, evaluate, and persist the bounded `dga_logreg_v1` model."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import random
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from typing import Any

import joblib  # type: ignore[import-untyped]
import numpy as np
import sklearn  # type: ignore[import-untyped]
from sklearn.linear_model import LogisticRegression  # type: ignore[import-untyped]
from sklearn.metrics import (  # type: ignore[import-untyped]
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline  # type: ignore[import-untyped]
from sklearn.preprocessing import StandardScaler  # type: ignore[import-untyped]

from sih26145.ml.dns_features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, extract_dns_features

MODEL_VERSION = "dga_logreg_v1"
ARTIFACT_SCHEMA_VERSION = "dga_model_artifact_v1"
DECISION_THRESHOLD = 0.5
SPLIT_SEED = 26_145


@dataclass(frozen=True, slots=True)
class DatasetRow:
    domain: str
    label: int
    family: str
    source: str


@dataclass(frozen=True, slots=True)
class DatasetSplit:
    train: tuple[DatasetRow, ...]
    test: tuple[DatasetRow, ...]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_rows(path: Path) -> tuple[DatasetRow, ...]:
    """Load the strict prepared dataset contract."""

    rows: list[DatasetRow] = []
    seen: set[str] = set()
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != ["domain", "label", "family", "source"]:
            raise ValueError("invalid_dataset_columns")
        for source_row in reader:
            domain = source_row["domain"]
            if domain in seen:
                raise ValueError("duplicate_dataset_domain")
            seen.add(domain)
            try:
                label = int(source_row["label"])
            except ValueError:
                raise ValueError("invalid_dataset_label") from None
            if label not in (0, 1):
                raise ValueError("invalid_dataset_label")
            family = source_row["family"]
            source = source_row["source"]
            if not family or not source:
                raise ValueError("invalid_dataset_group")
            rows.append(DatasetRow(domain, label, family, source))
    if not rows:
        raise ValueError("empty_dataset")
    return tuple(rows)


def _benign_is_test(domain: str) -> bool:
    return hashlib.sha256(domain.encode("ascii")).digest()[0] % 5 == 0


def split_rows(rows: Sequence[DatasetRow]) -> DatasetSplit:
    """Split DGA rows by whole family and unique benign rows by stable hash."""

    dga_families = sorted({row.family for row in rows if row.label == 1})
    if len(dga_families) < 2:
        raise ValueError("at_least_two_dga_families_required")
    shuffled = dga_families.copy()
    random.Random(SPLIT_SEED).shuffle(shuffled)
    test_family_count = max(1, round(len(shuffled) * 0.25))
    test_families = frozenset(shuffled[:test_family_count])

    train: list[DatasetRow] = []
    test: list[DatasetRow] = []
    for row in rows:
        belongs_to_test = (
            row.family in test_families if row.label == 1 else _benign_is_test(row.domain)
        )
        (test if belongs_to_test else train).append(row)

    if {row.label for row in train} != {0, 1} or {row.label for row in test} != {0, 1}:
        raise ValueError("split_must_contain_both_labels")
    return DatasetSplit(tuple(train), tuple(test))


def _matrix(rows: Sequence[DatasetRow]) -> np.ndarray[Any, np.dtype[np.float64]]:
    return np.asarray(
        [extract_dns_features(row.domain).as_vector() for row in rows],
        dtype=np.float64,
    )


def _label_array(rows: Sequence[DatasetRow]) -> np.ndarray[Any, np.dtype[np.int64]]:
    return np.asarray([row.label for row in rows], dtype=np.int64)


def train_and_export(
    *,
    dataset_csv: Path,
    dataset_manifest_path: Path,
    artifact_path: Path,
    metadata_path: Path,
    inference_repetitions: int = 20,
) -> dict[str, Any]:
    """Fit one fixed candidate, evaluate once, and persist artifact metadata."""

    if inference_repetitions <= 0:
        raise ValueError("inference_repetitions_must_be_positive")
    rows = load_rows(dataset_csv)
    split = split_rows(rows)
    train_x = _matrix(split.train)
    train_y = _label_array(split.train)
    test_x = _matrix(split.test)
    test_y = _label_array(split.test)

    model = Pipeline(
        (
            ("scaler", StandardScaler()),
            (
                "classifier",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=2_000,
                    random_state=SPLIT_SEED,
                ),
            ),
        )
    )
    model.fit(train_x, train_y)
    probabilities = model.predict_proba(test_x)[:, 1]
    predictions = (probabilities >= DECISION_THRESHOLD).astype(np.int64)
    tn, fp, fn, tp = (int(value) for value in confusion_matrix(test_y, predictions).ravel())
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0

    model.predict_proba(test_x)
    durations: list[float] = []
    for _ in range(inference_repetitions):
        started = time.perf_counter()
        model.predict_proba(test_x)
        durations.append(time.perf_counter() - started)
    median_batch_seconds = median(durations)
    seconds_per_domain = median_batch_seconds / len(test_x)

    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, artifact_path)
    manifest = json.loads(dataset_manifest_path.read_text(encoding="utf-8"))
    train_families = sorted({row.family for row in split.train if row.label == 1})
    test_families = sorted({row.family for row in split.test if row.label == 1})
    train_domains = {row.domain for row in split.train}
    test_domains = {row.domain for row in split.test}
    metadata: dict[str, Any] = {
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "model_version": MODEL_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "labels": {"benign": 0, "dga": 1},
        "decision_threshold": DECISION_THRESHOLD,
        "classifier": {
            "type": "sklearn.linear_model.LogisticRegression",
            "class_weight": "balanced",
            "max_iter": 2_000,
            "random_state": SPLIT_SEED,
        },
        "preprocessing": {"type": "sklearn.preprocessing.StandardScaler"},
        "dataset": manifest,
        "split": {
            "strategy": "family-disjoint DGA plus SHA-256-bucketed unique benign domains",
            "seed": SPLIT_SEED,
            "train_rows": len(split.train),
            "test_rows": len(split.test),
            "train_dga_families": train_families,
            "test_dga_families": test_families,
            "dga_family_overlap": sorted(set(train_families) & set(test_families)),
            "domain_overlap_count": len(train_domains & test_domains),
        },
        "evaluation": {
            "precision": float(precision_score(test_y, predictions, zero_division=0)),
            "recall": float(recall_score(test_y, predictions, zero_division=0)),
            "f1": float(f1_score(test_y, predictions, zero_division=0)),
            "false_positive_rate": false_positive_rate,
            "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        },
        "cpu_inference": {
            "test_domains": len(test_x),
            "repetitions": inference_repetitions,
            "median_batch_seconds": median_batch_seconds,
            "microseconds_per_domain": seconds_per_domain * 1_000_000,
            "domains_per_second": 1.0 / seconds_per_domain,
        },
        "artifact": {
            "filename": artifact_path.name,
            "bytes": artifact_path.stat().st_size,
            "sha256": _sha256(artifact_path),
        },
        "environment": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "platform": platform.platform(),
        },
        "trained_at_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return metadata


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--dataset-manifest", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        train_and_export(
            dataset_csv=args.dataset,
            dataset_manifest_path=args.dataset_manifest,
            artifact_path=args.artifact,
            metadata_path=args.metadata,
        )
    except (OSError, UnicodeError, ValueError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
