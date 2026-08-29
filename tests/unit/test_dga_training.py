from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import joblib  # type: ignore[import-untyped]
import numpy as np

from sih26145.ml.dns_features import extract_dns_features
from tools.train_dga_model import load_rows, split_rows, train_and_export


def _dataset(path: Path) -> None:
    rows: list[tuple[str, int, str, str]] = []
    benign = [
        "example.com",
        "openai.com",
        "wikipedia.org",
        "python.org",
        "kernel.org",
        "debian.org",
        "mit.edu",
        "bbc.co.uk",
        "cloudflare.com",
        "mozilla.org",
        "ubuntu.com",
        "ietf.org",
        "w3.org",
        "github.com",
        "gnu.org",
        "apache.org",
        "postgresql.org",
        "rust-lang.org",
        "numpy.org",
        "scipy.org",
    ]
    rows.extend((domain, 0, "benign", "majestic") for domain in benign)
    for family, prefix in (
        ("alpha", "x9q7"),
        ("beta", "z8v6"),
        ("gamma", "k7j5"),
        ("delta", "p6r4"),
    ):
        rows.extend((f"{prefix}{index}m2n8.example", 1, family, "baderj") for index in range(8))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(("domain", "label", "family", "source"))
        writer.writerows(rows)


def test_split_is_family_disjoint_and_has_no_domain_overlap(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset.csv"
    _dataset(dataset)

    split = split_rows(load_rows(dataset))

    train_domains = {row.domain for row in split.train}
    test_domains = {row.domain for row in split.test}
    train_families = {row.family for row in split.train if row.label == 1}
    test_families = {row.family for row in split.test if row.label == 1}
    assert train_domains.isdisjoint(test_domains)
    assert train_families.isdisjoint(test_families)
    assert train_families | test_families == {"alpha", "beta", "gamma", "delta"}
    assert {row.label for row in split.train} == {0, 1}
    assert {row.label for row in split.test} == {0, 1}


def test_training_exports_reloadable_model_and_required_honest_metadata(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset.csv"
    _dataset(dataset)
    dataset_manifest = tmp_path / "dataset.manifest.json"
    dataset_manifest.write_text(
        json.dumps(
            {
                "schema_version": "dns_dataset_manifest_v1",
                "dataset_sha256": hashlib.sha256(dataset.read_bytes()).hexdigest(),
                "sources": {"majestic": {"licence": "CC BY 3.0"}, "dga": {"licence": "GPL-2.0"}},
            }
        ),
        encoding="utf-8",
    )
    artifact = tmp_path / "model.joblib"
    metadata_path = tmp_path / "model.metadata.json"

    metadata = train_and_export(
        dataset_csv=dataset,
        dataset_manifest_path=dataset_manifest,
        artifact_path=artifact,
        metadata_path=metadata_path,
        inference_repetitions=2,
    )

    assert metadata["artifact_schema_version"] == "dga_model_artifact_v1"
    assert metadata["model_version"] == "dga_logreg_v1"
    assert metadata["feature_schema_version"] == "dns_features_v1"
    assert metadata["labels"] == {"benign": 0, "dga": 1}
    assert metadata["decision_threshold"] == 0.5
    assert metadata["split"]["dga_family_overlap"] == []
    assert metadata["split"]["domain_overlap_count"] == 0
    assert set(metadata["evaluation"]) >= {
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
        "confusion_matrix",
    }
    assert metadata["artifact"]["bytes"] == artifact.stat().st_size
    assert metadata["artifact"]["sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert metadata["cpu_inference"]["domains_per_second"] > 0
    assert json.loads(metadata_path.read_text(encoding="utf-8")) == metadata

    model = joblib.load(artifact)
    vector = np.asarray([extract_dns_features("x9q70m2n8.example").as_vector()])
    probability = float(model.predict_proba(vector)[0, 1])
    assert 0.0 <= probability <= 1.0
