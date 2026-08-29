from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest

from tools.prepare_dns_dataset import prepare_dataset


def _write_majestic(path: Path, domains: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["GlobalRank", "Domain"])
        writer.writeheader()
        for rank, domain in enumerate(domains, start=1):
            writer.writerow({"GlobalRank": rank, "Domain": domain})


def test_prepare_dataset_caps_normalizes_deduplicates_and_records_hashes(tmp_path: Path) -> None:
    majestic = tmp_path / "majestic.csv"
    _write_majestic(majestic, ["Example.COM", "openai.com", "example.com", "third.org"])
    dga_root = tmp_path / "dga"
    (dga_root / "alpha").mkdir(parents=True)
    (dga_root / "beta").mkdir()
    alpha = dga_root / "alpha" / "domains.txt"
    beta = dga_root / "beta" / "domains.txt"
    alpha.write_text("x1q9.example\nBAD..NAME\nx1q9.example\na9z8.test\n", encoding="utf-8")
    beta.write_text("qq77.example\nzz88.example\n", encoding="utf-8")
    output = tmp_path / "dataset.csv"
    manifest_path = tmp_path / "manifest.json"

    manifest = prepare_dataset(
        majestic_csv=majestic,
        dga_root=dga_root,
        dga_files=(("alpha", "alpha/domains.txt"), ("beta", "beta/domains.txt")),
        output_csv=output,
        manifest_path=manifest_path,
        dga_revision="0123456789abcdef",
        benign_limit=2,
        per_family_limit=1,
    )

    rows = list(csv.DictReader(output.read_text(encoding="utf-8").splitlines()))
    assert rows == [
        {"domain": "example.com", "label": "0", "family": "benign", "source": "majestic"},
        {"domain": "openai.com", "label": "0", "family": "benign", "source": "majestic"},
        {"domain": "x1q9.example", "label": "1", "family": "alpha", "source": "baderj"},
        {"domain": "qq77.example", "label": "1", "family": "beta", "source": "baderj"},
    ]
    assert manifest["schema_version"] == "dns_dataset_manifest_v1"
    assert manifest["row_counts"] == {"benign": 2, "dga": 2, "total": 4}
    assert (
        manifest["sources"]["majestic"]["sha256"]
        == hashlib.sha256(majestic.read_bytes()).hexdigest()
    )
    assert manifest["sources"]["dga"]["revision"] == "0123456789abcdef"
    assert manifest["sources"]["dga"]["families"] == ["alpha", "beta"]
    assert manifest["dataset_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    assert json.loads(manifest_path.read_text(encoding="utf-8")) == manifest


def test_prepare_dataset_rejects_conflicting_labels(tmp_path: Path) -> None:
    majestic = tmp_path / "majestic.csv"
    _write_majestic(majestic, ["same.example"])
    dga_root = tmp_path / "dga"
    (dga_root / "alpha").mkdir(parents=True)
    (dga_root / "alpha" / "domains.txt").write_text("same.example\n", encoding="utf-8")

    with pytest.raises(ValueError, match="conflicting_domain_label"):
        prepare_dataset(
            majestic_csv=majestic,
            dga_root=dga_root,
            dga_files=(("alpha", "alpha/domains.txt"),),
            output_csv=tmp_path / "dataset.csv",
            manifest_path=tmp_path / "manifest.json",
            dga_revision="0123456789abcdef",
        )
