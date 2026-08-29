"""Prepare one bounded DNS lexical dataset from explicit local source files."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from sih26145.contracts.events import normalize_dns_name

MAJESTIC_URL = "https://downloads.majestic.com/majestic_million.csv"
DGA_REPOSITORY_URL = "https://github.com/baderj/domain_generation_algorithms"
PINNED_DGA_REVISION = "0faef452d267a62a94124ef2806bc4a72e0913bd"
MAX_DATASET_LINE_BYTES = 4_096
DEFAULT_DGA_FILES = (
    ("banjori", "banjori/example_domains.txt"),
    ("chinad", "chinad/example_domains.txt"),
    ("fobber", "fobber/domains_1.txt"),
    ("kraken_v1", "kraken/v1/example_domains.txt"),
    ("simda", "simda/example_domains.txt"),
    ("tempedreve", "tempedreve/example_domains.txt"),
    ("tinba", "tinba/example_domains.txt"),
    ("tufik", "tufik/example_domains.txt"),
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _valid_domain(value: str) -> str | None:
    try:
        return normalize_dns_name(value.strip())
    except ValueError:
        return None


def _bounded_utf8_lines(path: Path) -> Iterator[str]:
    with path.open("rb") as handle:
        while raw := handle.readline(MAX_DATASET_LINE_BYTES + 1):
            if len(raw) > MAX_DATASET_LINE_BYTES:
                raise ValueError("dataset_line_too_long")
            try:
                yield raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                raise ValueError("invalid_dataset_encoding") from None


def prepare_dataset(
    *,
    majestic_csv: Path,
    dga_root: Path,
    dga_files: Sequence[tuple[str, str]] = DEFAULT_DGA_FILES,
    output_csv: Path,
    manifest_path: Path,
    dga_revision: str = PINNED_DGA_REVISION,
    benign_limit: int = 20_000,
    per_family_limit: int = 2_000,
) -> dict[str, Any]:
    """Write a deterministic bounded labelled CSV and provenance manifest."""

    if benign_limit <= 0 or per_family_limit <= 0:
        raise ValueError("dataset_limits_must_be_positive")
    if not majestic_csv.is_file() or not dga_root.is_dir():
        raise ValueError("dataset_source_missing")

    rows: list[tuple[str, int, str, str]] = []
    seen_labels: dict[str, int] = {}
    duplicate_count = 0
    invalid_count = 0

    def add(domain: str, label: int, family: str, source: str) -> bool:
        nonlocal duplicate_count
        previous = seen_labels.get(domain)
        if previous is not None:
            if previous != label:
                raise ValueError("conflicting_domain_label")
            duplicate_count += 1
            return False
        seen_labels[domain] = label
        rows.append((domain, label, family, source))
        return True

    benign_count = 0
    with majestic_csv.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or "Domain" not in reader.fieldnames:
            raise ValueError("majestic_domain_column_missing")
        for source_row in reader:
            domain = _valid_domain(source_row.get("Domain", ""))
            if domain is None:
                invalid_count += 1
                continue
            if add(domain, 0, "benign", "majestic"):
                benign_count += 1
                if benign_count == benign_limit:
                    break

    dga_file_records: list[dict[str, Any]] = []
    dga_count = 0
    families: list[str] = []
    for family, relative_path in dga_files:
        source_path = dga_root / relative_path
        if not source_path.is_file():
            raise ValueError("dga_family_file_missing")
        families.append(family)
        family_count = 0
        for line in _bounded_utf8_lines(source_path):
            domain = _valid_domain(line)
            if domain is None:
                invalid_count += 1
                continue
            if add(domain, 1, family, "baderj"):
                family_count += 1
                dga_count += 1
                if family_count == per_family_limit:
                    break
        if family_count == 0:
            raise ValueError("dga_family_has_no_valid_domains")
        dga_file_records.append(
            {
                "family": family,
                "path": relative_path,
                "sha256": _sha256(source_path),
                "selected_rows": family_count,
            }
        )

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(("domain", "label", "family", "source"))
        writer.writerows(rows)

    manifest: dict[str, Any] = {
        "schema_version": "dns_dataset_manifest_v1",
        "sources": {
            "majestic": {
                "url": MAJESTIC_URL,
                "licence": "CC BY 3.0 Unported",
                "sha256": _sha256(majestic_csv),
                "selected_rows": benign_count,
            },
            "dga": {
                "repository": DGA_REPOSITORY_URL,
                "licence": "GPL-2.0",
                "revision": dga_revision,
                "families": families,
                "files": dga_file_records,
                "selected_rows": dga_count,
            },
        },
        "selection_limits": {
            "benign": benign_limit,
            "per_dga_family": per_family_limit,
        },
        "row_counts": {"benign": benign_count, "dga": dga_count, "total": len(rows)},
        "discarded": {"duplicates": duplicate_count, "invalid": invalid_count},
        "dataset_sha256": _sha256(output_csv),
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def _current_revision(dga_root: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(dga_root), "rev-parse", "HEAD"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        shell=False,
        text=True,
    )
    if completed.returncode != 0:
        raise ValueError("dga_revision_unavailable")
    return completed.stdout.strip()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--majestic-csv", type=Path, required=True)
    parser.add_argument("--dga-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        revision = _current_revision(args.dga_root)
        if revision != PINNED_DGA_REVISION:
            raise ValueError("dga_revision_mismatch")
        prepare_dataset(
            majestic_csv=args.majestic_csv,
            dga_root=args.dga_root,
            output_csv=args.output,
            manifest_path=args.manifest,
            dga_revision=revision,
        )
    except (OSError, UnicodeError, ValueError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
