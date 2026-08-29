"""Strict local loading and inference for the packaged DGA model."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any, Final, Literal

import joblib  # type: ignore[import-untyped]
import numpy as np
import sklearn  # type: ignore[import-untyped]
from sklearn.linear_model import LogisticRegression  # type: ignore[import-untyped]
from sklearn.pipeline import Pipeline  # type: ignore[import-untyped]
from sklearn.preprocessing import StandardScaler  # type: ignore[import-untyped]

from sih26145.ml.dns_features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, extract_dns_features

ARTIFACT_SCHEMA_VERSION: Final = "dga_model_artifact_v1"
MODEL_VERSION: Literal["dga_logreg_v1"] = "dga_logreg_v1"
DECISION_THRESHOLD: Final = 0.5
_ARTIFACT_FILENAME: Final = "dga_logreg_v1.joblib"
_METADATA_FILENAME: Final = "dga_logreg_v1.metadata.json"


class DgaModelError(ValueError):
    """The local model artifact or its metadata is invalid or incompatible."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mapping(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise DgaModelError("invalid_model_metadata")
    return value


@dataclass(frozen=True, slots=True)
class DgaModel:
    """One validated sklearn pipeline and its fixed runtime contract."""

    _pipeline: Pipeline
    model_version: Literal["dga_logreg_v1"]
    feature_schema_version: Literal["dns_features_v1"]
    decision_threshold: float

    @classmethod
    def load(cls, artifact_path: Path, metadata_path: Path) -> DgaModel:
        """Validate and load one trusted local artifact without network access."""

        try:
            metadata = _mapping(json.loads(metadata_path.read_text(encoding="utf-8")))
            artifact = _mapping(metadata["artifact"])
            environment = _mapping(metadata["environment"])
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
            raise DgaModelError("invalid_model_metadata") from error

        expected_metadata: tuple[tuple[str, object], ...] = (
            ("artifact_schema_version", ARTIFACT_SCHEMA_VERSION),
            ("model_version", MODEL_VERSION),
            ("feature_schema_version", FEATURE_SCHEMA_VERSION),
            ("feature_names", list(FEATURE_NAMES)),
            ("labels", {"benign": 0, "dga": 1}),
            ("decision_threshold", DECISION_THRESHOLD),
        )
        if any(metadata.get(key) != expected for key, expected in expected_metadata):
            raise DgaModelError("incompatible_model_metadata")
        if environment.get("scikit_learn") != sklearn.__version__:
            raise DgaModelError("incompatible_model_metadata")
        if artifact.get("filename") != artifact_path.name:
            raise DgaModelError("incompatible_model_metadata")

        try:
            expected_bytes = artifact["bytes"]
            expected_sha256 = artifact["sha256"]
            actual_bytes = artifact_path.stat().st_size
            actual_sha256 = _sha256(artifact_path)
        except (OSError, KeyError, TypeError) as error:
            raise DgaModelError("invalid_model_artifact") from error
        if (
            not isinstance(expected_bytes, int)
            or isinstance(expected_bytes, bool)
            or expected_bytes <= 0
            or not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or expected_bytes != actual_bytes
            or expected_sha256 != actual_sha256
        ):
            raise DgaModelError("invalid_model_artifact")

        try:
            pipeline = joblib.load(artifact_path)
        except Exception as error:
            raise DgaModelError("invalid_model_artifact") from error
        if not isinstance(pipeline, Pipeline) or list(pipeline.named_steps) != [
            "scaler",
            "classifier",
        ]:
            raise DgaModelError("invalid_model_pipeline")
        scaler = pipeline.named_steps["scaler"]
        classifier = pipeline.named_steps["classifier"]
        if not isinstance(scaler, StandardScaler) or not isinstance(classifier, LogisticRegression):
            raise DgaModelError("invalid_model_pipeline")
        classes = getattr(classifier, "classes_", None)
        if (
            getattr(scaler, "n_features_in_", None) != len(FEATURE_NAMES)
            or getattr(classifier, "n_features_in_", None) != len(FEATURE_NAMES)
            or not isinstance(classes, np.ndarray)
            or not np.array_equal(classes, np.asarray([0, 1]))
            or classifier.class_weight != "balanced"
        ):
            raise DgaModelError("invalid_model_pipeline")

        return cls(
            _pipeline=pipeline,
            model_version=MODEL_VERSION,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            decision_threshold=DECISION_THRESHOLD,
        )

    @classmethod
    def load_packaged(cls) -> DgaModel:
        """Load the model shipped inside the installed ``sih26145`` package."""

        package = files("sih26145").joinpath("artifacts")
        try:
            with (
                as_file(package.joinpath(_ARTIFACT_FILENAME)) as artifact_path,
                as_file(package.joinpath(_METADATA_FILENAME)) as metadata_path,
            ):
                return cls.load(artifact_path, metadata_path)
        except (FileNotFoundError, ModuleNotFoundError) as error:
            raise DgaModelError("packaged_model_missing") from error

    def predict_probability(self, domain: str) -> float:
        """Return the DGA-class probability for one validated passive DNS name."""

        vector = np.asarray([extract_dns_features(domain).as_vector()], dtype=np.float64)
        try:
            probabilities = self._pipeline.predict_proba(vector)
            probability = float(probabilities[0, 1])
        except (IndexError, TypeError, ValueError) as error:
            raise DgaModelError("invalid_model_output") from error
        if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
            raise DgaModelError("invalid_model_output")
        return probability
