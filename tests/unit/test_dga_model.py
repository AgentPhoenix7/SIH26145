from __future__ import annotations

import hashlib
import importlib
import json
import socket
from pathlib import Path
from typing import Any

import joblib  # type: ignore[import-untyped]
import pytest
import sklearn  # type: ignore[import-untyped]

ARTIFACT = Path("src/sih26145/artifacts/dga_logreg_v1.joblib")
METADATA = Path("src/sih26145/artifacts/dga_logreg_v1.metadata.json")


def _module() -> Any:
    return importlib.import_module("sih26145.ml.dga_model")


def test_packaged_model_predicts_locally_without_network(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()

    def fail_socket(*_args: object, **_kwargs: object) -> socket.socket:
        pytest.fail("runtime DGA inference attempted to open a network socket")

    monkeypatch.setattr(socket, "socket", fail_socket)
    model = module.DgaModel.load_packaged()

    assert model.model_version == "dga_logreg_v1"
    assert model.feature_schema_version == "dns_features_v1"
    assert model.decision_threshold == 0.5
    assert model.predict_probability("example.com") < 0.01
    assert model.predict_probability("x9q7z8v6k5j4m3n2.example") > 0.99


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("model_version",), "unknown"),
        (("feature_schema_version",), "dns_features_v2"),
        (("feature_names",), ["wrong"]),
        (("labels",), {"benign": 1, "dga": 0}),
        (("decision_threshold",), 1.0),
        (("artifact", "sha256"), "0" * 64),
    ],
)
def test_loader_rejects_incompatible_or_tampered_metadata(
    path: tuple[str, ...],
    value: object,
    tmp_path: Path,
) -> None:
    module = _module()
    artifact = tmp_path / ARTIFACT.name
    artifact.write_bytes(ARTIFACT.read_bytes())
    metadata: dict[str, Any] = json.loads(METADATA.read_text(encoding="utf-8"))
    target: dict[str, Any] = metadata
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    metadata_path = tmp_path / METADATA.name
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    with pytest.raises(module.DgaModelError):
        module.DgaModel.load(artifact, metadata_path)


def test_loader_rejects_artifact_with_wrong_pipeline_shape(tmp_path: Path) -> None:
    module = _module()
    artifact = tmp_path / ARTIFACT.name
    joblib.dump({"not": "a pipeline"}, artifact)
    metadata: dict[str, Any] = json.loads(METADATA.read_text(encoding="utf-8"))
    metadata["artifact"]["bytes"] = artifact.stat().st_size
    metadata["artifact"]["sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
    metadata_path = tmp_path / METADATA.name
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    with pytest.raises(module.DgaModelError):
        module.DgaModel.load(artifact, metadata_path)


def test_loader_rejects_runtime_sklearn_version_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    artifact = tmp_path / ARTIFACT.name
    artifact.write_bytes(ARTIFACT.read_bytes())
    metadata_path = tmp_path / METADATA.name
    metadata_path.write_bytes(METADATA.read_bytes())
    monkeypatch.setattr(sklearn, "__version__", "1.8.0")

    with pytest.raises(module.DgaModelError, match="incompatible_model_metadata"):
        module.DgaModel.load(artifact, metadata_path)
