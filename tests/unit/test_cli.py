from __future__ import annotations

from pathlib import Path

import pytest

import sih26145.cli as cli
from sih26145.ml.dga_model import DgaModelError


def test_invalid_packaged_model_fails_before_zeek_starts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"placeholder")

    def invalid_model() -> None:
        raise DgaModelError("invalid_model_artifact")

    def unexpected_replay(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Zeek replay started before packaged model validation")

    monkeypatch.setattr("sih26145.ml.dga_model.DgaModel.load_packaged", invalid_model)
    monkeypatch.setattr(cli, "run_replay", unexpected_replay)

    exit_code = cli.main([str(pcap)])

    assert exit_code == 2
    assert capsys.readouterr().err == "configuration_error: invalid_dga_model\n"
