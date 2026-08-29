from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

import pytest

import sih26145.cli as cli
import sih26145.replay as replay
from sih26145.contracts.alerts import AlertV1, DgaEvidence
from sih26145.contracts.events import EndOfStreamV1, parse_stream_line
from sih26145.detection.dga import DgaDetector
from sih26145.detection.pipeline import DetectionPipeline
from sih26145.detection.port_scan import PortScanDetector, ScanConfig
from sih26145.detection.syn_flood import SynFloodConfig, SynFloodDetector
from sih26145.ml.dga_model import DgaModel
from sih26145.replay import ReplayResult, run_replay

FIXTURES = Path("tests/fixtures/milestone3").resolve()


def detector_pipeline() -> DetectionPipeline:
    return DetectionPipeline(
        port_scan=PortScanDetector(config=ScanConfig()),
        syn_flood=SynFloodDetector(config=SynFloodConfig()),
        dga=DgaDetector(model=DgaModel.load_packaged()),
    )


def collect_native_alerts(fixture_name: str) -> tuple[ReplayResult, list[AlertV1]]:
    alerts: list[AlertV1] = []
    result = run_replay(FIXTURES / fixture_name, detector_pipeline(), alerts.append)
    return result, alerts


@pytest.mark.e2e
def test_native_dga_replay_emits_strict_model_evidence() -> None:
    result, alerts = collect_native_alerts("dga_dns.pcap")
    manifest = json.loads((FIXTURES / "dga_dns.manifest.json").read_text())

    assert result == ReplayResult(
        events_processed=1,
        alerts_emitted=1,
        last_event_ts=1_700_000_000.25,
    )
    [alert] = alerts
    assert alert.threat_class == "DGA"
    assert alert.protocol == "udp"
    assert str(alert.source.ip) == "192.0.2.10"
    assert isinstance(alert.evidence, DgaEvidence)
    assert alert.evidence.query_name == "x9q7z8v6k5j4m3n2.example"
    assert alert.evidence.query_type == 1
    assert alert.evidence.dga_probability == manifest["model"]["probability"]
    assert alert.evidence.model_version == "dga_logreg_v1"
    assert alert.evidence.feature_schema_version == "dns_features_v1"


@pytest.mark.e2e
def test_native_benign_dns_replay_emits_zero_alerts() -> None:
    result, alerts = collect_native_alerts("benign_dns.pcap")

    assert result == ReplayResult(
        events_processed=1,
        alerts_emitted=0,
        last_event_ts=1_700_000_000.25,
    )
    assert alerts == []


@pytest.mark.e2e
def test_native_dga_alert_is_emitted_before_eos(monkeypatch: pytest.MonkeyPatch) -> None:
    observations: list[str] = []
    real_parse = parse_stream_line

    def observe_parse(raw: bytes) -> Any:
        record = real_parse(raw)
        if isinstance(record, EndOfStreamV1):
            observations.append("end_of_stream")
        return record

    def observe_alert(_alert: AlertV1) -> None:
        observations.append("alert")

    monkeypatch.setattr(replay, "parse_stream_line", observe_parse)

    result = run_replay(FIXTURES / "dga_dns.pcap", detector_pipeline(), observe_alert)

    assert result.alerts_emitted == 1
    assert observations == ["alert", "end_of_stream"]


@pytest.mark.e2e
def test_cli_dns_replay_is_canonical_and_offline(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_socket(*_args: object, **_kwargs: object) -> socket.socket:
        pytest.fail("CLI DGA inference attempted network access")

    monkeypatch.setattr(socket, "socket", fail_socket)

    dga_exit = cli.main([str(FIXTURES / "dga_dns.pcap")])
    dga_output = capsys.readouterr()
    benign_exit = cli.main([str(FIXTURES / "benign_dns.pcap")])
    benign_output = capsys.readouterr()

    lines = dga_output.out.splitlines()
    assert dga_exit == 0
    assert dga_output.err == ""
    assert len(lines) == 1
    alert = AlertV1.model_validate_json(lines[0])
    assert alert.threat_class == "DGA"
    assert lines[0] == alert.model_dump_json()
    assert benign_exit == 0
    assert benign_output.out == ""
    assert benign_output.err == ""
