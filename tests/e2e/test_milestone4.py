from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from sih26145.api import AlertListResponse, create_app
from sih26145.contracts.alerts import DgaEvidence, PortScanEvidence, SynFloodEvidence

pytestmark = [pytest.mark.e2e, pytest.mark.anyio]

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPLAY_HEADERS = {"X-SIH26145-Action": "run-approved-fixture"}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def http_client() -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=create_app(fixture_root=REPOSITORY_ROOT)),
        base_url="http://127.0.0.1:8000",
    )


async def test_api_replays_all_three_alert_classes_into_one_bounded_store() -> None:
    async with http_client() as client:
        responses = [
            await client.post("/api/replays/port-scan-alert", headers=REPLAY_HEADERS),
            await client.post("/api/replays/syn-flood-alert", headers=REPLAY_HEADERS),
            await client.post("/api/replays/dga-alert", headers=REPLAY_HEADERS),
        ]
        stored_response = await client.get("/api/alerts")

    assert [response.status_code for response in responses] == [200, 200, 200]
    assert [response.json()["alerts_emitted"] for response in responses] == [1, 1, 1]
    stored_payload = AlertListResponse.model_validate_json(stored_response.text)
    assert stored_payload.stored_count == 3
    alerts = stored_payload.alerts
    assert [alert.threat_class for alert in alerts] == ["DGA", "SYN_FLOOD", "PORT_SCAN"]
    assert isinstance(alerts[0].evidence, DgaEvidence)
    assert alerts[0].evidence.model_version == "dga_logreg_v1"
    assert isinstance(alerts[1].evidence, SynFloodEvidence)
    assert alerts[1].evidence.deduplicated_syn_events == 100
    assert isinstance(alerts[2].evidence, PortScanEvidence)
    assert alerts[2].evidence.deduplicated_attempts == 20


@pytest.mark.parametrize(
    "fixture_id",
    [
        "port-scan-benign",
        "syn-flood-below",
        "syn-flood-benign",
        "dga-benign",
    ],
)
async def test_comparison_replays_add_no_dashboard_alert(fixture_id: str) -> None:
    async with http_client() as client:
        replay_response = await client.post(
            f"/api/replays/{fixture_id}",
            headers=REPLAY_HEADERS,
        )
        stored_response = await client.get("/api/alerts")

    assert replay_response.status_code == 200
    assert replay_response.json()["alerts_emitted"] == 0
    assert stored_response.json()["alerts"] == []
