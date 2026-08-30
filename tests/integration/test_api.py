from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from threading import Event, Thread

import anyio
import pytest
import uvicorn
from httpx import ASGITransport, AsyncClient

import sih26145.api as api
from sih26145.alert_store import AlertStore
from sih26145.contracts.alerts import AlertV1
from sih26145.detection.pipeline import DetectionPipeline
from sih26145.replay import ReplayError, ReplayResult
from tests.unit.test_alert_contracts import valid_alert_payload

REPLAY_HEADERS = {"X-SIH26145-Action": "run-approved-fixture"}


def alert(flow_id: str, *, seconds: int = 0) -> AlertV1:
    payload = deepcopy(valid_alert_payload())
    payload["flow_id"] = flow_id
    payload["timestamp"] += timedelta(seconds=seconds)
    payload["window"]["start"] += timedelta(seconds=seconds)
    payload["window"]["end"] += timedelta(seconds=seconds)
    return AlertV1.model_validate(payload)


def fixture_file(root: Path, fixture_id: api.FixtureId) -> Path:
    relative = api.APPROVED_FIXTURES[fixture_id]
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"controlled fixture")
    return path.resolve()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def http_client(app: object) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://testserver",
    )


@pytest.mark.anyio
async def test_alert_route_returns_bounded_newest_first_alert_v1_records() -> None:
    store = AlertStore(capacity=100)
    store.add(alert("first"))
    store.add(alert("second", seconds=1))
    async with http_client(api.create_app(store=store)) as client:
        response = await client.get("/api/alerts", params={"limit": 1})

    assert response.status_code == 200
    payload = response.json()
    assert payload["capacity"] == 100
    assert payload["stored_count"] == 2
    assert payload["returned_count"] == 1
    assert [item["flow_id"] for item in payload["alerts"]] == ["second"]
    assert payload["alerts"][0]["schema_version"] == "alert_v1"


@pytest.mark.parametrize("limit", [0, 101])
@pytest.mark.anyio
async def test_alert_route_rejects_out_of_bounds_limit(limit: int) -> None:
    async with http_client(api.create_app()) as client:
        response = await client.get("/api/alerts", params={"limit": limit})

    assert response.status_code == 422


@pytest.mark.anyio
async def test_approved_replay_uses_existing_pipeline_callback_and_stores_alert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_path = fixture_file(tmp_path, api.FixtureId.PORT_SCAN_ALERT)
    expected_alert = alert("stored")

    def fake_replay(
        pcap_path: Path,
        detector: DetectionPipeline,
        emit_alert: Callable[[AlertV1], None],
    ) -> ReplayResult:
        assert pcap_path == expected_path
        assert isinstance(detector, DetectionPipeline)
        emit_alert(expected_alert)
        return ReplayResult(events_processed=20, alerts_emitted=1, last_event_ts=100.0)

    monkeypatch.setattr(api, "run_replay", fake_replay)
    async with http_client(api.create_app(fixture_root=tmp_path)) as client:
        response = await client.post(
            "/api/replays/port-scan-alert",
            headers=REPLAY_HEADERS,
        )
        stored = (await client.get("/api/alerts")).json()["alerts"]

    assert response.status_code == 200
    assert response.json() == {
        "fixture_id": "port-scan-alert",
        "events_processed": 20,
        "alerts_emitted": 1,
        "stored_count": 1,
    }
    assert [item["flow_id"] for item in stored] == ["stored"]


@pytest.mark.anyio
async def test_invalid_replay_selection_never_starts_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_replay(*_args: object, **_kwargs: object) -> ReplayResult:
        pytest.fail("invalid replay selection reached run_replay")

    monkeypatch.setattr(api, "run_replay", unexpected_replay)
    async with http_client(api.create_app()) as client:
        response = await client.post(
            "/api/replays/../../untrusted",
            headers=REPLAY_HEADERS,
        )

    assert response.status_code in {404, 422}


@pytest.mark.anyio
async def test_replay_failure_returns_fixed_error_without_internal_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_file(tmp_path, api.FixtureId.DGA_ALERT)

    def failed_replay(*_args: object, **_kwargs: object) -> ReplayResult:
        raise ReplayError("child_exit_nonzero")

    monkeypatch.setattr(api, "run_replay", failed_replay)
    async with http_client(api.create_app(fixture_root=tmp_path)) as client:
        response = await client.post(
            "/api/replays/dga-alert",
            headers=REPLAY_HEADERS,
        )

    assert response.status_code == 500
    assert response.json() == {"detail": "replay_failed"}
    assert "child_exit_nonzero" not in response.text


@pytest.mark.anyio
async def test_replay_requires_browser_preflight_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_replay(*_args: object, **_kwargs: object) -> ReplayResult:
        pytest.fail("headerless replay reached run_replay")

    monkeypatch.setattr(api, "run_replay", unexpected_replay)
    async with http_client(api.create_app()) as client:
        response = await client.post("/api/replays/dga-alert")

    assert response.status_code == 403
    assert response.json() == {"detail": "replay_action_required"}


def test_coordinator_rejects_concurrent_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_file(tmp_path, api.FixtureId.DGA_ALERT)
    entered = Event()
    release = Event()

    def blocked_replay(*_args: object, **_kwargs: object) -> ReplayResult:
        entered.set()
        assert release.wait(timeout=2.0)
        return ReplayResult(events_processed=1, alerts_emitted=0, last_event_ts=100.0)

    monkeypatch.setattr(api, "run_replay", blocked_replay)
    coordinator = api.ReplayCoordinator(
        store=AlertStore(capacity=100),
        fixture_root=tmp_path,
    )
    worker = Thread(target=coordinator.run, args=(api.FixtureId.DGA_ALERT,))
    worker.start()
    assert entered.wait(timeout=1.0)

    try:
        with pytest.raises(api.ReplayBusy):
            coordinator.run(api.FixtureId.DGA_ALERT)
    finally:
        release.set()
        worker.join(timeout=2.0)

    assert not worker.is_alive()


def test_server_entrypoint_binds_to_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def fake_uvicorn_run(app: object, **kwargs: object) -> None:
        observed["app"] = app
        observed.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_uvicorn_run)

    api.main()

    assert observed["host"] == "127.0.0.1"
    assert observed["port"] == 8000


@pytest.mark.anyio
async def test_dashboard_and_assets_are_served_from_the_same_origin() -> None:
    async with http_client(api.create_app()) as client:
        dashboard = await client.get("/")
        stylesheet = await client.get("/assets/dashboard.css")
        script = await client.get("/assets/dashboard.js")

    assert dashboard.status_code == 200
    assert dashboard.headers["content-type"].startswith("text/html")
    assert 'href="/assets/dashboard.css"' in dashboard.text
    assert 'src="/assets/dashboard.js"' in dashboard.text
    assert "PORT_SCAN" in dashboard.text
    assert "SYN_FLOOD" in dashboard.text
    assert "DGA" in dashboard.text
    assert "UDP reflection/amplification" in dashboard.text
    assert "NOT IMPLEMENTED" in dashboard.text
    assert "C2 beaconing" in dashboard.text
    assert "TLS/QUIC malware metadata" in dashboard.text
    assert "Data exfiltration" in dashboard.text
    assert "DEFERRED" in dashboard.text
    assert 'aria-live="polite"' in dashboard.text
    assert stylesheet.status_code == 200
    assert stylesheet.headers["content-type"].startswith("text/css")
    assert script.status_code == 200
    assert "javascript" in script.headers["content-type"]
    assert "const MAX_ALERTS = 50" in script.text
    assert ".textContent" in script.text
    assert ".innerHTML" not in script.text
    assert "setTimeout" in script.text
    assert '"X-SIH26145-Action": "run-approved-fixture"' in script.text


@pytest.mark.anyio
async def test_fixed_dashboard_assets_do_not_require_a_threadpool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def reject_threadpool(*_args: object, **_kwargs: object) -> object:
        pytest.fail("fixed dashboard assets reached the AnyIO threadpool")

    monkeypatch.setattr(anyio.to_thread, "run_sync", reject_threadpool)
    async with http_client(api.create_app()) as client:
        response = await client.get("/")

    assert response.status_code == 200
