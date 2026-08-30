"""Loopback-only API for approved replay fixtures and bounded alerts."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from threading import Lock
from typing import Annotated

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import Response
from pydantic import Field

from sih26145.alert_store import AlertStore
from sih26145.contracts.alerts import AlertV1
from sih26145.contracts.events import StrictModel
from sih26145.detection.port_scan import PortScanDetector, ScanConfig
from sih26145.detection.scan_window import StateLimitExceeded
from sih26145.detection.syn_flood import SynFloodConfig, SynFloodDetector
from sih26145.ml.dga_model import DgaModelError
from sih26145.replay import ReplayError, run_replay
from sih26145.runtime import build_detection_pipeline

ALERT_STORE_CAPACITY = 100
DEFAULT_ALERT_LIMIT = 50
REPLAY_ACTION_VALUE = "run-approved-fixture"
DASHBOARD_DIR = Path(__file__).with_name("dashboard")
DASHBOARD_HTML = (DASHBOARD_DIR / "index.html").read_bytes()
DASHBOARD_CSS = (DASHBOARD_DIR / "dashboard.css").read_bytes()
DASHBOARD_JS = (DASHBOARD_DIR / "dashboard.js").read_bytes()


class FixtureId(StrEnum):
    """Only deterministic committed captures exposed by the local API."""

    PORT_SCAN_ALERT = "port-scan-alert"
    PORT_SCAN_BENIGN = "port-scan-benign"
    SYN_FLOOD_ALERT = "syn-flood-alert"
    SYN_FLOOD_BELOW = "syn-flood-below"
    SYN_FLOOD_BENIGN = "syn-flood-benign"
    DGA_ALERT = "dga-alert"
    DGA_BENIGN = "dga-benign"


APPROVED_FIXTURES: dict[FixtureId, Path] = {
    FixtureId.PORT_SCAN_ALERT: Path("tests/fixtures/milestone1/vertical_at_threshold.pcap"),
    FixtureId.PORT_SCAN_BENIGN: Path("tests/fixtures/milestone1/benign.pcap"),
    FixtureId.SYN_FLOOD_ALERT: Path("tests/fixtures/milestone2/syn_flood_at_threshold.pcap"),
    FixtureId.SYN_FLOOD_BELOW: Path("tests/fixtures/milestone2/syn_flood_below.pcap"),
    FixtureId.SYN_FLOOD_BENIGN: Path("tests/fixtures/milestone2/benign_distributed.pcap"),
    FixtureId.DGA_ALERT: Path("tests/fixtures/milestone3/dga_dns.pcap"),
    FixtureId.DGA_BENIGN: Path("tests/fixtures/milestone3/benign_dns.pcap"),
}


class AlertListResponse(StrictModel):
    """Bounded API envelope containing unchanged ``alert_v1`` records."""

    alerts: tuple[AlertV1, ...]
    returned_count: Annotated[int, Field(ge=0)]
    stored_count: Annotated[int, Field(ge=0)]
    capacity: Annotated[int, Field(gt=0)]


class ReplayResponse(StrictModel):
    """Safe accounting for one approved deterministic replay."""

    fixture_id: FixtureId
    events_processed: Annotated[int, Field(ge=0)]
    alerts_emitted: Annotated[int, Field(ge=0)]
    stored_count: Annotated[int, Field(ge=0)]


class ReplayBusy(RuntimeError):
    """Another approved replay is already active."""


class FixtureUnavailable(RuntimeError):
    """An approved fixture is absent or outside the configured fixture root."""


class ReplayCoordinator:
    """Serialize approved fixture replays into one bounded alert store."""

    def __init__(self, *, store: AlertStore, fixture_root: Path) -> None:
        self._store = store
        self._fixture_root = fixture_root.resolve()
        self._replay_lock = Lock()

    def _fixture_path(self, fixture_id: FixtureId) -> Path:
        try:
            path = (self._fixture_root / APPROVED_FIXTURES[fixture_id]).resolve(strict=True)
            path.relative_to(self._fixture_root)
        except (KeyError, OSError, ValueError):
            raise FixtureUnavailable from None
        if not path.is_file():
            raise FixtureUnavailable
        return path

    def run(self, fixture_id: FixtureId) -> ReplayResponse:
        """Run one fixed capture through the existing callback path."""

        if not self._replay_lock.acquire(blocking=False):
            raise ReplayBusy
        try:
            result = run_replay(
                self._fixture_path(fixture_id),
                build_detection_pipeline(
                    port_scan=PortScanDetector(config=ScanConfig()),
                    syn_flood=SynFloodDetector(config=SynFloodConfig()),
                ),
                self._store.add,
            )
            return ReplayResponse(
                fixture_id=fixture_id,
                events_processed=result.events_processed,
                alerts_emitted=result.alerts_emitted,
                stored_count=self._store.stored_count,
            )
        finally:
            self._replay_lock.release()


def create_app(
    *,
    store: AlertStore | None = None,
    fixture_root: Path | None = None,
) -> FastAPI:
    """Create the local API with isolated state for tests or one server process."""

    alert_store = store or AlertStore(capacity=ALERT_STORE_CAPACITY)
    coordinator = ReplayCoordinator(
        store=alert_store,
        fixture_root=fixture_root or Path.cwd(),
    )
    app = FastAPI(title="SIH26145 Local Detection Dashboard", docs_url=None, redoc_url=None)

    @app.get("/", response_class=Response, include_in_schema=False)
    async def dashboard() -> Response:
        return Response(DASHBOARD_HTML, media_type="text/html")

    @app.get("/assets/dashboard.css", response_class=Response, include_in_schema=False)
    async def dashboard_stylesheet() -> Response:
        return Response(DASHBOARD_CSS, media_type="text/css")

    @app.get("/assets/dashboard.js", response_class=Response, include_in_schema=False)
    async def dashboard_script() -> Response:
        return Response(DASHBOARD_JS, media_type="text/javascript")

    @app.get("/api/alerts", response_model=AlertListResponse)
    async def list_alerts(
        limit: Annotated[int, Query(ge=1, le=ALERT_STORE_CAPACITY)] = DEFAULT_ALERT_LIMIT,
    ) -> AlertListResponse:
        alerts = alert_store.snapshot(limit=limit)
        return AlertListResponse(
            alerts=alerts,
            returned_count=len(alerts),
            stored_count=alert_store.stored_count,
            capacity=alert_store.capacity,
        )

    @app.post("/api/replays/{fixture_id}", response_model=ReplayResponse)
    async def replay_fixture(
        fixture_id: FixtureId,
        replay_action: Annotated[
            str | None,
            Header(alias="X-SIH26145-Action"),
        ] = None,
    ) -> ReplayResponse:
        if replay_action != REPLAY_ACTION_VALUE:
            raise HTTPException(status_code=403, detail="replay_action_required")
        try:
            return coordinator.run(fixture_id)
        except ReplayBusy:
            raise HTTPException(status_code=409, detail="replay_busy") from None
        except FixtureUnavailable:
            raise HTTPException(status_code=500, detail="fixture_unavailable") from None
        except (DgaModelError, ReplayError, StateLimitExceeded):
            raise HTTPException(status_code=500, detail="replay_failed") from None

    return app


def main() -> None:
    """Serve the local dashboard API on loopback only."""

    uvicorn.run(create_app(), host="127.0.0.1", port=8000)
