"""Synchronous fan-out to the implemented streaming detectors."""

from __future__ import annotations

from dataclasses import dataclass

from sih26145.contracts.alerts import AlertV1
from sih26145.contracts.events import TcpSynAttemptV1
from sih26145.detection.port_scan import PortScanDetector
from sih26145.detection.syn_flood import SynFloodDetector


@dataclass(frozen=True, slots=True)
class DetectionPipeline:
    """Feed each event to both detectors and preserve deterministic alert order."""

    port_scan: PortScanDetector
    syn_flood: SynFloodDetector

    def process(self, event: TcpSynAttemptV1) -> tuple[AlertV1, ...]:
        """Return every alert produced for one event before accepting the next."""

        alerts: list[AlertV1] = []
        scan_alert = self.port_scan.process(event)
        if scan_alert is not None:
            alerts.append(scan_alert)
        flood_alert = self.syn_flood.process(event)
        if flood_alert is not None:
            alerts.append(flood_alert)
        return tuple(alerts)
