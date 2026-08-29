"""Synchronous fan-out to the implemented streaming detectors."""

from __future__ import annotations

from dataclasses import dataclass

from sih26145.contracts.alerts import AlertV1
from sih26145.contracts.events import DnsEventV1, NetworkEvent
from sih26145.detection.dga import DgaDetector
from sih26145.detection.port_scan import PortScanDetector
from sih26145.detection.syn_flood import SynFloodDetector


@dataclass(frozen=True, slots=True)
class DetectionPipeline:
    """Feed each event to both detectors and preserve deterministic alert order."""

    port_scan: PortScanDetector
    syn_flood: SynFloodDetector
    dga: DgaDetector

    def process(self, event: NetworkEvent) -> tuple[AlertV1, ...]:
        """Return every alert produced for one event before accepting the next."""

        if isinstance(event, DnsEventV1):
            dga_alert = self.dga.process(event)
            return () if dga_alert is None else (dga_alert,)

        alerts: list[AlertV1] = []
        scan_alert = self.port_scan.process(event)
        if scan_alert is not None:
            alerts.append(scan_alert)
        flood_alert = self.syn_flood.process(event)
        if flood_alert is not None:
            alerts.append(flood_alert)
        return tuple(alerts)
