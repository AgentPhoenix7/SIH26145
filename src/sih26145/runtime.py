"""Construction of the verified in-process detector pipeline."""

from __future__ import annotations

from sih26145.detection.dga import DgaDetector
from sih26145.detection.pipeline import DetectionPipeline
from sih26145.detection.port_scan import PortScanDetector
from sih26145.detection.syn_flood import SynFloodDetector
from sih26145.ml.dga_model import DgaModel


def build_detection_pipeline(
    *,
    port_scan: PortScanDetector,
    syn_flood: SynFloodDetector,
) -> DetectionPipeline:
    """Build the existing three-detector pipeline with local model inference."""

    return DetectionPipeline(
        port_scan=port_scan,
        syn_flood=syn_flood,
        dga=DgaDetector(model=DgaModel.load_packaged()),
    )
