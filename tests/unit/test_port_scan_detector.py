from __future__ import annotations

import math
from datetime import UTC

import pytest
from pydantic import ValidationError

from sih26145.contracts.alerts import Severity
from sih26145.detection.port_scan import PortScanDetector, ScanConfig
from sih26145.detection.scan_window import StateLimitExceeded, StateLimits
from tests.factories import horizontal_events, syn, vertical_events


def test_vertical_scan_alerts_at_exact_threshold() -> None:
    detector = PortScanDetector(config=ScanConfig())

    alerts = [detector.process(event) for event in vertical_events(attempts=20, ports=15)]
    alert = next(item for item in alerts if item is not None)

    assert sum(item is not None for item in alerts) == 1
    assert alert.flow_id == "uid-19"
    assert str(alert.source.ip) == "192.0.2.10"
    assert alert.evidence.deduplicated_attempts == 20
    assert alert.evidence.unique_destination_ports == 15
    assert alert.evidence.unique_destination_hosts == 1
    assert alert.confidence == 0.75
    assert alert.severity is Severity.MEDIUM


def test_horizontal_scan_alerts_at_exact_threshold() -> None:
    detector = PortScanDetector(config=ScanConfig())

    alerts = [
        detector.process(event) for event in horizontal_events(attempts=20, hosts=15)
    ]
    alert = next(item for item in alerts if item is not None)

    assert sum(item is not None for item in alerts) == 1
    assert alert.evidence.unique_destination_hosts == 15
    assert alert.evidence.unique_destination_ports == 1


def test_below_both_fanout_thresholds_does_not_alert() -> None:
    detector = PortScanDetector(config=ScanConfig())

    alerts = [detector.process(event) for event in vertical_events(attempts=20, ports=14)]

    assert all(alert is None for alert in alerts)


def test_minimum_attempt_gate_is_required_even_with_fanout() -> None:
    detector = PortScanDetector(config=ScanConfig())

    alerts = [detector.process(event) for event in vertical_events(attempts=19, ports=19)]

    assert all(alert is None for alert in alerts)


def test_sources_are_evaluated_independently() -> None:
    detector = PortScanDetector(config=ScanConfig())
    first_source = vertical_events(attempts=10, ports=10, src_ip="192.0.2.10")
    second_source = vertical_events(attempts=10, ports=10, src_ip="192.0.2.11")
    interleaved = []
    for index, (first, second) in enumerate(zip(first_source, second_source, strict=True)):
        interleaved.append(first.model_copy(update={"uid": f"first-{index}"}))
        interleaved.append(
            second.model_copy(
                update={"uid": f"second-{index}", "ts": second.ts + 0.125}
            )
        )
    interleaved.sort(key=lambda event: event.ts)

    assert all(detector.process(event) is None for event in interleaved)


def test_custom_thresholds_populate_alert_evidence() -> None:
    config = ScanConfig(
        window_seconds=5.0,
        minimum_attempts=3,
        minimum_unique_destination_ports=2,
        minimum_unique_destination_hosts=4,
        cooldown_seconds=7.0,
    )
    detector = PortScanDetector(config=config)
    events = vertical_events(attempts=3, ports=2, start_ts=100.0, step=1.0)

    alert = detector.process(events[0])
    assert alert is None
    assert detector.process(events[1]) is None
    alert = detector.process(events[2])

    assert alert is not None
    assert alert.window.configured_seconds == 5.0
    assert alert.evidence.attempt_rate_per_second == 0.6
    assert alert.evidence.observed_span_seconds == 2.0
    assert alert.evidence.thresholds.minimum_attempts == 3
    assert alert.evidence.thresholds.minimum_unique_destination_ports == 2
    assert alert.evidence.thresholds.minimum_unique_destination_hosts == 4


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("window_seconds", 0.0),
        ("window_seconds", math.nan),
        ("minimum_attempts", 0),
        ("minimum_attempts", 1.5),
        ("minimum_unique_destination_ports", 0),
        ("minimum_unique_destination_hosts", 0),
        ("cooldown_seconds", -1.0),
        ("cooldown_seconds", math.inf),
    ],
)
def test_invalid_scan_configuration_is_rejected(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        ScanConfig.model_validate({field: value})


def test_cooldown_suppresses_then_realerts_at_exact_boundary() -> None:
    detector = PortScanDetector(
        config=ScanConfig(
            window_seconds=100.0,
            minimum_attempts=2,
            minimum_unique_destination_ports=2,
            minimum_unique_destination_hosts=2,
            cooldown_seconds=30.0,
        )
    )

    assert detector.process(syn(ts=100.0, uid="a", dst_port=22)) is None
    first = detector.process(syn(ts=101.0, uid="b", dst_port=23))
    suppressed = detector.process(syn(ts=110.0, uid="c", dst_port=24))
    second = detector.process(syn(ts=131.0, uid="d", dst_port=25))

    assert first is not None
    assert suppressed is None
    assert second is not None
    assert second.evidence.deduplicated_attempts == 4
    assert second.flow_id == "d"


def test_cooldown_state_expires_on_later_accepted_event() -> None:
    detector = PortScanDetector(
        config=ScanConfig(
            window_seconds=100.0,
            minimum_attempts=1,
            minimum_unique_destination_ports=1,
            minimum_unique_destination_hosts=1,
            cooldown_seconds=30.0,
        )
    )
    detector.process(syn(ts=100.0, uid="a", src_ip="192.0.2.10"))
    assert detector.cooldown_entries == 1

    detector.process(syn(ts=130.0, uid="b", src_ip="192.0.2.11"))

    assert detector.cooldown_entries == 1


def test_cooldown_limit_fails_without_partial_cooldown_insertion() -> None:
    state_limits = StateLimits(
        max_active_sources=10,
        max_attempts_per_source=10,
        max_total_attempts=20,
        max_dedup_uids=20,
        max_cooldown_sources=2,
        dedup_ttl_seconds=60.0,
    )
    detector = PortScanDetector(
        config=ScanConfig(
            window_seconds=10.0,
            minimum_attempts=1,
            minimum_unique_destination_ports=1,
            minimum_unique_destination_hosts=1,
            cooldown_seconds=30.0,
        ),
        limits=state_limits,
    )
    detector.process(syn(ts=100.0, uid="a", src_ip="192.0.2.10"))
    detector.process(syn(ts=101.0, uid="b", src_ip="192.0.2.11"))

    with pytest.raises(StateLimitExceeded) as captured:
        detector.process(syn(ts=102.0, uid="c", src_ip="192.0.2.12"))

    assert captured.value.limit_name == "max_cooldown_sources"
    assert detector.cooldown_entries == 2


@pytest.mark.parametrize(
    ("attempts", "ports", "confidence", "severity"),
    [
        (20, 15, 0.75, Severity.MEDIUM),
        (32, 24, 0.9, Severity.HIGH),
        (40, 30, 1.0, Severity.CRITICAL),
    ],
)
def test_confidence_and_severity_are_deterministic(
    attempts: int,
    ports: int,
    confidence: float,
    severity: Severity,
) -> None:
    detector = PortScanDetector(
        config=ScanConfig(window_seconds=20.0, cooldown_seconds=0.0)
    )
    events = vertical_events(attempts=attempts, ports=ports, start_ts=100.0, step=0.25)

    alerts = [detector.process(event) for event in events]
    alert = next(item for item in reversed(alerts) if item is not None)

    assert alert.confidence == confidence
    assert alert.severity is severity


def test_alert_contains_utc_trigger_time_and_ten_sorted_samples() -> None:
    detector = PortScanDetector(config=ScanConfig())
    events = vertical_events(attempts=20, ports=15, start_ts=1_700_000_000.0, step=0.25)

    alert = next(
        item for item in (detector.process(event) for event in events) if item is not None
    )

    assert alert.timestamp.tzinfo is UTC
    assert alert.timestamp.timestamp() == events[-1].ts
    assert len(alert.evidence.destination_samples) == 10
    assert [sample.port for sample in alert.evidence.destination_samples] == list(range(20, 30))
