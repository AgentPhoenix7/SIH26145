from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

import sih26145.detection.syn_flood as syn_flood_module
from sih26145.contracts.alerts import Severity
from sih26145.contracts.events import TcpSynAttemptV1
from sih26145.detection.scan_window import StateLimitExceeded, TimestampRegressionError
from sih26145.detection.syn_flood import (
    SynFloodConfig,
    SynFloodDetector,
    SynFloodStateLimits,
    SynFloodWindow,
)
from tests.factories import syn


def flood_event(
    index: int,
    *,
    ts: float | None = None,
    source_count: int = 20,
    destination_ip: str = "198.51.100.20",
    destination_port: int = 443,
) -> TcpSynAttemptV1:
    return syn(
        ts=100.0 + index * 0.1 if ts is None else ts,
        uid=f"flood-{index}",
        src_ip=f"192.0.2.{1 + index % source_count}",
        src_port=40_000 + index,
        dst_ip=destination_ip,
        dst_port=destination_port,
    )


def small_config(**overrides: int | float) -> SynFloodConfig:
    values: dict[str, int | float] = {
        "window_seconds": 10.0,
        "minimum_syn_events": 4,
        "minimum_unique_sources": 3,
        "cooldown_seconds": 30.0,
    }
    values.update(overrides)
    return SynFloodConfig.model_validate(values)


def small_limits(**overrides: int | float) -> SynFloodStateLimits:
    values: dict[str, int | float] = {
        "max_active_targets": 10,
        "max_events_per_target": 10,
        "max_total_events": 20,
        "max_dedup_uids": 20,
        "max_cooldown_targets": 10,
        "dedup_ttl_seconds": 60.0,
    }
    values.update(overrides)
    return SynFloodStateLimits(**values)  # type: ignore[arg-type]


def test_syn_flood_alerts_at_exact_event_and_source_thresholds() -> None:
    detector = SynFloodDetector(config=small_config())

    alerts = [detector.process(flood_event(index, source_count=3)) for index in range(4)]
    alert = next(item for item in alerts if item is not None)

    assert sum(item is not None for item in alerts) == 1
    assert alert.threat_class == "SYN_FLOOD"
    assert alert.flow_id == "flood-3"
    assert str(alert.source.ip) == "192.0.2.1"
    assert alert.evidence.deduplicated_syn_events == 4
    assert alert.evidence.unique_sources == 3
    assert alert.evidence.source_ip_entropy_bits == 1.5
    assert alert.evidence.syn_rate_per_second == 0.4
    assert str(alert.evidence.target.ip) == "198.51.100.20"
    assert alert.evidence.target.port == 443
    assert [str(address) for address in alert.evidence.source_samples] == [
        "192.0.2.1",
        "192.0.2.2",
        "192.0.2.3",
    ]
    assert alert.confidence == 0.75
    assert alert.severity is Severity.MEDIUM


def test_both_syn_event_and_unique_source_thresholds_are_required() -> None:
    event_gate_detector = SynFloodDetector(config=small_config())

    below_events = [
        event_gate_detector.process(flood_event(index, source_count=3)) for index in range(3)
    ]
    source_gate_detector = SynFloodDetector(config=small_config())
    below_sources = [
        source_gate_detector.process(flood_event(index, source_count=2)) for index in range(4)
    ]

    assert all(alert is None for alert in below_events)
    assert all(alert is None for alert in below_sources)


def test_targets_are_evaluated_independently() -> None:
    detector = SynFloodDetector(config=small_config())
    events = [
        flood_event(0, destination_port=443),
        flood_event(1, destination_port=8443),
        flood_event(2, destination_port=443),
        flood_event(3, destination_port=8443),
        flood_event(4, destination_port=443),
        flood_event(5, destination_port=8443),
    ]

    assert all(detector.process(event) is None for event in events)


def test_window_deduplicates_uids_and_computes_source_entropy() -> None:
    window = SynFloodWindow(window_seconds=10.0)
    window.observe(flood_event(0, source_count=2))
    window.observe(flood_event(1, source_count=2))
    window.observe(flood_event(2, source_count=2))
    snapshot = window.observe(flood_event(3, source_count=2))
    duplicate = window.observe(flood_event(4, source_count=2).model_copy(update={"uid": "flood-3"}))

    assert snapshot is not None
    assert snapshot.events == 4
    assert snapshot.unique_sources == 2
    assert snapshot.source_ip_entropy_bits == 1.0
    assert duplicate is None
    assert window.total_events == 4


def test_entropy_work_remains_constant_per_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_log2 = math.log2
    log2_calls = 0

    def counting_log2(value: float) -> float:
        nonlocal log2_calls
        log2_calls += 1
        return real_log2(value)

    monkeypatch.setattr(math, "log2", counting_log2)
    window = SynFloodWindow(window_seconds=10.0)

    for index in range(100):
        window.observe(
            flood_event(
                index,
                ts=100.0 + index * 0.01,
                source_count=100,
            )
        )

    assert log2_calls <= 400


def test_source_samples_are_not_sorted_below_alert_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_sort(*_args: object, **_kwargs: object) -> None:
        pytest.fail("source samples must not be sorted before an alert is eligible")

    monkeypatch.setattr(syn_flood_module, "sorted", unexpected_sort, raising=False)
    detector = SynFloodDetector(config=small_config())

    assert detector.process(flood_event(0)) is None


def test_exact_window_boundary_is_included_then_expires() -> None:
    window = SynFloodWindow(window_seconds=10.0)
    window.observe(flood_event(0, ts=100.0))

    at_boundary = window.observe(flood_event(1, ts=110.0))
    after_boundary = window.observe(flood_event(2, ts=110.000001))

    assert at_boundary is not None and at_boundary.events == 2
    assert after_boundary is not None and after_boundary.events == 2


def test_timestamp_regression_fails_before_syn_flood_state_mutation() -> None:
    window = SynFloodWindow(window_seconds=10.0)
    window.observe(flood_event(0, ts=101.0))
    before = window.debug_counts()

    with pytest.raises(TimestampRegressionError):
        window.observe(flood_event(1, ts=100.0))

    assert window.debug_counts() == before


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("window_seconds", 0.0),
        ("window_seconds", math.nan),
        ("minimum_syn_events", 0),
        ("minimum_syn_events", 1.5),
        ("minimum_unique_sources", 0),
        ("cooldown_seconds", -1.0),
        ("cooldown_seconds", math.inf),
    ],
)
def test_invalid_syn_flood_configuration_is_rejected(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        SynFloodConfig.model_validate({field: value})


def test_detector_rejects_unreachable_thresholds_and_invalid_window() -> None:
    limits = small_limits(max_events_per_target=3, max_total_events=3, max_dedup_uids=3)

    with pytest.raises(ValueError, match="state capacity"):
        SynFloodDetector(config=small_config(minimum_syn_events=4), limits=limits)
    with pytest.raises(ValueError, match="unique-source threshold"):
        SynFloodDetector(
            config=small_config(minimum_syn_events=3, minimum_unique_sources=4),
            limits=limits,
        )
    with pytest.raises(ValueError, match="deduplication TTL"):
        SynFloodDetector(config=small_config(window_seconds=60.000001))


def test_cooldown_suppresses_then_realerts_at_exact_boundary() -> None:
    detector = SynFloodDetector(
        config=small_config(
            window_seconds=60.0,
            minimum_syn_events=2,
            minimum_unique_sources=2,
            cooldown_seconds=30.0,
        )
    )

    assert detector.process(flood_event(0, ts=100.0)) is None
    first = detector.process(flood_event(1, ts=101.0))
    suppressed = detector.process(flood_event(2, ts=110.0))
    second = detector.process(flood_event(3, ts=131.0))

    assert first is not None
    assert suppressed is None
    assert second is not None
    assert second.evidence.deduplicated_syn_events == 4


@pytest.mark.parametrize(
    ("limit_overrides", "events", "expected_name"),
    [
        (
            {"max_active_targets": 1},
            [flood_event(0), flood_event(1, destination_port=8443)],
            "max_active_targets",
        ),
        (
            {"max_events_per_target": 1},
            [flood_event(0), flood_event(1)],
            "max_events_per_target",
        ),
        (
            {"max_total_events": 1},
            [flood_event(0), flood_event(1)],
            "max_total_events",
        ),
        (
            {"max_dedup_uids": 1},
            [flood_event(0), flood_event(1)],
            "max_dedup_uids",
        ),
    ],
)
def test_each_syn_flood_state_limit_fails_without_partial_insertion(
    limit_overrides: dict[str, int],
    events: list[object],
    expected_name: str,
) -> None:
    window = SynFloodWindow(window_seconds=10.0, limits=small_limits(**limit_overrides))
    first, second = events
    window.observe(first)  # type: ignore[arg-type]
    before = window.debug_counts()

    with pytest.raises(StateLimitExceeded) as captured:
        window.observe(second)  # type: ignore[arg-type]

    assert captured.value.limit_name == expected_name
    assert window.debug_counts() == before


def test_cooldown_capacity_failure_rolls_back_the_triggering_event() -> None:
    detector = SynFloodDetector(
        config=small_config(
            window_seconds=10.0,
            minimum_syn_events=1,
            minimum_unique_sources=1,
            cooldown_seconds=30.0,
        ),
        limits=small_limits(
            max_active_targets=1,
            max_events_per_target=1,
            max_total_events=1,
            max_cooldown_targets=1,
        ),
    )
    detector.process(flood_event(0, ts=100.0, destination_port=443))
    blocked = flood_event(1, ts=111.0, destination_port=8443)

    for _ in range(2):
        with pytest.raises(StateLimitExceeded, match="max_cooldown_targets"):
            detector.process(blocked)


@pytest.mark.parametrize(
    ("events", "sources", "confidence", "severity"),
    [
        (4, 3, 0.75, Severity.MEDIUM),
        (7, 5, 0.9271, Severity.HIGH),
        (8, 6, 1.0, Severity.CRITICAL),
    ],
)
def test_confidence_and_severity_are_deterministic(
    events: int,
    sources: int,
    confidence: float,
    severity: Severity,
) -> None:
    detector = SynFloodDetector(config=small_config(cooldown_seconds=0.0))

    alerts = [detector.process(flood_event(index, source_count=sources)) for index in range(events)]
    alert = next(item for item in reversed(alerts) if item is not None)

    assert alert.confidence == confidence
    assert alert.severity is severity
