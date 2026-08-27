from __future__ import annotations

import math

import pytest

from sih26145.detection.scan_window import (
    PortScanWindow,
    StateLimitExceeded,
    StateLimits,
    TimestampRegressionError,
)
from tests.factories import syn


def limits(**overrides: int | float) -> StateLimits:
    values: dict[str, int | float] = {
        "max_active_sources": 10,
        "max_attempts_per_source": 10,
        "max_total_attempts": 20,
        "max_dedup_uids": 20,
        "max_cooldown_sources": 10,
        "dedup_ttl_seconds": 60.0,
    }
    values.update(overrides)
    return StateLimits(**values)  # type: ignore[arg-type]


def test_exact_window_boundary_is_included_then_expires() -> None:
    window = PortScanWindow(window_seconds=10.0)
    window.observe(syn(ts=100.0, uid="first", dst_port=22))

    at_boundary = window.observe(syn(ts=110.0, uid="second", dst_port=23))
    after_boundary = window.observe(syn(ts=110.000001, uid="third", dst_port=24))

    assert at_boundary is not None and at_boundary.attempts == 2
    assert after_boundary is not None and after_boundary.attempts == 2
    assert after_boundary.unique_ports == 2


def test_uid_retransmission_does_not_change_state() -> None:
    window = PortScanWindow(window_seconds=10.0)
    first = window.observe(syn(ts=100.0, uid="same", dst_port=443))
    duplicate = window.observe(syn(ts=101.0, uid="same", dst_port=444))

    assert first is not None
    assert duplicate is None
    assert window.total_attempts == 1
    assert window.dedup_uids == 1


def test_timestamp_regression_fails_before_mutation() -> None:
    window = PortScanWindow(window_seconds=10.0)
    window.observe(syn(ts=101.0, uid="accepted"))
    before = window.debug_counts()

    with pytest.raises(TimestampRegressionError):
        window.observe(syn(ts=100.0, uid="late"))

    assert window.debug_counts() == before


def test_equal_timestamps_preserve_insertion_order() -> None:
    window = PortScanWindow(window_seconds=10.0)

    first = window.observe(syn(ts=100.0, uid="first", dst_port=443))
    second = window.observe(syn(ts=100.0, uid="second", dst_port=22))

    assert first is not None and second is not None
    assert second.destination_samples == (
        (syn().dst_ip, 22),
        (syn().dst_ip, 443),
    )


def test_sources_have_isolated_counters() -> None:
    window = PortScanWindow(window_seconds=10.0)
    window.observe(syn(ts=100.0, uid="a", src_ip="192.0.2.10", dst_port=22))

    other = window.observe(syn(ts=101.0, uid="b", src_ip="192.0.2.11", dst_port=443))

    assert other is not None
    assert other.attempts == 1
    assert other.unique_ports == 1
    assert window.active_sources == 2


def test_expiry_decrements_all_unique_counters() -> None:
    window = PortScanWindow(window_seconds=10.0)
    window.observe(syn(ts=100.0, uid="a", dst_ip="198.51.100.20", dst_port=22))
    window.observe(syn(ts=101.0, uid="b", dst_ip="198.51.100.21", dst_port=23))

    snapshot = window.observe(syn(ts=110.5, uid="c", dst_ip="198.51.100.21", dst_port=23))

    assert snapshot is not None
    assert snapshot.attempts == 2
    assert snapshot.unique_hosts == 1
    assert snapshot.unique_ports == 1
    assert snapshot.unique_endpoints == 1


def test_uid_is_retained_at_ttl_boundary_then_reusable_after_it() -> None:
    window = PortScanWindow(window_seconds=10.0)
    window.observe(syn(ts=100.0, uid="same"))

    assert window.observe(syn(ts=160.0, uid="same")) is None
    reused = window.observe(syn(ts=160.000001, uid="same"))

    assert reused is not None
    assert reused.attempts == 1


def test_ipv6_sources_and_destinations_are_supported() -> None:
    window = PortScanWindow(window_seconds=10.0)

    snapshot = window.observe(syn(ts=100.0, src_ip="2001:db8::10", dst_ip="2001:db8::20"))

    assert snapshot is not None
    assert str(snapshot.source_ip) == "2001:db8::10"
    assert str(snapshot.destination_samples[0][0]) == "2001:db8::20"


def test_destination_samples_sort_ipv4_before_ipv6_then_port() -> None:
    window = PortScanWindow(window_seconds=10.0)
    window.observe(syn(ts=100.0, uid="v6", dst_ip="2001:db8::20", dst_port=22))
    window.observe(syn(ts=101.0, uid="high", dst_ip="198.51.100.21", dst_port=22))
    snapshot = window.observe(syn(ts=102.0, uid="low", dst_ip="198.51.100.20", dst_port=443))

    assert snapshot is not None
    assert [(str(ip), port) for ip, port in snapshot.destination_samples] == [
        ("198.51.100.20", 443),
        ("198.51.100.21", 22),
        ("2001:db8::20", 22),
    ]


@pytest.mark.parametrize(
    ("limit_overrides", "events", "expected_name"),
    [
        (
            {"max_active_sources": 1},
            [
                syn(ts=100.0, uid="a", src_ip="192.0.2.10"),
                syn(ts=101.0, uid="b", src_ip="192.0.2.11"),
            ],
            "max_active_sources",
        ),
        (
            {"max_attempts_per_source": 1},
            [syn(ts=100.0, uid="a"), syn(ts=101.0, uid="b")],
            "max_attempts_per_source",
        ),
        (
            {"max_total_attempts": 1},
            [syn(ts=100.0, uid="a"), syn(ts=101.0, uid="b")],
            "max_total_attempts",
        ),
        (
            {"max_dedup_uids": 1},
            [syn(ts=100.0, uid="a"), syn(ts=101.0, uid="b")],
            "max_dedup_uids",
        ),
    ],
)
def test_each_state_limit_fails_without_partial_insertion(
    limit_overrides: dict[str, int],
    events: list[object],
    expected_name: str,
) -> None:
    window = PortScanWindow(window_seconds=10.0, limits=limits(**limit_overrides))
    first, second = events
    window.observe(first)  # type: ignore[arg-type]
    before = window.debug_counts()

    with pytest.raises(StateLimitExceeded) as captured:
        window.observe(second)  # type: ignore[arg-type]

    assert captured.value.limit_name == expected_name
    assert window.debug_counts() == before


def test_expiry_runs_before_resource_limit_check() -> None:
    window = PortScanWindow(
        window_seconds=1.0,
        limits=limits(max_attempts_per_source=1, max_total_attempts=1),
    )
    window.observe(syn(ts=100.0, uid="first"))

    snapshot = window.observe(syn(ts=102.0, uid="second"))

    assert snapshot is not None
    assert snapshot.attempts == 1
    assert window.total_attempts == 1


@pytest.mark.parametrize("window_seconds", [0.0, -1.0, math.nan, math.inf])
def test_window_duration_must_be_positive_and_finite(window_seconds: float) -> None:
    with pytest.raises(ValueError):
        PortScanWindow(window_seconds=window_seconds)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_active_sources", 0),
        ("max_attempts_per_source", 0),
        ("max_total_attempts", 0),
        ("max_dedup_uids", 0),
        ("max_cooldown_sources", 0),
        ("dedup_ttl_seconds", 0.0),
        ("dedup_ttl_seconds", math.inf),
    ],
)
def test_state_limits_must_be_positive_and_finite(field: str, value: int | float) -> None:
    with pytest.raises(ValueError):
        limits(**{field: value})
