from __future__ import annotations

from copy import deepcopy
from datetime import timedelta

import pytest
from pydantic import ValidationError

from sih26145.alert_store import AlertStore
from sih26145.contracts.alerts import AlertV1
from tests.unit.test_alert_contracts import valid_alert_payload


def alert(flow_id: str, *, seconds: int = 0) -> AlertV1:
    payload = deepcopy(valid_alert_payload())
    payload["flow_id"] = flow_id
    payload["timestamp"] += timedelta(seconds=seconds)
    payload["window"]["start"] += timedelta(seconds=seconds)
    payload["window"]["end"] += timedelta(seconds=seconds)
    return AlertV1.model_validate(payload)


def test_store_evicts_oldest_alert_and_returns_newest_first() -> None:
    store = AlertStore(capacity=2)

    store.add(alert("first"))
    store.add(alert("second", seconds=1))
    store.add(alert("third", seconds=2))

    assert [item.flow_id for item in store.snapshot()] == ["third", "second"]
    assert store.stored_count == 2
    assert store.capacity == 2


def test_store_rejects_invalid_alert_without_mutation() -> None:
    store = AlertStore(capacity=2)

    with pytest.raises(ValidationError):
        store.add({"schema_version": "alert_v1", "confidence": 2.0})

    assert store.snapshot() == ()


def test_store_isolated_from_mutation_of_added_alert() -> None:
    store = AlertStore(capacity=2)
    original = alert("original")

    store.add(original)
    original.flow_id = "mutated-after-add"

    assert store.snapshot()[0].flow_id == "original"


def test_snapshot_mutation_does_not_change_stored_alert() -> None:
    store = AlertStore(capacity=2)
    store.add(alert("stored"))

    returned = store.snapshot()[0]
    returned.flow_id = "mutated-snapshot"

    assert store.snapshot()[0].flow_id == "stored"


def test_snapshot_limit_is_bounded_by_store_capacity() -> None:
    store = AlertStore(capacity=2)
    store.add(alert("first"))
    store.add(alert("second", seconds=1))

    assert [item.flow_id for item in store.snapshot(limit=1)] == ["second"]
    with pytest.raises(ValueError, match="snapshot_limit"):
        store.snapshot(limit=3)
