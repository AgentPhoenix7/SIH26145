"""Bounded in-memory storage for validated local dashboard alerts."""

from __future__ import annotations

from collections import deque
from threading import Lock

from sih26145.contracts.alerts import AlertV1


class AlertStore:
    """Keep a deterministic bounded FIFO of strict ``alert_v1`` records."""

    def __init__(self, *, capacity: int) -> None:
        if capacity <= 0:
            raise ValueError("alert_store_capacity")
        self._capacity = capacity
        self._alerts: deque[AlertV1] = deque(maxlen=capacity)
        self._lock = Lock()

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def stored_count(self) -> int:
        with self._lock:
            return len(self._alerts)

    def add(self, alert: object) -> None:
        """Validate and append one alert, evicting the oldest at capacity."""

        validated = AlertV1.model_validate(alert)
        with self._lock:
            self._alerts.append(validated.model_copy(deep=True))

    def snapshot(self, *, limit: int | None = None) -> tuple[AlertV1, ...]:
        """Return a stable newest-first snapshot bounded by capacity."""

        effective_limit = self._capacity if limit is None else limit
        if not 1 <= effective_limit <= self._capacity:
            raise ValueError("snapshot_limit")
        with self._lock:
            selected = reversed(tuple(self._alerts)[-effective_limit:])
            return tuple(alert.model_copy(deep=True) for alert in selected)
