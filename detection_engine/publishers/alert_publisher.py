"""
Alert publisher interface and in-memory test implementation.

Alerts are published as JSON to the `alerts` Kafka topic by the
production Kafka publisher. The small AlertPublisher protocol allows
tests to substitute an in-memory publisher without requiring a Kafka
broker.
"""

from __future__ import annotations

from typing import Any, Protocol


DEFAULT_ALERTS_TOPIC = "alerts"


class AlertPublisher(Protocol):
    """Interface implemented by alert publishers."""

    def publish(self, alert_dict: dict[str, Any]) -> None:
        """Publish a single alert."""
        ...


class InMemoryAlertPublisher:
    """Test/dev double that records published alerts in memory."""

    def __init__(self) -> None:
        self.published: list[dict[str, Any]] = []

    def publish(self, alert_dict: dict[str, Any]) -> None:
        """Record an alert without contacting Kafka."""
        self.published.append(alert_dict)