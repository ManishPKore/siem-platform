"""
Kafka-backed alert publisher.

Uses confluent-kafka, consistent with the Kafka producer and consumer
already used by the SIEM platform.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from confluent_kafka import Producer

from detection_engine.publishers.alert_publisher import (
    AlertPublisher,
    DEFAULT_ALERTS_TOPIC,
)

logger = logging.getLogger(__name__)


class KafkaAlertPublisher:
    """Production publisher backed by a Kafka broker."""

    def __init__(
        self,
        bootstrap_servers: str,
        topic: str = DEFAULT_ALERTS_TOPIC,
    ) -> None:
        self._topic = topic

        self._producer = Producer(
            {
                "bootstrap.servers": bootstrap_servers,
                "acks": "all",
                "enable.idempotence": True,
                "retries": 3,
            }
        )

    def publish(self, alert_dict: dict[str, Any]) -> None:
        """Serialize and publish an alert to Kafka."""

        payload = json.dumps(alert_dict, default=str)

        key = alert_dict.get("source_ip")

        try:
            self._producer.produce(
                topic=self._topic,
                key=str(key) if key is not None else None,
                value=payload,
                callback=self._delivery_callback,
            )

            # Serve delivery callbacks without blocking for the full
            # Kafka delivery interval.
            self._producer.poll(0)

        except Exception:
            logger.exception(
                "Failed to publish alert to Kafka topic '%s'",
                self._topic,
            )
            raise

    def flush(self) -> None:
        """Wait for outstanding Kafka messages to be delivered."""

        self._producer.flush()

    def close(self) -> None:
        """Flush pending messages and release the Kafka producer."""

        self._producer.flush()
        self._producer = None  # type: ignore[assignment]

    @staticmethod
    def _delivery_callback(err: Any, message: Any) -> None:
        """Log Kafka delivery failures."""

        if err is not None:
            logger.error(
                "Failed to deliver alert to Kafka topic '%s': %s",
                message.topic(),
                err,
            )