"""Consume the ``alerts`` Kafka topic and persist alerts to PostgreSQL.

Delivery semantics: at-least-once.

Kafka offsets are committed only after successful persistence.
Malformed messages are logged, skipped, and committed.

Transient storage failures are retried with backoff.
If retries are exhausted, the message is left uncommitted so
it can be re-read after restart.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import time
from typing import Optional

from confluent_kafka import Consumer, KafkaError

from api.services.alert_service import (
    AlertEvent,
    AlertStorageError,
    AlertStorageService,
)

logger = logging.getLogger(__name__)

ALERTS_TOPIC = os.getenv(
    "KAFKA_ALERTS_TOPIC",
    "alerts",
)

POLL_TIMEOUT_S = 1.0
MAX_SAVE_RETRIES = 3
RETRY_BACKOFF_S = 1.0


def build_consumer() -> Consumer:
    return Consumer(
        {
            "bootstrap.servers": os.getenv(
                "KAFKA_BOOTSTRAP_SERVERS",
                "localhost:9092",
            ),
            "group.id": os.getenv(
                "KAFKA_ALERTS_GROUP_ID",
                "alert-storage",
            ),
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        }
    )


def _save_with_retry(
    service: AlertStorageService,
    alert: AlertEvent,
) -> None:
    for attempt in range(
        1,
        MAX_SAVE_RETRIES + 1,
    ):
        try:
            service.save_alert(alert)
            return

        except AlertStorageError:
            if attempt == MAX_SAVE_RETRIES:
                raise

            logger.warning(
                "alert save failed "
                "(attempt %d/%d); retrying",
                attempt,
                MAX_SAVE_RETRIES,
            )

            time.sleep(
                RETRY_BACKOFF_S * attempt
            )


def run(
    service: Optional[
        AlertStorageService
    ] = None,
    consumer: Optional[
        Consumer
    ] = None,
) -> None:
    service = (
        service
        or AlertStorageService()
    )

    consumer = (
        consumer
        or build_consumer()
    )

    running = True

    def _stop(*_: object) -> None:
        nonlocal running
        running = False

    signal.signal(
        signal.SIGINT,
        _stop,
    )

    signal.signal(
        signal.SIGTERM,
        _stop,
    )

    consumer.subscribe(
        [ALERTS_TOPIC]
    )

    logger.info(
        "alert consumer started topic=%s",
        ALERTS_TOPIC,
    )

    try:
        while running:
            msg = consumer.poll(
                POLL_TIMEOUT_S
            )

            if msg is None:
                continue

            if msg.error():
                if (
                    msg.error().code()
                    != KafkaError._PARTITION_EOF
                ):
                    logger.error(
                        "kafka error: %s",
                        msg.error(),
                    )

                continue

            try:
                payload = json.loads(
                    msg.value()
                )

                alert = AlertEvent.from_dict(
                    payload
                )

            except (
                ValueError,
                TypeError,
                json.JSONDecodeError,
            ) as exc:
                logger.warning(
                    "skipping malformed alert "
                    "at %s[%s]@%s: %s",
                    msg.topic(),
                    msg.partition(),
                    msg.offset(),
                    exc,
                )

                consumer.commit(
                    message=msg,
                    asynchronous=False,
                )

                continue

            _save_with_retry(
                service,
                alert,
            )

            consumer.commit(
                message=msg,
                asynchronous=False,
            )

    finally:
        consumer.close()

        logger.info(
            "alert consumer stopped"
        )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s "
            "%(levelname)s "
            "%(name)s: %(message)s"
        ),
    )

    run()