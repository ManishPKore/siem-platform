"""
Kafka consumer for the SIEM platform (Issue: Implement base Kafka log consumer).

Reads events from the `logs-raw` topic, validates them against the log
schema produced by the log generator (issue #6), and hands well-formed
records to a downstream processing callback. Offsets are committed
manually, and only after a record has been fully handled, so a crash or
restart re-delivers whatever wasn't committed yet (at-least-once delivery).

This consumer is the pre-Spark starting point for the pipeline; it will
be superseded by the Spark consumer in issue #11 but is kept around for
testing simple end-to-end flows.

Usage:
    python -m consumers.log_consumer
    # or, with a custom handler:
    from consumers.log_consumer import LogConsumer, ConsumerConfig
    consumer = LogConsumer(ConsumerConfig.from_env(), on_record=my_handler)
    consumer.run()
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
from dataclasses import dataclass
from types import FrameType
from typing import Any, Callable, Optional

from confluent_kafka import Consumer, KafkaError, KafkaException, Message

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())  # library-safe: no output unless a caller configures logging

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

DEFAULT_TOPIC = "logs-raw"
DEFAULT_GROUP_ID = "siem-consumers"
DEFAULT_AUTO_OFFSET_RESET = "earliest"
DEFAULT_POLL_TIMEOUT_SECONDS = 1.0

# Fields every log event is expected to carry. Adjust this set if the
# schema from the log generator (issue #6) differs — this is the one
# assumption in this file that depends on that schema.
REQUIRED_LOG_FIELDS = {
    "event_id",
    "timestamp",
    "source_ip",
    "event_type",
    "severity",
    "raw_message",
    "source",
}


@dataclass(frozen=True)
class ConsumerConfig:
    bootstrap_servers: str
    topic: str = DEFAULT_TOPIC
    group_id: str = DEFAULT_GROUP_ID
    auto_offset_reset: str = DEFAULT_AUTO_OFFSET_RESET
    poll_timeout: float = DEFAULT_POLL_TIMEOUT_SECONDS

    @classmethod
    def from_env(cls) -> "ConsumerConfig":
        """Build config from environment variables.

        Raises:
            RuntimeError: if KAFKA_BOOTSTRAP_SERVERS is not set. The
                bootstrap address is never hardcoded to localhost.
        """
        bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS")
        if not bootstrap:
            raise RuntimeError(
                "KAFKA_BOOTSTRAP_SERVERS environment variable is not set"
            )
        return cls(
            bootstrap_servers=bootstrap,
            topic=os.environ.get("KAFKA_LOGS_RAW_TOPIC", DEFAULT_TOPIC),
            group_id=os.environ.get("KAFKA_CONSUMER_GROUP_ID", DEFAULT_GROUP_ID),
            auto_offset_reset=os.environ.get(
                "KAFKA_AUTO_OFFSET_RESET", DEFAULT_AUTO_OFFSET_RESET
            ),
            poll_timeout=float(
                os.environ.get("KAFKA_POLL_TIMEOUT_SECONDS", DEFAULT_POLL_TIMEOUT_SECONDS)
            ),
        )

    def to_confluent_config(self) -> dict:
        return {
            "bootstrap.servers": self.bootstrap_servers,
            "group.id": self.group_id,
            "auto.offset.reset": self.auto_offset_reset,
            # Manual commits only — a record is committed exactly once,
            # right after it has been processed (or explicitly skipped).
            "enable.auto.commit": False,
        }


class SchemaValidationError(Exception):
    """Raised when a decoded log record is missing required fields."""


def validate_log_schema(record: dict) -> None:
    """Validate a decoded log record against REQUIRED_LOG_FIELDS.

    Raises:
        SchemaValidationError: if any required field is missing.
    """
    missing = REQUIRED_LOG_FIELDS - record.keys()
    if missing:
        raise SchemaValidationError(f"missing required fields: {sorted(missing)}")


# --------------------------------------------------------------------------- #
# Consumer
# --------------------------------------------------------------------------- #

RecordHandler = Callable[[dict], None]


def _default_handler(record: dict) -> None:
    """Fallback downstream handler: just log the record was received."""
    logger.info("processed record source_ip=%s event_type=%s",
                record.get("source_ip"), record.get("event_type"))


class LogConsumer:
    """Consumes JSON log events from `logs-raw`, validates, and dispatches them.

    Args:
        config: Kafka connection settings.
        on_record: callback invoked with each valid, decoded log record.
            Defaults to a no-op logger; this is the seam where the future
            processing/enrichment layer plugs in.
        consumer: optional pre-built confluent_kafka.Consumer, for tests.
    """

    def __init__(
        self,
        config: ConsumerConfig,
        on_record: Optional[RecordHandler] = None,
        consumer: Optional[Consumer] = None,
    ) -> None:
        self.config = config
        self.on_record = on_record or _default_handler
        self._consumer = consumer or Consumer(config.to_confluent_config())
        self._running = False
        self._subscribed = False

    # -- lifecycle ---------------------------------------------------- #

    def subscribe(self) -> None:
        self._consumer.subscribe([self.config.topic])
        self._subscribed = True
        logger.info(
            "subscribed to topic=%s group_id=%s",
            self.config.topic,
            self.config.group_id,
        )

    def run(self) -> None:
        """Block, polling for messages until stop() is called or a signal fires."""
        if not self._subscribed:
            self.subscribe()

        self._install_signal_handlers()
        self._running = True
        logger.info("consumer loop starting")

        try:
            while self._running:
                self.poll_once()
        finally:
            self.close()

    def poll_once(self) -> Optional[dict]:
        """Poll for a single message, process it, and commit on success.

        Returns the decoded record on success, or None if there was
        nothing to read or the message was skipped (malformed JSON or
        failing schema validation). Skipped messages still have their
        offsets committed so the consumer doesn't get stuck retrying them
        forever.
        """
        msg = self._consumer.poll(self.config.poll_timeout)
        if msg is None:
            return None

        if msg.error():
            self._handle_kafka_error(msg)
            return None

        record = self._decode(msg)
        if record is None:
            # Malformed JSON: logged inside _decode. Skip past it.
            self._commit(msg)
            return None

        try:
            validate_log_schema(record)
        except SchemaValidationError as exc:
            logger.warning(
                "skipping record with invalid schema at offset=%s partition=%s: %s",
                msg.offset(),
                msg.partition(),
                exc,
            )
            self._commit(msg)
            return None

        self.on_record(record)
        self._commit(msg)
        return record

    def stop(self) -> None:
        self._running = False

    def close(self) -> None:
        logger.info("closing consumer")
        try:
            self._consumer.close()
        except Exception:  # pragma: no cover - defensive, close() rarely raises
            logger.exception("error while closing consumer")

    # -- internals ------------------------------------------------------ #

    def _decode(self, msg: Message) -> Optional[dict]:
        raw = msg.value()
        if raw is None:
            logger.warning(
                "skipping empty message at offset=%s partition=%s",
                msg.offset(),
                msg.partition(),
            )
            return None

        text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
        text = text.strip()
        if not text:
            logger.warning(
                "skipping blank message at offset=%s partition=%s",
                msg.offset(),
                msg.partition(),
            )
            return None

        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            logger.warning(
                "skipping malformed JSON at offset=%s partition=%s: %s",
                msg.offset(),
                msg.partition(),
                exc,
            )
            return None

    def _commit(self, msg: Message) -> None:
        try:
            self._consumer.commit(message=msg, asynchronous=False)
        except KafkaException:
            logger.exception(
                "failed to commit offset=%s partition=%s",
                msg.offset(),
                msg.partition(),
            )
            raise

    def _handle_kafka_error(self, msg: Message) -> None:
        err = msg.error()
        if err.code() == KafkaError._PARTITION_EOF:
            logger.debug(
                "reached end of partition=%s offset=%s", msg.partition(), msg.offset()
            )
            return
        logger.error("Kafka error: %s", err)
        raise KafkaException(err)

    def _install_signal_handlers(self) -> None:
        def _handle(signum: int, frame: Optional[FrameType]) -> None:
            logger.info("received signal %s, shutting down", signum)
            self.stop()

        signal.signal(signal.SIGINT, _handle)
        signal.signal(signal.SIGTERM, _handle)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )
    config = ConsumerConfig.from_env()
    consumer = LogConsumer(config)
    consumer.run()


if __name__ == "__main__":
    main()