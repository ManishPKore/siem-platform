"""
LogProducer: reads newline-delimited JSON log events (from stdin, e.g. piped
from log_generator.py or any future log source) and publishes each one to
the `logs-raw` Kafka topic using confluent-kafka.

Usage:
    python producers/log_generator.py | python producers/log_producer.py

Env vars:
    KAFKA_BOOTSTRAP_SERVERS   required, e.g. "localhost:9092"
    KAFKA_TOPIC               optional, defaults to "logs-raw"
"""

from __future__ import annotations

import json
import logging
import os
import random
import signal
import sys
import time
from typing import Optional

from confluent_kafka import KafkaError, KafkaException, Producer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [log_producer] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("log_producer")

DEFAULT_TOPIC = "logs-raw"
MAX_CONNECT_RETRIES = 3
BASE_BACKOFF_SECONDS = 1.0
MAX_BUFFER_FULL_RETRIES = 5


class _ShutdownRequested(Exception):
    """Raised from the signal handler to unblock a blocking stdin read.

    A plain flag isn't enough: `for line in sys.stdin` blocks in C, and a
    handler that just sets an attribute won't be checked until the next
    line arrives (which may be never, e.g. if the upstream generator has
    stalled). Raising here lets Python's PEP 475 EINTR handling propagate
    the exception out of the blocked read instead of silently retrying it.
    """


class LogProducer:
    """Wraps a confluent_kafka.Producer to publish log events as JSON,
    keyed by source_ip, with delivery confirmation and retrying startup."""

    def __init__(
        self,
        bootstrap_servers: Optional[str] = None,
        topic: str = DEFAULT_TOPIC,
        max_connect_retries: int = MAX_CONNECT_RETRIES,
        base_backoff_seconds: float = BASE_BACKOFF_SECONDS,
    ):
        self.bootstrap_servers = bootstrap_servers or os.environ.get(
            "KAFKA_BOOTSTRAP_SERVERS"
        )
        if not self.bootstrap_servers:
            raise RuntimeError(
                "KAFKA_BOOTSTRAP_SERVERS environment variable is not set "
                "and no bootstrap_servers argument was provided."
            )

        self.topic = topic
        self.max_connect_retries = max_connect_retries
        self.base_backoff_seconds = base_backoff_seconds

        self._shutting_down = False
        self._sent_count = 0
        self._failed_count = 0

        self.producer: Producer = self._connect_with_retry()

    # -- connection -------------------------------------------------

    def _build_producer(self) -> Producer:
        return Producer(
            {
                "bootstrap.servers": self.bootstrap_servers,
                # fail fast on the initial metadata request so retry/backoff
                # logic in _connect_with_retry actually gets exercised
                "socket.timeout.ms": 10000,
                "message.timeout.ms": 30000,
                # --- explicit delivery reliability (don't rely on defaults) ---
                "acks": "all",
                "enable.idempotence": True,
                # in-flight message retries handled by librdkafka itself,
                # with backoff that grows toward retry.backoff.max.ms —
                # this is what actually satisfies "retries with exponential
                # backoff" for failures that happen *after* startup, not
                # just the connection-retry loop below
                "retries": 3,
                "retry.backoff.ms": 500,
                "retry.backoff.max.ms": 4000,
                # --- throughput (defaults are conservative for log volume) ---
                "linger.ms": 20,
                "compression.type": "snappy",
            }
        )

    def _connect_with_retry(self) -> Producer:
        attempt = 0
        last_error: Optional[Exception] = None

        while attempt < self.max_connect_retries:
            attempt += 1
            try:
                producer = self._build_producer()
                # list_topics forces a metadata round-trip so unreachable
                # brokers surface here rather than on the first publish
                producer.list_topics(timeout=10)
                logger.info(
                    "Connected to Kafka at %s (attempt %d)",
                    self.bootstrap_servers,
                    attempt,
                )
                return producer
            except KafkaException as exc:
                last_error = exc
                backoff = self.base_backoff_seconds * (2 ** (attempt - 1))
                backoff += random.uniform(0, backoff * 0.1)  # jitter
                logger.error(
                    "Failed to connect to Kafka at %s (attempt %d/%d): %s",
                    self.bootstrap_servers,
                    attempt,
                    self.max_connect_retries,
                    exc,
                )
                if attempt < self.max_connect_retries:
                    logger.info("Retrying in %.1fs...", backoff)
                    time.sleep(backoff)
            except Exception as exc:
                # Anything that isn't a KafkaException is almost certainly a
                # bug (bad config, etc.), not a transient network issue —
                # don't spend 3 retries masking it, fail immediately.
                logger.error(
                    "Unexpected (non-Kafka) error while connecting: %s", exc
                )
                raise

        raise ConnectionError(
            f"Could not connect to Kafka at {self.bootstrap_servers} "
            f"after {self.max_connect_retries} attempts"
        ) from last_error

    # -- publishing ---------------------------------------------------

    def _delivery_callback(self, err: Optional[KafkaError], msg) -> None:
        if err is not None:
            self._failed_count += 1
            logger.error(
                "Delivery failed for message key=%r on topic=%s: %s",
                msg.key(),
                msg.topic(),
                err,
            )
        else:
            self._sent_count += 1
            logger.debug(
                "Delivered to %s [partition %d] @ offset %d",
                msg.topic(),
                msg.partition(),
                msg.offset(),
            )

    def publish(self, event: dict) -> None:
        """Serialize a single log event to JSON and publish it, keyed by
        source_ip. Non-blocking; delivery is confirmed asynchronously via
        _delivery_callback. Poll(0) drains the local callback queue.

        If the local producer queue is full, waits and retries up to
        MAX_BUFFER_FULL_RETRIES times before dropping the event (logged as
        a failure) — this is bounded deliberately, a naive retry-forever
        or recurse-forever here will crash the process (RecursionError) or
        wedge it if the broker stays unreachable."""
        try:
            key = event.get("source_ip") if isinstance(event, dict) else None
            key_bytes = str(key).encode("utf-8") if key is not None else None
            value_bytes = json.dumps(event).encode("utf-8")
        except (TypeError, ValueError) as exc:
            self._failed_count += 1
            logger.error("Failed to serialize event, dropping it: %s", exc)
            return

        for buffer_attempt in range(MAX_BUFFER_FULL_RETRIES + 1):
            try:
                self.producer.produce(
                    topic=self.topic,
                    key=key_bytes,
                    value=value_bytes,
                    callback=self._delivery_callback,
                )
                self.producer.poll(0)  # serve delivery callbacks, non-blocking
                return
            except BufferError:
                if buffer_attempt >= MAX_BUFFER_FULL_RETRIES:
                    self._failed_count += 1
                    logger.error(
                        "Producer queue stayed full after %d retries, "
                        "dropping event",
                        MAX_BUFFER_FULL_RETRIES,
                    )
                    return
                logger.warning(
                    "Producer queue full, waiting for space (retry %d/%d)",
                    buffer_attempt + 1,
                    MAX_BUFFER_FULL_RETRIES,
                )
                self.producer.poll(1)
            except KafkaException as exc:
                self._failed_count += 1
                logger.error("Failed to publish event: %s", exc)
                return

    def run(self, input_stream=sys.stdin) -> None:
        """Consume newline-delimited JSON events from input_stream (stdout
        of log_generator.py by default) and publish each to Kafka."""
        signal.signal(signal.SIGINT, self._handle_shutdown_signal)
        signal.signal(signal.SIGTERM, self._handle_shutdown_signal)

        logger.info("LogProducer started, publishing to topic '%s'", self.topic)

        try:
            for line in input_stream:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.error("Skipping malformed log line: %s", exc)
                    continue
                if not isinstance(event, dict):
                    logger.error(
                        "Skipping event: expected a JSON object, got %s",
                        type(event).__name__,
                    )
                    continue
                self.publish(event)
        except _ShutdownRequested:
            pass
        finally:
            self.shutdown()

    # -- shutdown -------------------------------------------------------

    def _handle_shutdown_signal(self, signum, frame) -> None:
        logger.info("Received signal %d, shutting down gracefully...", signum)
        self._shutting_down = True
        raise _ShutdownRequested()

    def shutdown(self) -> None:
        logger.info(
            "Flushing producer (sent=%d, failed=%d)...",
            self._sent_count,
            self._failed_count,
        )
        remaining = self.producer.flush(timeout=10)
        if remaining > 0:
            logger.warning(
                "%d messages were still in queue after flush timeout", remaining
            )
        logger.info("Shutdown complete.")


def main() -> None:
    topic = os.environ.get("KAFKA_TOPIC", DEFAULT_TOPIC)
    try:
        producer = LogProducer(topic=topic)
    except (RuntimeError, ConnectionError) as exc:
        logger.error("Startup failed: %s", exc)
        sys.exit(1)

    producer.run()


if __name__ == "__main__":
    main()