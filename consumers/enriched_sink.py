"""foreachBatch handler for the enriched stream: one enrichment, three sinks.

    enriched micro-batch (GeoIP + ASN + reputation already applied)
            |  persist()  <- enrichment runs exactly once per batch
            +--> Kafka  logs-enriched   (rules engine and other consumers)
            +--> PostgreSQL + Elasticsearch (api/services/spark_dual_sink.py)

Why one foreachBatch instead of one streaming query per sink: every query
re-reads Kafka and recomputes the stream, so a second query would enrich every
event again, calling AbuseIPDB twice and spending the 1000-checks/day free
quota twice. Here the batch is persisted, so the UDF (and every API call) runs
once and all sinks read the same cached rows.

Delivery semantics: at-least-once. Each sink is attempted even if the other
fails (so a Kafka outage does not stop events reaching storage, and vice
versa); if any sink failed the handler then raises, Spark stops the query, and
the whole batch is replayed from the checkpoint on restart. Replays are
harmless downstream: Kafka messages are keyed by event_id, and PostgreSQL /
Elasticsearch write idempotently by event_id.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from consumers.enriched_events import DEFAULT_ENRICHED_TOPIC, build_enriched_payload

logger = logging.getLogger(__name__)

DEFAULT_LATENCY_TARGET_SECONDS = 10.0

# acks=all + idempotence: no acknowledged message is lost and broker-side
# retries cannot create duplicates within a producer session.
DEFAULT_PRODUCER_OPTIONS: dict[str, str] = {
    "kafka.acks": "all",
    "kafka.enable.idempotence": "true",
}


class EnrichedBatchError(RuntimeError):
    """One or more sinks failed for a batch (the batch will be replayed)."""

    def __init__(self, batch_id: int, errors: Mapping[str, BaseException]) -> None:
        self.batch_id = batch_id
        self.errors = dict(errors)
        detail = "; ".join(
            f"{sink}: {type(exc).__name__}: {exc}" for sink, exc in self.errors.items()
        )
        super().__init__(f"batch {batch_id}: sink(s) failed -> {detail}")


@dataclass(frozen=True)
class KafkaSinkConfig:
    bootstrap_servers: str
    topic: str = DEFAULT_ENRICHED_TOPIC
    producer_options: Mapping[str, str] = field(
        default_factory=lambda: dict(DEFAULT_PRODUCER_OPTIONS)
    )


class KafkaEnrichedWriter:
    """Writes the key/value payload DataFrame to the ``logs-enriched`` topic.

    By default this is Spark's built-in Kafka batch sink (executors write in
    parallel). ``write_fn`` replaces it, which is how tests capture the
    payload without a broker.
    """

    def __init__(
        self,
        config: KafkaSinkConfig,
        write_fn: Optional[Callable[[DataFrame], None]] = None,
    ) -> None:
        self._config = config
        self._write_fn = write_fn

    @property
    def topic(self) -> str:
        return self._config.topic

    def write(self, payload_df: DataFrame) -> None:
        if self._write_fn is not None:
            self._write_fn(payload_df)
            return

        writer = (
            payload_df.write.format("kafka")
            .option("kafka.bootstrap.servers", self._config.bootstrap_servers)
            .option("topic", self._config.topic)
        )
        for name, value in self._config.producer_options.items():
            writer = writer.option(name, value)
        writer.save()


@dataclass(frozen=True)
class BatchSummary:
    events: int
    threats: int
    max_lag_seconds: Optional[float]
    avg_lag_seconds: Optional[float]


def summarize_batch(batch_df: DataFrame) -> BatchSummary:
    """One pass over the (persisted) batch: size, threats, end-to-end lag.

    Lag is ``enriched_at - event_timestamp``: log generated -> enrichment done.
    Running this first also materialises the cached batch, so the enrichment
    UDF executes here, once, before any sink reads it.
    """
    columns = set(batch_df.columns)
    aggregations = [F.count(F.lit(1)).alias("events")]
    if "is_known_threat" in columns:
        aggregations.append(
            F.sum(F.col("is_known_threat").cast("int")).alias("threats")
        )
    has_lag = {"enriched_at", "event_timestamp"} <= columns
    if has_lag:
        lag = F.col("enriched_at").cast("double") - F.col("event_timestamp").cast(
            "double"
        )
        aggregations += [F.max(lag).alias("max_lag"), F.avg(lag).alias("avg_lag")]

    row = batch_df.agg(*aggregations).first()
    return BatchSummary(
        events=int(row["events"] or 0),
        threats=int((row["threats"] if "is_known_threat" in columns else 0) or 0),
        max_lag_seconds=float(row["max_lag"]) if has_lag and row["max_lag"] is not None else None,
        avg_lag_seconds=float(row["avg_lag"]) if has_lag and row["avg_lag"] is not None else None,
    )


def make_enriched_batch_handler(
    storage_handler: Callable[[DataFrame, int], Any],
    kafka_writer: KafkaEnrichedWriter,
    *,
    latency_target_seconds: float = DEFAULT_LATENCY_TARGET_SECONDS,
) -> Callable[[DataFrame, int], None]:
    """Build the foreachBatch callback.

    Args:
        storage_handler: The PostgreSQL + Elasticsearch callback
            (``api.services.spark_dual_sink.write_valid_events_batch(writer)``).
        kafka_writer: Publishes to ``logs-enriched``.
        latency_target_seconds: A batch whose slowest event exceeds this
            end-to-end lag is logged as a warning (acceptance target: 10 s).
    """

    def _handle(batch_df: DataFrame, batch_id: int) -> None:
        batch_df.persist()
        try:
            summary = summarize_batch(batch_df)
            if summary.events == 0:
                logger.info("Enriched batch %s is empty", batch_id)
                return

            errors: dict[str, BaseException] = {}

            try:
                kafka_writer.write(build_enriched_payload(batch_df))
            except Exception as exc:  # noqa: BLE001 - still try the other sink
                errors["kafka"] = exc
                logger.exception(
                    "Enriched batch %s: writing to Kafka topic %s failed",
                    batch_id,
                    kafka_writer.topic,
                )

            try:
                storage_handler(batch_df, batch_id)
            except Exception as exc:  # noqa: BLE001
                errors["storage"] = exc
                logger.exception(
                    "Enriched batch %s: writing to PostgreSQL/Elasticsearch failed",
                    batch_id,
                )

            logger.info(
                "Enriched batch %s: events=%d threats=%d kafka=%s storage=%s "
                "lag(max/avg)=%s/%s s",
                batch_id,
                summary.events,
                summary.threats,
                "FAILED" if "kafka" in errors else "ok",
                "FAILED" if "storage" in errors else "ok",
                _fmt(summary.max_lag_seconds),
                _fmt(summary.avg_lag_seconds),
            )
            if (
                summary.max_lag_seconds is not None
                and summary.max_lag_seconds > latency_target_seconds
            ):
                logger.warning(
                    "Enriched batch %s: slowest event took %.1f s end to end "
                    "(target %.0f s)",
                    batch_id,
                    summary.max_lag_seconds,
                    latency_target_seconds,
                )

            if errors:
                raise EnrichedBatchError(batch_id, errors)
        finally:
            batch_df.unpersist()

    return _handle


def _fmt(value: Optional[float]) -> str:
    return "n/a" if value is None else f"{value:.2f}"