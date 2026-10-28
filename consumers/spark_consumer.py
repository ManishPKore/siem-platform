"""
consumers/spark_consumer.py

PySpark Structured Streaming replacement for the plain Kafka consumer
(consumers/log_consumer.py, Issue #5). This is the processing engine
detection rules (future issues) will be built on top of: it reads raw log
events from the `logs-raw` Kafka topic in near real time, normalizes them
into the canonical schema from Issue #6 (consumers/schemas.py -- see
consumers/normalizer.py, Issue #11), validates the normalized result, and
fans out into two sinks:

    * valid records   -> GeoIP + ASN enrichment (enrichment/spark_enrichment.py:
      adds geo_country / geo_city / geo_latitude / geo_longitude /
      geo_is_private plus asn_number / asn_org, the columns detection
      rules such as impossible_travel read) -> PostgreSQL + Elasticsearch
      dual sink.
    * invalid records (unparsable JSON, missing/blank required fields
      after normalization, or an unrecognized raw `event_type` that
      normalize_event() couldn't map to a known source) -> an
      append-only, UTC-date-partitioned JSON "dead letter" store under
      data/dead_letter/YYYY-MM-DD/, so nothing is ever silently dropped.

Unlike consumers/log_consumer.py (confluent-kafka, one record at a
time, Python-level offset commits), this reads Kafka via Spark's
built-in `kafka` streaming source and lets Spark manage Kafka offsets
itself through checkpointing -- see "Checkpointing & recovery" below.

Run locally
-----------
1. Install dependencies (pyspark is now in requirements.txt):

       pip install -r requirements.txt

2. Start Kafka and create its topics:

       docker compose up -d zookeeper kafka kafka-init

3. Run the job:

       spark-submit \
         --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.1 \
         consumers/spark_consumer.py

   The script also declares `spark.jars.packages` on its own
   SparkSession (see build_spark_session()), so a plain
   `python consumers/spark_consumer.py` works too -- Spark resolves
   and caches the connector jar via Ivy on first run. `--packages` on
   the spark-submit command line is the more reliable option on a
   network-restricted machine, since it lets you pre-stage the jar.

4. In another terminal, feed it events:

       python producers/log_generator.py --rate 10 | python producers/log_producer.py

   Normalized events should appear on the console within a couple of seconds.

Running against the docker-compose Spark cluster
---------------------------------------------------
    docker compose up -d spark spark-worker
    docker compose exec spark spark-submit \
        --master spark://spark:7077 \
        --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.1 \
        /opt/siem-platform/consumers/spark_consumer.py

The repo root is bind-mounted at /opt/siem-platform in both Spark
containers, so data/checkpoints and data/dead_letter land back on the
host, same as running locally. Use KAFKA_BOOTSTRAP_SERVERS=kafka:29092
(the in-network listener) when running this way.

Configuration (environment variables)
--------------------------------------
    KAFKA_BOOTSTRAP_SERVERS         required, e.g. "localhost:9092"
    KAFKA_LOGS_RAW_TOPIC            default "logs-raw"
    KAFKA_ENRICHED_TOPIC            default "logs-enriched" (enriched events
                                     are published here, see below)
    SPARK_MASTER                    default "local[2]" (2+ threads
                                     required for streaming -- with 1
                                     thread there's no capacity left to
                                     run the query after receiving data)
    SPARK_APP_NAME                  default "siem-spark-consumer"
    SPARK_STARTING_OFFSETS          default "earliest" (only consulted
                                     the first time a query runs -- see
                                     below)
    SPARK_TRIGGER_INTERVAL          default "2 seconds" (kept well
                                     under the <5s lag acceptance target
                                     to leave headroom for processing)
    SPARK_CHECKPOINT_DIR            default "data/checkpoints/spark_consumer"
    SPARK_DEAD_LETTER_DIR           default "data/dead_letter" (batches
                                     are actually written under
                                     <this>/YYYY-MM-DD/ -- see
                                     consumers.normalizer.dead_letter_output_path)
    SPARK_FAIL_ON_DATA_LOSS         default "false" (see inline comment
                                     on the Kafka source options below)
    SPARK_MAX_OFFSETS_PER_TRIGGER   optional; unset = no cap
    GEOIP_DB_PATH                   default "data/GeoLite2-City.mmdb" (see
                                     README "GeoIP Database Setup"). If the
                                     file is missing the job still runs:
                                     private IPs are flagged, public IPs get
                                     null geo fields, and a warning is logged
                                     at startup.
    ASN_DB_PATH                     default "data/GeoLite2-ASN.mmdb" (see
                                     README "ASN Database Setup"). If the
                                     file is missing the job still runs:
                                     asn_number / asn_org are null and a
                                     warning is logged at startup.
    ABUSEIPDB_API_KEY               optional. Enables AbuseIPDB reputation
                                     lookups (README "Threat Intelligence
                                     Setup"). Unset = local blocklist only
                                     (data/known_bad_ips.txt, override with
                                     KNOWN_BAD_IPS_PATH) and a startup
                                     warning. The key is read by each Spark
                                     Python worker from its own environment.
    ABUSEIPDB_THREAT_THRESHOLD      default 50 (score >= this is a threat)
    ABUSEIPDB_DAILY_LIMIT           default 1000 (free tier) per worker

Checkpointing & recovery
-------------------------
The two sink queries below (console, dead-letter) each get their own
subdirectory under SPARK_CHECKPOINT_DIR, because Spark requires a
dedicated checkpoint location per streaming query:

    data/checkpoints/spark_consumer/console/
    data/checkpoints/spark_consumer/dead_letter/

Both are created automatically on first run. Each checkpoint records
the Kafka offsets that query has fully processed. SPARK_STARTING_OFFSETS
is consulted ONLY when a query has no checkpoint yet; on every later
run Spark resumes from the checkpointed offsets and
SPARK_STARTING_OFFSETS is ignored -- this is what satisfies "recovers
from restart and continues from the last checkpoint offset". To force
a full replay, delete the checkpoint directories and re-run.

Malformed / invalid records
-----------------------------
`from_json` never raises on bad input -- a value that isn't valid JSON,
or is valid JSON but missing/mistyped fields, just produces nulls for
the affected column(s) (Spark's PERMISSIVE mode). This job parses the
Kafka payload against consumers.normalizer.RAW_EVENT_SCHEMA (the shape
producers/log_generator.py actually emits -- NOT the canonical LogEvent
shape), normalizes it into canonical fields via
consumers.normalizer.normalize_event() (Issue #11), and then treats a
row as invalid if any canonical REQUIRED_LOG_FIELDS column is
null/blank after normalization, or its `timestamp` field can't be
parsed into an actual timestamp. That required-fields check
(consumers.normalizer.required_field_mask(), reused via
is_normalization_valid()) is defined against
consumers.log_consumer.REQUIRED_LOG_FIELDS, so the Spark and
non-Spark consumers can never validate against two different
definitions of "required". An unrecognized raw `event_type` -- one
normalize_event() can't map to a known source -- comes out of
normalization with `source` (and therefore `event_type`, `severity`)
NULL, which fails that same required-fields check; there is no
separate "unrecognized source" code path.

Invalid records are written to SPARK_DEAD_LETTER_DIR/YYYY-MM-DD/ as
newline-delimited JSON (the normalized row, including the original
raw_value and Kafka metadata), and every micro-batch containing at
least one logs a warning with the count -- see write_dead_letter_batch()
below.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
from dataclasses import dataclass
from typing import Optional

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F

from consumers.enriched_events import DEFAULT_ENRICHED_TOPIC
from consumers.enriched_sink import (
    KafkaEnrichedWriter,
    KafkaSinkConfig,
    make_enriched_batch_handler,
)
from consumers.log_consumer import DEFAULT_TOPIC
from enrichment.pipeline_enricher import startup_warnings
from enrichment.spark_enrichment import add_enrichment_columns
from api.services.spark_dual_sink import (
    build_dual_sink_writer,
    write_valid_events_batch,
)

from consumers.normalizer import (
    RAW_EVENT_SCHEMA,
    dead_letter_output_path,
    is_normalization_valid,
    normalize_event,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [spark_consumer] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("spark_consumer")

SPARK_VERSION = "3.5.1"
SCALA_BINARY_VERSION = "2.12"
KAFKA_CONNECTOR_PACKAGE = (
    f"org.apache.spark:spark-sql-kafka-0-10_{SCALA_BINARY_VERSION}:{SPARK_VERSION}"
)

DEFAULT_MASTER = "local[2]"
DEFAULT_APP_NAME = "siem-spark-consumer"
DEFAULT_STARTING_OFFSETS = "earliest"
DEFAULT_TRIGGER_INTERVAL = "2 seconds"
DEFAULT_CHECKPOINT_DIR = "data/checkpoints/spark_consumer"
DEFAULT_DEAD_LETTER_DIR = "data/dead_letter"


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SparkConsumerConfig:
    bootstrap_servers: str
    topic: str = DEFAULT_TOPIC
    enriched_topic: str = DEFAULT_ENRICHED_TOPIC
    master: str = DEFAULT_MASTER
    app_name: str = DEFAULT_APP_NAME
    starting_offsets: str = DEFAULT_STARTING_OFFSETS
    trigger_interval: str = DEFAULT_TRIGGER_INTERVAL
    checkpoint_dir: str = DEFAULT_CHECKPOINT_DIR
    dead_letter_dir: str = DEFAULT_DEAD_LETTER_DIR
    fail_on_data_loss: bool = False
    max_offsets_per_trigger: Optional[int] = None

    @classmethod
    def from_env(cls) -> "SparkConsumerConfig":
        bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS")
        if not bootstrap:
            raise RuntimeError(
                "KAFKA_BOOTSTRAP_SERVERS environment variable is not set"
            )

        max_offsets_raw = os.environ.get("SPARK_MAX_OFFSETS_PER_TRIGGER")

        return cls(
            bootstrap_servers=bootstrap,
            topic=os.environ.get("KAFKA_LOGS_RAW_TOPIC", DEFAULT_TOPIC),
            enriched_topic=os.environ.get(
                "KAFKA_ENRICHED_TOPIC", DEFAULT_ENRICHED_TOPIC
            ),
            master=os.environ.get("SPARK_MASTER", DEFAULT_MASTER),
            app_name=os.environ.get("SPARK_APP_NAME", DEFAULT_APP_NAME),
            starting_offsets=os.environ.get(
                "SPARK_STARTING_OFFSETS", DEFAULT_STARTING_OFFSETS
            ),
            trigger_interval=os.environ.get(
                "SPARK_TRIGGER_INTERVAL", DEFAULT_TRIGGER_INTERVAL
            ),
            checkpoint_dir=os.environ.get(
                "SPARK_CHECKPOINT_DIR", DEFAULT_CHECKPOINT_DIR
            ),
            dead_letter_dir=os.environ.get(
                "SPARK_DEAD_LETTER_DIR", DEFAULT_DEAD_LETTER_DIR
            ),
            fail_on_data_loss=os.environ.get("SPARK_FAIL_ON_DATA_LOSS", "false")
            .strip()
            .lower()
            in ("1", "true", "yes"),
            max_offsets_per_trigger=(
                int(max_offsets_raw) if max_offsets_raw else None
            ),
        )

    @property
    def console_checkpoint_dir(self) -> str:
        return os.path.join(self.checkpoint_dir, "console")

    @property
    def dead_letter_checkpoint_dir(self) -> str:
        return os.path.join(self.checkpoint_dir, "dead_letter")


# --------------------------------------------------------------------------- #
# Spark session / source
# --------------------------------------------------------------------------- #


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _executor_python_path() -> str:
    """Repo root (plus any existing PYTHONPATH) for Spark's Python workers.

    Python UDFs -- enrichment/spark_enrichment.py's GeoIP pandas_udf -- run in
    worker processes that must be able to `import enrichment`. Locally they
    inherit the driver's environment, but on the docker-compose Spark cluster
    they are spawned by the worker daemon, which has no PYTHONPATH. The repo
    is bind-mounted at the same path in every container, so pointing workers
    at REPO_ROOT makes both setups behave the same.
    """
    existing = os.environ.get("PYTHONPATH")
    return os.pathsep.join(p for p in (REPO_ROOT, existing) if p)


def build_spark_session(config: SparkConsumerConfig) -> SparkSession:
    return (
        SparkSession.builder.appName(config.app_name)
        .master(config.master)
        .config("spark.jars.packages", KAFKA_CONNECTOR_PACKAGE)
        .config("spark.sql.session.timeZone", "UTC")
        .config("spark.executorEnv.PYTHONPATH", _executor_python_path())
        .getOrCreate()
    )


def read_kafka_stream(spark: SparkSession, config: SparkConsumerConfig) -> DataFrame:
    reader = (
        spark.readStream.format("kafka")
        .option("kafka.bootstrap.servers", config.bootstrap_servers)
        .option("subscribe", config.topic)
        .option("startingOffsets", config.starting_offsets)
        .option("failOnDataLoss", str(config.fail_on_data_loss).lower())
    )
    if config.max_offsets_per_trigger:
        reader = reader.option(
            "maxOffsetsPerTrigger", config.max_offsets_per_trigger
        )
    return reader.load()


# --------------------------------------------------------------------------- #
# Parsing / normalization / validation
# --------------------------------------------------------------------------- #


def parse_normalize_and_validate(raw_df: DataFrame) -> DataFrame:
    """
    Parse the Kafka `value` bytes as raw producer-shaped JSON
    (consumers.normalizer.RAW_EVENT_SCHEMA), normalize into the canonical
    LogEvent shape (consumers.normalizer.normalize_event(), Issue #11),
    and mark each row valid/invalid via
    consumers.normalizer.is_normalization_valid() for downstream routing.

    Never drops or raises on bad input -- see module docstring.
    """
    parsed = (
        raw_df.select(
            F.col("value").cast("string").alias("raw_value"),
            F.col("key").cast("string").alias("kafka_key"),
            F.col("topic").alias("kafka_topic"),
            F.col("partition").alias("kafka_partition"),
            F.col("offset").alias("kafka_offset"),
            F.col("timestamp").alias("kafka_produced_at"),
        )
        .withColumn("_parsed", F.from_json(F.col("raw_value"), RAW_EVENT_SCHEMA))
        .select(
            "raw_value",
            "kafka_key",
            "kafka_topic",
            "kafka_partition",
            "kafka_offset",
            "kafka_produced_at",
            "_parsed.*",
        )
    )

    normalized = normalize_event(parsed)

    normalized = normalized.withColumn(
        "processing_lag_seconds",
        F.unix_timestamp(F.current_timestamp())
        - F.unix_timestamp(F.col("event_timestamp")),
    )

    return is_normalization_valid(normalized)


# --------------------------------------------------------------------------- #
# Sinks
# --------------------------------------------------------------------------- #


def build_enrichment_stage(
    valid_df: DataFrame,
    *,
    geoip_db_path: Optional[str] = None,
    asn_db_path: Optional[str] = None,
    blocklist_path: Optional[str] = None,
) -> DataFrame:
    """Run unified enrichment after normalization and before detection/storage.

    One UDF pass adds GeoIP, ASN and IP-reputation columns, plus ``enriched_at``
    (when this stage ran), so every event carries its own end-to-end latency.
    Only valid rows get here; dead-letter rows are written as they are.

    The stage never drops a row. Optional paths override the corresponding
    environment/default paths; the AbuseIPDB key comes from worker environment.
    """
    return add_enrichment_columns(
        valid_df,
        ip_col="source_ip",
        geoip_db_path=geoip_db_path,
        asn_db_path=asn_db_path,
        blocklist_path=blocklist_path,
    ).withColumn("enriched_at", F.current_timestamp())


def write_dead_letter_batch(dead_letter_dir: str):
    """Returns a foreachBatch function that logs a warning (with count)
    for any micro-batch containing invalid records, then appends them to
    a UTC-date-partitioned subdirectory of dead_letter_dir
    (dead_letter_dir/YYYY-MM-DD/, per consumers.normalizer.
    dead_letter_output_path -- Issue #11's dead-letter path convention)
    as newline-delimited JSON. Using foreachBatch here (rather than a
    plain `.format("json")` sink) is what makes the "produce a warning
    log" acceptance criterion possible -- a bare file sink writes
    silently with no hook to log from."""

    def _write(batch_df: DataFrame, batch_id: int) -> None:
        batch_df.persist()
        try:
            count = batch_df.count()
            if count == 0:
                return
            output_path = dead_letter_output_path(dead_letter_dir)
            logger.warning(
                "batch %d: %d invalid record(s) (unparsable JSON, missing "
                "required field after normalization, or unrecognized "
                "event source) routed to dead-letter store at %s",
                batch_id,
                count,
                output_path,
            )
            (
                batch_df.withColumn("dead_letter_batch_id", F.lit(batch_id))
                .withColumn("dead_letter_written_at", F.current_timestamp())
                .write.mode("append")
                .json(output_path)
            )
        finally:
            batch_df.unpersist()

    return _write


CONSOLE_DISPLAY_COLUMNS = [
    "event_id",
    "timestamp",
    "event_timestamp",
    "normalized_at",
    "source_ip",
    "source",
    "event_type",
    "severity",
    "raw_message",
    "processing_lag_seconds",
    "kafka_partition",
    "kafka_offset",
]


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def main() -> None:
    config = SparkConsumerConfig.from_env()
    os.makedirs(config.checkpoint_dir, exist_ok=True)
    os.makedirs(config.dead_letter_dir, exist_ok=True)

    spark = build_spark_session(config)
    spark.sparkContext.setLogLevel("WARN")

    logger.info(
        "starting spark_consumer: topic=%s bootstrap=%s master=%s trigger=%s "
        "checkpoint_dir=%s dead_letter_dir=%s",
        config.topic,
        config.bootstrap_servers,
        config.master,
        config.trigger_interval,
        config.checkpoint_dir,
        config.dead_letter_dir,
    )

    dual_writer = None
    active_queries = []

    try:
        raw_df = read_kafka_stream(spark, config)
        parsed_df = parse_normalize_and_validate(raw_df)

        valid_df = parsed_df.filter(F.col("_is_valid")).drop("_is_valid")
        invalid_df = parsed_df.filter(~F.col("_is_valid")).drop("_is_valid")

        # Degraded setups (missing GeoIP/ASN database, no AbuseIPDB key) are
        # allowed -- the affected fields are just null -- but say so loudly once.
        for message in startup_warnings():
            logger.warning(message)

        # Enrichment stage: normalizer -> enrichment -> rules / sinks.
        enriched_df = build_enrichment_stage(valid_df)

        dual_writer = build_dual_sink_writer()

        # One foreachBatch fans the enriched batch out to Kafka (logs-enriched)
        # and to PostgreSQL + Elasticsearch, enriching each event exactly once.
        enriched_handler = make_enriched_batch_handler(
            storage_handler=write_valid_events_batch(dual_writer),
            kafka_writer=KafkaEnrichedWriter(
                KafkaSinkConfig(
                    bootstrap_servers=config.bootstrap_servers,
                    topic=config.enriched_topic,
                )
            ),
        )

        valid_query = (
            enriched_df.writeStream
            .foreachBatch(enriched_handler)
            .outputMode("append")
            .option("checkpointLocation", config.console_checkpoint_dir)
            .trigger(processingTime=config.trigger_interval)
            .start()
        )
        active_queries.append(valid_query)

        dead_letter_query = (
            invalid_df.writeStream.foreachBatch(
                write_dead_letter_batch(config.dead_letter_dir)
            )
            .outputMode("append")
            .option("checkpointLocation", config.dead_letter_checkpoint_dir)
            .trigger(processingTime=config.trigger_interval)
            .start()
        )
        active_queries.append(dead_letter_query)

        def _handle_shutdown(signum, frame) -> None:
            logger.info("received signal %s, stopping streaming queries...", signum)
            for query in active_queries:
                if query.isActive:
                    query.stop()

        signal.signal(signal.SIGINT, _handle_shutdown)
        signal.signal(signal.SIGTERM, _handle_shutdown)

        spark.streams.awaitAnyTermination()
    finally:
        # Clean up any query that successfully started, even if starting the
        # other query or registering a signal handler fails.
        for query in active_queries:
            if query.isActive:
                continue
            try:
                exc = query.exception()
            except Exception:
                logger.exception("could not retrieve error for query %s", query.id)
                continue
            if exc is not None:
                logger.error(
                    "streaming query %s terminated with error: %s",
                    query.id,
                    exc,
                )

        for query in active_queries:
            if query.isActive:
                try:
                    query.stop()
                except Exception:
                    logger.exception("failed to stop streaming query %s", query.id)

        if dual_writer is not None:
            try:
                dual_writer.close()
            except Exception:
                logger.exception("failed to close dual sink writer")

        try:
            spark.stop()
        finally:
            logger.info("spark_consumer stopped")


if __name__ == "__main__":
    main()