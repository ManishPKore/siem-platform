"""
consumers/spark_consumer.py

PySpark Structured Streaming replacement for the plain Kafka consumer
(consumers/log_consumer.py, Issue #5). This is the processing engine
detection rules (future issues) will be built on top of: it reads
normalized log events from the `logs-raw` Kafka topic in near real
time, validates each record against the canonical schema introduced in
Issue #6 (consumers/schemas.py), and fans out into two sinks:

    * valid records   -> console sink (stdout), for now -- this will be
      swapped for the enrichment/detection sinks in a later issue.
    * invalid records (unparsable JSON, or missing/blank required
      fields) -> an append-only JSON "dead letter" store under
      data/dead_letter/, so nothing is ever silently dropped.

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

   Parsed events should appear on the console within a couple of
   seconds.

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
    SPARK_DEAD_LETTER_DIR           default "data/dead_letter"
    SPARK_FAIL_ON_DATA_LOSS         default "false" (see inline comment
                                     on the Kafka source options below)
    SPARK_MAX_OFFSETS_PER_TRIGGER   optional; unset = no cap

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
the affected column(s) (Spark's PERMISSIVE mode). This job treats a
record as invalid if any REQUIRED_LOG_FIELDS column is null/blank
after parsing, or its `timestamp` field can't be parsed into an actual
timestamp. REQUIRED_LOG_FIELDS is imported from consumers.log_consumer
rather than redefined here, so the Spark and non-Spark consumers can
never validate against two different definitions of "required".
Invalid records are written to SPARK_DEAD_LETTER_DIR as
newline-delimited JSON (original raw_value plus Kafka metadata), and
every micro-batch containing at least one logs a warning with the
count -- see write_dead_letter_batch() below.
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
from pyspark.sql.types import (
    BooleanType,
    IntegerType,
    StringType,
    StructField,
    StructType,
)

# Reuse the base consumer's definition of "required fields" so the
# Spark and confluent-kafka consumers can never silently drift apart on
# what counts as a valid record. confluent-kafka is already a hard
# project dependency (used by log_consumer.py / log_producer.py), so
# this import adds no new dependency.
from consumers.log_consumer import DEFAULT_TOPIC, REQUIRED_LOG_FIELDS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [spark_consumer] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("spark_consumer")

# The connector version must match the Spark version, which must match
# the Spark image used in docker-compose.yml.
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
# Canonical event schema (Issue #6 -- consumers/schemas.py::LogEvent)
# --------------------------------------------------------------------------- #
#
# `timestamp` is read as a plain string, not TimestampType: from_json's
# built-in timestamp parsing is picky about the exact pattern and
# silently nulls the field on any mismatch, which would make a
# perfectly valid record look "invalid". It's parsed explicitly below
# instead, with an explicit set of accepted patterns, so the failure
# mode is visible and testable rather than implicit in the schema.
#
# Every field is nullable=True at the Spark schema level -- Spark
# doesn't reject/fail rows for a "non-nullable" field missing from the
# JSON, it just leaves it null, so nullable=False here would be
# misleading. REQUIRED_LOG_FIELDS (imported above) is what actually
# enforces which fields must be present -- see _build_required_field_mask.
LOG_EVENT_SCHEMA = StructType(
    [
        # --- Universal fields (every source) ---
        StructField("event_id", StringType(), True),
        StructField("timestamp", StringType(), True),
        StructField("source_ip", StringType(), True),
        StructField("event_type", StringType(), True),
        StructField("severity", StringType(), True),
        StructField("raw_message", StringType(), True),
        StructField("source", StringType(), True),
        # --- SSH-specific ---
        StructField("username", StringType(), True),
        StructField("auth_method", StringType(), True),
        StructField("success", BooleanType(), True),
        # --- Web-specific ---
        StructField("method", StringType(), True),
        StructField("path", StringType(), True),
        StructField("status_code", IntegerType(), True),
        StructField("user_agent", StringType(), True),
        StructField("bytes_sent", IntegerType(), True),
        # --- Firewall-specific ---
        StructField("action", StringType(), True),
        StructField("dest_ip", StringType(), True),
        StructField("dest_port", IntegerType(), True),
        StructField("protocol", StringType(), True),
        # --- Present on producers/log_generator.py output, not part of
        # the strict LogEvent contract; kept so it isn't lost, never
        # required. ---
        StructField("schema_version", StringType(), True),
    ]
)

# ISO-8601 patterns actually seen on `logs-raw`:
#   producers/log_generator.py's iso()          -> "2026-09-04T10:00:00Z"
#   consumers/schemas.py's LogEvent.isoformat()  -> "2026-09-04T10:00:00+00:00"
# Both are tried, in order; F.coalesce keeps the first non-null result.
_TIMESTAMP_PATTERNS = ("yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ssXXX")


def _parse_event_timestamp(column: str):
    candidates = [F.to_timestamp(F.col(column), p) for p in _TIMESTAMP_PATTERNS]
    # Bare fallback with no explicit pattern, in case a producer ever
    # emits fractional seconds or an offset the two patterns above
    # don't cover but Spark's default parser does.
    candidates.append(F.to_timestamp(F.col(column)))
    return F.coalesce(*candidates)


def _build_required_field_mask():
    """AND together an isNotNull/non-blank check for every field in
    REQUIRED_LOG_FIELDS. `timestamp` is checked via the parsed
    `event_timestamp` column instead of the raw string, since a
    non-blank-but-unparsable timestamp is exactly as invalid as a
    missing one."""
    checks = []
    for field in sorted(REQUIRED_LOG_FIELDS):
        if field == "timestamp":
            checks.append(F.col("event_timestamp").isNotNull())
        else:
            checks.append(F.col(field).isNotNull() & (F.trim(F.col(field)) != ""))
    mask = checks[0]
    for check in checks[1:]:
        mask = mask & check
    return mask


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SparkConsumerConfig:
    bootstrap_servers: str
    topic: str = DEFAULT_TOPIC
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


def build_spark_session(config: SparkConsumerConfig) -> SparkSession:
    return (
        SparkSession.builder.appName(config.app_name)
        .master(config.master)
        # Lets `python consumers/spark_consumer.py` work without an
        # explicit `--packages` flag (see module docstring). Harmless
        # no-op if the connector is already on the classpath.
        .config("spark.jars.packages", KAFKA_CONNECTOR_PACKAGE)
        .config("spark.sql.session.timeZone", "UTC")
        .getOrCreate()
    )


def read_kafka_stream(spark: SparkSession, config: SparkConsumerConfig) -> DataFrame:
    reader = (
        spark.readStream.format("kafka")
        .option("kafka.bootstrap.servers", config.bootstrap_servers)
        .option("subscribe", config.topic)
        .option("startingOffsets", config.starting_offsets)
        # If Kafka has already deleted offsets this query would read
        # next (e.g. retention expired while the job was down), the
        # default (true) fails the whole query. false logs and skips
        # ahead instead -- the right trade-off for a dev/local topic
        # with 24h retention (docker-compose.yml) where "the job was
        # down over the weekend" is routine, not fatal. Flip to true
        # for a deployment where silently skipping lost data is
        # unacceptable.
        .option("failOnDataLoss", str(config.fail_on_data_loss).lower())
    )
    if config.max_offsets_per_trigger:
        reader = reader.option(
            "maxOffsetsPerTrigger", config.max_offsets_per_trigger
        )
    return reader.load()


# --------------------------------------------------------------------------- #
# Parsing / validation
# --------------------------------------------------------------------------- #


def parse_and_validate(raw_df: DataFrame) -> DataFrame:
    """Parse the Kafka `value` bytes as JSON against LOG_EVENT_SCHEMA and
    add the columns downstream code needs to split valid vs invalid
    records. Never drops or raises on bad input -- see module docstring.
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
        .withColumn("_parsed", F.from_json(F.col("raw_value"), LOG_EVENT_SCHEMA))
        .select(
            "raw_value",
            "kafka_key",
            "kafka_topic",
            "kafka_partition",
            "kafka_offset",
            "kafka_produced_at",
            "_parsed.*",
        )
        .withColumn("event_timestamp", _parse_event_timestamp("timestamp"))
        .withColumn(
            "processing_lag_seconds",
            F.unix_timestamp(F.current_timestamp())
            - F.unix_timestamp(F.col("event_timestamp")),
        )
    )
    return parsed.withColumn("_is_valid", _build_required_field_mask())


# --------------------------------------------------------------------------- #
# Sinks
# --------------------------------------------------------------------------- #


def write_dead_letter_batch(dead_letter_dir: str):
    """Returns a foreachBatch function that logs a warning (with count)
    for any micro-batch containing invalid records, then appends them
    to dead_letter_dir as newline-delimited JSON. Using foreachBatch
    here (rather than a plain `.format("json")` sink) is what makes the
    "produce a warning log" acceptance criterion possible -- a bare
    file sink writes silently with no hook to log from."""

    def _write(batch_df: DataFrame, batch_id: int) -> None:
        batch_df.persist()
        try:
            count = batch_df.count()
            if count == 0:
                return
            logger.warning(
                "batch %d: %d invalid record(s) (unparsable JSON or missing "
                "required field) routed to dead-letter store at %s",
                batch_id,
                count,
                dead_letter_dir,
            )
            (
                batch_df.withColumn("dead_letter_batch_id", F.lit(batch_id))
                .withColumn("dead_letter_written_at", F.current_timestamp())
                .write.mode("append")
                .json(dead_letter_dir)
            )
        finally:
            batch_df.unpersist()

    return _write


CONSOLE_DISPLAY_COLUMNS = [
    "event_id",
    "timestamp",
    "event_timestamp",
    "source_ip",
    "event_type",
    "severity",
    "source",
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
    spark.sparkContext.setLogLevel("WARN")  # Spark's own chatter, not ours

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

    raw_df = read_kafka_stream(spark, config)
    parsed_df = parse_and_validate(raw_df)

    valid_df = parsed_df.filter(F.col("_is_valid")).drop("_is_valid")
    invalid_df = parsed_df.filter(~F.col("_is_valid")).drop("_is_valid")

    console_query = (
        valid_df.select(*CONSOLE_DISPLAY_COLUMNS)
        .writeStream.format("console")
        .outputMode("append")
        .option("truncate", "false")
        .option("checkpointLocation", config.console_checkpoint_dir)
        .trigger(processingTime=config.trigger_interval)
        .start()
    )

    dead_letter_query = (
        invalid_df.writeStream.foreachBatch(
            write_dead_letter_batch(config.dead_letter_dir)
        )
        .outputMode("append")
        .option("checkpointLocation", config.dead_letter_checkpoint_dir)
        .trigger(processingTime=config.trigger_interval)
        .start()
    )

    active_queries = [console_query, dead_letter_query]

    def _handle_shutdown(signum, frame) -> None:
        logger.info("received signal %s, stopping streaming queries...", signum)
        for q in active_queries:
            if q.isActive:
                q.stop()

    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)

    try:
        spark.streams.awaitAnyTermination()
    finally:
        # awaitAnyTermination() returns as soon as ONE query stops (for
        # any reason, including an error) -- surface that error, then
        # bring the whole job down cleanly rather than leaving the
        # other query running unattended.
        for q in active_queries:
            if q.isActive:
                continue
            exc = q.exception()
            if exc is not None:
                logger.error("streaming query %s terminated with error: %s", q.id, exc)
        for q in active_queries:
            if q.isActive:
                q.stop()
        spark.stop()
        logger.info("spark_consumer stopped")


if __name__ == "__main__":
    main()