"""The ``logs-enriched`` event contract: build the Kafka payload, parse it back.

    enriched stream (geo_* ... columns)
            |
            v  build_enriched_payload()
    Kafka  logs-enriched   key = event_id, value = JSON (ENRICHED_EVENT_SCHEMA)
            |
            v  parse_enriched_events()
    typed DataFrame for downstream consumers (rules engine, ...)

Payload fields
    * every canonical LogEvent field (consumers/schemas.py): event_id,
      timestamp, source_ip, event_type, severity, raw_message, source, and the
      source-specific optional ones;
    * country, city, latitude, longitude   (GeoIP)
    * asn_number, asn_org                  (ASN)
    * reputation_score, is_known_threat, threat_categories (IP reputation)
    * is_private_ip                        (the stream's geo_is_private)
    * enriched_at                          (when the enrichment stage ran; with
      ``timestamp`` it gives the end-to-end latency of every event)

All fields are always present: unknown values are explicit JSON nulls
(``"asn_org": null``), never missing keys, so consumers see a stable schema.
``timestamp`` and ``enriched_at`` are ISO-8601 UTC strings.

Naming: the Kafka payload uses the canonical LogEvent names (``country``,
``latitude``...), while the in-stream columns the detection rules read keep
their ``geo_*`` names (see enrichment/spark_enrichment.py).
``STREAM_TO_PAYLOAD`` is the one place that maps between them, in both
directions.
"""

from __future__ import annotations

from pyspark.sql import Column, DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import (
    ArrayType,
    BooleanType,
    DataType,
    DoubleType,
    IntegerType,
    LongType,
    StringType,
    StructField,
    StructType,
)

DEFAULT_ENRICHED_TOPIC = "logs-enriched"

# in-stream enrichment column -> name in the Kafka payload / LogEvent
STREAM_TO_PAYLOAD: dict[str, str] = {
    "geo_country": "country",
    "geo_city": "city",
    "geo_latitude": "latitude",
    "geo_longitude": "longitude",
    "geo_is_private": "is_private_ip",
}
PAYLOAD_TO_STREAM: dict[str, str] = {v: k for k, v in STREAM_TO_PAYLOAD.items()}

# Timestamps are written as ISO-8601 in UTC (the Spark session runs in UTC, so
# XXX renders as "Z").
_TIMESTAMP_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX"

# Every canonical LogEvent field plus the payload-only extras, with the Spark
# type used on the wire. tests/consumers/test_enriched_events.py fails if
# LogEvent gains a field that is missing here.
_FIELDS: list[tuple[str, DataType]] = [
    ("event_id", StringType()),
    ("timestamp", StringType()),
    ("source_ip", StringType()),
    ("event_type", StringType()),
    ("severity", StringType()),
    ("raw_message", StringType()),
    ("source", StringType()),
    ("username", StringType()),
    ("auth_method", StringType()),
    ("success", BooleanType()),
    ("method", StringType()),
    ("path", StringType()),
    ("status_code", IntegerType()),
    ("user_agent", StringType()),
    ("bytes_sent", LongType()),
    ("action", StringType()),
    ("dest_ip", StringType()),
    ("dest_port", IntegerType()),
    ("protocol", StringType()),
    ("country", StringType()),
    ("city", StringType()),
    ("latitude", DoubleType()),
    ("longitude", DoubleType()),
    ("asn_number", LongType()),
    ("asn_org", StringType()),
    ("reputation_score", IntegerType()),
    ("is_known_threat", BooleanType()),
    ("threat_categories", ArrayType(StringType())),
    ("is_private_ip", BooleanType()),
    ("enriched_at", StringType()),
]

ENRICHED_EVENT_SCHEMA = StructType([StructField(n, t, True) for n, t in _FIELDS])
ENRICHED_EVENT_FIELDS: tuple[str, ...] = tuple(name for name, _ in _FIELDS)


def _iso(column: Column) -> Column:
    return F.date_format(column, _TIMESTAMP_FORMAT)


def _source_column(name: str, columns: set[str]):
    """The DataFrame column feeding payload field ``name``, or None.

    The stream's ``geo_*`` name wins over the unprefixed one, because the
    enrichment stage's output is the authority for those fields.
    """
    stream_name = PAYLOAD_TO_STREAM.get(name)
    if stream_name and stream_name in columns:
        return stream_name
    return name if name in columns else None


def _timestamp_expr(columns: set[str], dtypes: dict[str, str]) -> Column:
    if "event_timestamp" in columns and dtypes["event_timestamp"] == "timestamp":
        return _iso(F.col("event_timestamp"))
    if "timestamp" in columns:
        if dtypes["timestamp"] == "timestamp":
            return _iso(F.col("timestamp"))
        return F.col("timestamp").cast("string")
    return F.lit(None).cast("string")


def _enriched_at_expr(columns: set[str], dtypes: dict[str, str]) -> Column:
    if "enriched_at" not in columns:
        return _iso(F.current_timestamp())
    if dtypes["enriched_at"] == "timestamp":
        return _iso(F.col("enriched_at"))
    return F.col("enriched_at").cast("string")


def build_enriched_payload(df: DataFrame) -> DataFrame:
    """Turn an enriched stream DataFrame into Kafka ``key`` / ``value`` columns.

    The result has exactly the two string columns Spark's Kafka sink needs:
    ``key`` (event_id) and ``value`` (the JSON event). Fields missing from
    ``df`` are emitted as explicit nulls so the schema is always complete.
    """
    columns = set(df.columns)
    dtypes = dict(df.dtypes)

    expressions: dict[str, Column] = {}
    for name, dtype in _FIELDS:
        if name == "timestamp":
            expr = _timestamp_expr(columns, dtypes)
        elif name == "enriched_at":
            expr = _enriched_at_expr(columns, dtypes)
        else:
            source = _source_column(name, columns)
            if source is None:
                expr = F.lit(None).cast(dtype)
            else:
                expr = F.col(source).cast(dtype)
        expressions[name] = expr.alias(name)

    return df.select(
        expressions["event_id"].alias("key"),
        F.to_json(
            F.struct(*expressions.values()), {"ignoreNullFields": "false"}
        ).alias("value"),
    )


def parse_enriched_events(df: DataFrame, value_col: str = "value") -> DataFrame:
    """Parse ``logs-enriched`` JSON back into a typed DataFrame.

    Adds the in-stream names the detection rules read (``geo_country``,
    ``geo_latitude``, ``geo_longitude``, ``geo_city``, ``geo_is_private``) next
    to the canonical ones, and ``event_timestamp`` (a real timestamp). A value
    that is not valid JSON yields an all-null row rather than an error.
    """
    parsed = df.select(
        F.from_json(F.col(value_col).cast("string"), ENRICHED_EVENT_SCHEMA).alias("_e")
    ).select("_e.*")
    for payload_name, stream_name in PAYLOAD_TO_STREAM.items():
        parsed = parsed.withColumn(stream_name, F.col(payload_name))
    return parsed.withColumn("event_timestamp", F.to_timestamp("timestamp"))