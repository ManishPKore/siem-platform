"""Shared builders: real Kafka-shaped rows through the real pipeline stages."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from pyspark.sql.types import (
    LongType,
    StringType,
    StructField,
    StructType,
    TimestampType,
)

KAFKA_SCHEMA = StructType(
    [
        StructField("value", StringType(), True),
        StructField("key", StringType(), True),
        StructField("topic", StringType(), True),
        StructField("partition", LongType(), True),
        StructField("offset", LongType(), True),
        StructField("timestamp", TimestampType(), True),
    ]
)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def raw_login(ip: str, *, timestamp: str = "2026-10-19T10:00:00Z", event_id=None) -> str:
    """A raw producer-shaped successful SSH login, as published to logs-raw."""
    return json.dumps(
        {
            "schema_version": "1.0",
            "event_id": event_id or str(uuid.uuid4()),
            "timestamp": timestamp,
            "source_ip": ip,
            "event_type": "successful_login",
            "username": "alice",
            "service": "sshd",
            "outcome": "success",
            "dest_port": 22,
            "raw_message": f"Accepted password for alice from {ip} port 22 ssh2",
        }
    )


def kafka_df(spark, values):
    produced = datetime(2026, 10, 19, 10, 0, 1)
    rows = [(v, None, "logs-raw", 0, i, produced) for i, v in enumerate(values)]
    return spark.createDataFrame(rows, KAFKA_SCHEMA)


def enriched_df(spark, values, *, city_db, asn_db, blocklist):
    """raw JSON strings -> parse -> normalize -> validate -> enrichment stage.

    Returns (valid_enriched_df, invalid_df), exactly as spark_consumer.main()
    builds them (minus the Kafka source).
    """
    from pyspark.sql import functions as F

    from consumers.spark_consumer import (
        build_enrichment_stage,
        parse_normalize_and_validate,
    )

    parsed = parse_normalize_and_validate(kafka_df(spark, values))
    valid = parsed.filter(F.col("_is_valid")).drop("_is_valid")
    invalid = parsed.filter(~F.col("_is_valid")).drop("_is_valid")
    stage = build_enrichment_stage(
        valid,
        geoip_db_path=str(city_db),
        asn_db_path=str(asn_db),
        blocklist_path=str(blocklist),
    )
    return stage, invalid