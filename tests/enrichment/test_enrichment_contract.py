"""Interconnection tests: enrichment <-> detection / schema / storage.

Each test pins one place where the GeoIP step meets existing code, so a rename
on either side fails here instead of silently producing un-enriched data.
"""

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from api.services.es_storage_service import ElasticsearchStorageService
from api.services.spark_dual_sink import (
    GEO_STREAM_TO_LOGEVENT,
    write_valid_events_batch,
)
from consumers.schemas import LogEvent
from enrichment.spark_enrichment import (
    GEO_COLUMNS,
    GEO_COUNTRY_COL,
    GEO_LATITUDE_COL,
    GEO_LONGITUDE_COL,
)

GEO = dict(country="US", city="Mountain View", latitude=37.39, longitude=-122.08)


def ssh_event(**overrides):
    base = dict(
        event_id=uuid.uuid4(),
        timestamp=datetime(2026, 10, 19, 10, 0, tzinfo=timezone.utc),
        source_ip="8.8.8.8",
        event_type="successful_login",
        severity="INFO",
        raw_message="Accepted password for alice from 8.8.8.8",
        source="ssh",
        username="alice",
        auth_method="password",
        success=True,
    )
    base.update(overrides)
    return base


# --- detection <-> enrichment ---------------------------------------------


def test_column_names_match_the_impossible_travel_rule():
    from detection_engine.rules import impossible_travel as it

    assert GEO_COUNTRY_COL == it.COUNTRY_COL
    assert GEO_LATITUDE_COL == it.LATITUDE_COL
    assert GEO_LONGITUDE_COL == it.LONGITUDE_COL


# --- schema <-> enrichment --------------------------------------------------


def test_logevent_accepts_optional_geo_fields():
    event = LogEvent(**ssh_event(**GEO))
    assert (event.country, event.city) == ("US", "Mountain View")


def test_logevent_geo_fields_are_optional():
    event = LogEvent(**ssh_event())
    assert event.country is None and event.latitude is None


@pytest.mark.parametrize(
    "field,value",
    [("latitude", 91), ("latitude", -91), ("longitude", 181), ("longitude", -181)],
)
def test_logevent_rejects_out_of_range_coordinates(field, value):
    with pytest.raises(ValidationError):
        LogEvent(**ssh_event(**{field: value}))


def test_logevent_still_forbids_unknown_fields():
    with pytest.raises(ValidationError):
        LogEvent(**ssh_event(geo_is_private=True))


def test_stream_columns_map_onto_real_logevent_fields():
    assert set(GEO_STREAM_TO_LOGEVENT) <= set(GEO_COLUMNS)
    assert set(GEO_STREAM_TO_LOGEVENT.values()) <= set(LogEvent.model_fields)
    assert "geo_is_private" not in GEO_STREAM_TO_LOGEVENT  # stream-only


# --- storage <-> enrichment -------------------------------------------------


def test_elasticsearch_document_gets_country_city_and_geo_point():
    doc = ElasticsearchStorageService.to_document(LogEvent(**ssh_event(**GEO)))
    assert doc["country"] == "US"
    assert doc["city"] == "Mountain View"
    assert doc["location"] == {"lat": 37.39, "lon": -122.08}
    assert "latitude" not in doc and "longitude" not in doc


def test_elasticsearch_document_fields_are_all_in_the_strict_mapping():
    from scripts.es_mapping import MAPPINGS

    doc = ElasticsearchStorageService.to_document(LogEvent(**ssh_event(**GEO)))
    assert set(doc) <= set(MAPPINGS["properties"])


def test_postgres_row_carries_geo_in_metadata():
    from api.services.storage_service import EventStorageService

    row = EventStorageService(session_factory=lambda: None)._to_row(
        LogEvent(**ssh_event(**GEO))
    )
    assert row["metadata"]["country"] == "US"
    assert row["metadata"]["latitude"] == 37.39


# --- Spark stream rows -> sink adapter -> LogEvent ---------------------------


class CapturingWriter:
    def __init__(self):
        self.events = []

    def write(self, events):
        self.events.extend(events)
        return SimpleNamespace(
            events_received=len(self.events),
            postgres_result=len(self.events),
            elasticsearch_result=SimpleNamespace(indexed=len(self.events), failed=0),
        )


def test_enriched_stream_rows_reach_the_sinks_as_logevents(spark, city_db):
    from pyspark.sql import functions as F

    from enrichment.spark_enrichment import add_geoip_columns

    df = spark.createDataFrame(
        [
            (str(uuid.uuid4()), "2026-10-19T10:00:00Z", "8.8.8.8"),
            (str(uuid.uuid4()), "2026-10-19T10:00:01Z", "192.168.1.1"),
        ],
        ["event_id", "timestamp", "source_ip"],
    )
    df = (
        df.withColumn("event_type", F.lit("successful_login"))
        .withColumn("severity", F.lit("INFO"))
        .withColumn("raw_message", F.lit("Accepted password for alice"))
        .withColumn("source", F.lit("ssh"))
        .withColumn("username", F.lit("alice"))
        .withColumn("auth_method", F.lit("password"))
        .withColumn("success", F.lit(True))
    )

    writer = CapturingWriter()
    write_valid_events_batch(writer)(add_geoip_columns(df, db_path=city_db), 0)

    public = next(e for e in writer.events if e.source_ip == "8.8.8.8")
    private = next(e for e in writer.events if e.source_ip == "192.168.1.1")
    assert (public.country, public.city) == ("US", "Mountain View")
    assert public.latitude == pytest.approx(37.39)
    assert public.longitude == pytest.approx(-122.08)
    assert private.country is None and private.latitude is None


# --- spark_consumer <-> enrichment --------------------------------------------


def test_spark_session_gives_workers_the_repo_on_pythonpath(monkeypatch):
    import os

    from consumers import spark_consumer

    monkeypatch.setenv("PYTHONPATH", "/somewhere/else")
    first, *rest = spark_consumer._executor_python_path().split(os.pathsep)
    assert os.path.isdir(os.path.join(first, "enrichment"))
    assert rest == ["/somewhere/else"]


# --- full pipeline (minus Kafka) ----------------------------------------------


def test_raw_kafka_row_to_enriched_logevent_and_es_document(spark, city_db):
    """raw producer JSON -> parse/normalize/validate -> GeoIP -> sink adapter
    -> LogEvent -> Elasticsearch document, in the order main() uses them."""
    import json

    from pyspark.sql import functions as F
    from pyspark.sql.types import (
        LongType,
        StringType,
        StructField,
        StructType,
        TimestampType,
    )

    from consumers.spark_consumer import parse_normalize_and_validate
    from enrichment.spark_enrichment import add_geoip_columns

    kafka_schema = StructType(
        [
            StructField("value", StringType(), True),
            StructField("key", StringType(), True),
            StructField("topic", StringType(), True),
            StructField("partition", LongType(), True),
            StructField("offset", LongType(), True),
            StructField("timestamp", TimestampType(), True),
        ]
    )

    def raw_login(ip):
        return json.dumps(
            {
                "schema_version": "1.0",
                "event_id": str(uuid.uuid4()),
                "timestamp": "2026-10-19T10:00:00Z",
                "source_ip": ip,
                "event_type": "successful_login",
                "username": "alice",
                "service": "sshd",
                "outcome": "success",
                "dest_port": 22,
                "raw_message": f"Accepted password for alice from {ip} port 22 ssh2",
            }
        )

    now = datetime(2026, 10, 19, 10, 0, 1)
    rows = [
        (raw_login("8.8.8.8"), None, "logs-raw", 0, 0, now),
        (raw_login("192.168.1.1"), None, "logs-raw", 0, 1, now),
        ("{not json", None, "logs-raw", 0, 2, now),  # dead-letter material
    ]
    parsed = parse_normalize_and_validate(spark.createDataFrame(rows, kafka_schema))

    valid_df = parsed.filter(F.col("_is_valid")).drop("_is_valid")
    invalid_df = parsed.filter(~F.col("_is_valid")).drop("_is_valid")
    enriched_df = add_geoip_columns(valid_df, db_path=city_db)

    # Dead-letter rows are left un-enriched.
    assert invalid_df.count() == 1
    assert not set(GEO_COLUMNS) & set(invalid_df.columns)

    # The columns impossible_travel reads are present and typed.
    types = {f.name: f.dataType.simpleString() for f in enriched_df.schema.fields}
    assert types["geo_country"] == "string"
    assert types["geo_latitude"] == "double" and types["geo_longitude"] == "double"

    writer = CapturingWriter()
    write_valid_events_batch(writer)(enriched_df, 0)
    assert len(writer.events) == 2

    public = next(e for e in writer.events if e.source_ip == "8.8.8.8")
    assert (public.country, public.city) == ("US", "Mountain View")
    doc = ElasticsearchStorageService.to_document(public)
    assert doc["country"] == "US"
    assert doc["location"] == {"lat": 37.39, "lon": -122.08}

    private = next(e for e in writer.events if e.source_ip == "192.168.1.1")
    assert private.country is None and private.latitude is None
    assert "location" not in ElasticsearchStorageService.to_document(private)


# --- pipeline.enrich_event <-> Spark columns ----------------------------------


def test_enrich_event_fields_match_the_spark_stream_columns():
    """The plain-Python and Spark paths must emit identical column names."""
    from enrichment.pipeline import ENRICHMENT_FIELDS
    from enrichment.spark_enrichment import ASN_COLUMNS

    assert set(ENRICHMENT_FIELDS) == set(GEO_COLUMNS) | set(ASN_COLUMNS)


def test_geo_field_map_matches_the_geoip_enricher_keys():
    from enrichment.geoip import GeoIPEnricher
    from enrichment.pipeline import GEO_FIELD_MAP
    from enrichment.spark_enrichment import _RESULT_KEY_TO_COLUMN

    assert GEO_FIELD_MAP == _RESULT_KEY_TO_COLUMN
    assert set(GEO_FIELD_MAP) == set(GeoIPEnricher(reader=object()).enrich("10.0.0.1"))


def test_asn_columns_are_stream_only_until_storage_supports_them():
    """asn_* reach detection rules via the stream; LogEvent has no ASN fields
    yet, so they must not leak into the (extra=forbid) sink adapter."""
    assert "asn_number" not in LogEvent.model_fields
    assert "asn_org" not in set(GEO_STREAM_TO_LOGEVENT.values())


def test_asn_enriched_stream_rows_still_reach_the_sinks(spark, city_db, asn_db):
    """Extra asn_* stream columns must not break write_valid_events_batch."""
    from pyspark.sql import functions as F

    from enrichment.spark_enrichment import add_asn_columns, add_geoip_columns

    df = spark.createDataFrame(
        [(str(uuid.uuid4()), "2026-10-19T10:00:00Z", "8.8.8.8")],
        ["event_id", "timestamp", "source_ip"],
    )
    df = (
        df.withColumn("event_type", F.lit("successful_login"))
        .withColumn("severity", F.lit("INFO"))
        .withColumn("raw_message", F.lit("Accepted password for alice"))
        .withColumn("source", F.lit("ssh"))
        .withColumn("username", F.lit("alice"))
        .withColumn("auth_method", F.lit("password"))
        .withColumn("success", F.lit(True))
    )
    enriched = add_asn_columns(
        add_geoip_columns(df, db_path=city_db), db_path=asn_db
    )
    assert "asn_org" in enriched.columns

    writer = CapturingWriter()
    write_valid_events_batch(writer)(enriched, 0)
    assert writer.events[0].country == "US"