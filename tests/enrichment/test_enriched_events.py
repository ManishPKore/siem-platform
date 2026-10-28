"""Tests for consumers/enriched_events.py: the logs-enriched payload contract."""

import json
import re
import uuid

import pytest

pytest.importorskip("pyspark")

from pyspark.sql import functions as F
from pyspark.sql.types import (
    BooleanType,
    DoubleType,
    StringType,
    StructField,
    StructType,
    TimestampType,
)

from consumers.enriched_events import (
    ENRICHED_EVENT_FIELDS,
    ENRICHED_EVENT_SCHEMA,
    PAYLOAD_TO_STREAM,
    STREAM_TO_PAYLOAD,
    build_enriched_payload,
    parse_enriched_events,
)
from consumers.schemas import LogEvent
from enrichment.spark_enrichment import ENRICHMENT_COLUMNS
from tests.enrichment.pipeline_helpers import enriched_df, raw_login

ISO_UTC = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")

# The issue's acceptance criterion for the logs-enriched topic.
ACCEPTANCE_FIELDS = (
    "country", "city", "latitude", "longitude",
    "asn_org", "is_known_threat", "reputation_score",
)


@pytest.fixture
def blocklist(tmp_path):
    path = tmp_path / "bad.txt"
    path.write_text("8.8.8.8\n")
    return path


@pytest.fixture
def stage(spark, city_db, asn_db, blocklist):
    ids = [str(uuid.uuid4()) for _ in range(3)]
    values = [
        raw_login("8.8.8.8", event_id=ids[0]),  # public, blocklisted
        raw_login("192.168.1.1", event_id=ids[1]),  # private
        raw_login("81.2.69.142", event_id=ids[2]),  # public, not blocklisted
    ]
    df, _ = enriched_df(spark, values, city_db=city_db, asn_db=asn_db, blocklist=blocklist)
    return df, ids


def payloads(df):
    return {
        row["key"]: json.loads(row["value"]) for row in build_enriched_payload(df).collect()
    }


# ---- acceptance: contents of logs-enriched ------------------------------------


def test_acceptance_payload_has_all_normalized_fields_plus_enrichment(stage):
    df, ids = stage
    event = payloads(df)[ids[0]]

    for field in LogEvent.model_fields:  # every normalized (canonical) field
        assert field in event, field
    for field in ACCEPTANCE_FIELDS:
        assert field in event, field

    assert event["event_id"] == ids[0]
    assert event["source_ip"] == "8.8.8.8"
    assert event["event_type"] == "successful_login"
    assert event["source"] == "ssh" and event["username"] == "alice"
    assert event["country"] == "US" and event["city"] == "Mountain View"
    assert event["latitude"] == pytest.approx(37.39)
    assert event["longitude"] == pytest.approx(-122.08)
    assert event["asn_org"] == "GOOGLE" and event["asn_number"] == 15169
    assert event["is_known_threat"] is True  # blocklisted above
    assert event["reputation_score"] == 100
    assert event["threat_categories"] == ["local_blocklist"]
    assert event["is_private_ip"] is False


def test_private_ip_events_carry_explicit_null_enrichment_not_missing_keys(stage):
    df, ids = stage
    event = payloads(df)[ids[1]]
    assert event["is_private_ip"] is True
    for field in ("country", "city", "latitude", "longitude", "asn_org", "asn_number", "reputation_score"):
        assert field in event and event[field] is None, field
    assert event["is_known_threat"] is False
    assert event["threat_categories"] == []


def test_every_event_has_exactly_the_contract_fields(stage):
    df, _ = stage
    for event in payloads(df).values():
        assert set(event) == set(ENRICHED_EVENT_FIELDS)


def test_key_is_the_event_id_and_value_is_a_string(stage):
    df, ids = stage
    out = build_enriched_payload(df)
    assert out.columns == ["key", "value"]
    assert [f.dataType for f in out.schema.fields] == [StringType(), StringType()]
    assert {r["key"] for r in out.collect()} == set(ids)


def test_timestamps_are_iso_8601_utc_and_enriched_at_follows_event_time(stage):
    df, ids = stage
    event = payloads(df)[ids[0]]
    assert ISO_UTC.match(event["timestamp"]) and event["timestamp"].startswith("2026-10-19T10:00:00")
    assert ISO_UTC.match(event["enriched_at"])
    assert event["enriched_at"] > event["timestamp"]  # lexicographic == chronological


def test_every_logevent_field_is_in_the_contract():
    assert set(LogEvent.model_fields) <= set(ENRICHED_EVENT_FIELDS)
    assert set(ENRICHED_EVENT_FIELDS) - set(LogEvent.model_fields) == {"is_private_ip", "enriched_at"}


def test_the_stream_columns_map_onto_contract_fields():
    assert set(STREAM_TO_PAYLOAD) <= set(ENRICHMENT_COLUMNS)
    assert set(STREAM_TO_PAYLOAD.values()) <= set(ENRICHED_EVENT_FIELDS)
    assert PAYLOAD_TO_STREAM == {v: k for k, v in STREAM_TO_PAYLOAD.items()}


# ---- robustness ---------------------------------------------------------------


def test_missing_columns_become_explicit_nulls(spark):
    df = spark.createDataFrame([("e1", "2026-10-19T10:00:00Z", "8.8.8.8")], ["event_id", "timestamp", "source_ip"])
    event = payloads(df)["e1"]
    assert set(event) == set(ENRICHED_EVENT_FIELDS)
    assert event["source_ip"] == "8.8.8.8" and event["timestamp"] == "2026-10-19T10:00:00Z"
    assert event["country"] is None and event["asn_org"] is None and event["method"] is None
    assert ISO_UTC.match(event["enriched_at"])  # stamped at payload time


def test_stream_geo_columns_win_over_unprefixed_ones(spark):
    schema = StructType([
        StructField("event_id", StringType()), StructField("country", StringType()),
        StructField("geo_country", StringType()), StructField("geo_is_private", BooleanType()),
        StructField("geo_latitude", DoubleType()),
    ])
    df = spark.createDataFrame([("e1", "OLD", "US", True, 1.5)], schema)
    event = payloads(df)["e1"]
    assert event["country"] == "US" and event["is_private_ip"] is True
    assert event["latitude"] == 1.5


def test_timestamp_typed_columns_are_formatted_as_iso(spark):
    from datetime import datetime

    schema = StructType([StructField("event_id", StringType()), StructField("timestamp", TimestampType())])
    df = spark.createDataFrame([("e1", datetime(2026, 1, 2, 3, 4, 5))], schema)
    assert payloads(df)["e1"]["timestamp"] == "2026-01-02T03:04:05.000Z"


# ---- round trip ---------------------------------------------------------------


def test_parse_inverts_build_and_restores_the_rule_column_names(stage):
    df, ids = stage
    parsed = parse_enriched_events(build_enriched_payload(df))
    rows = {r["event_id"]: r.asDict() for r in parsed.collect()}
    assert set(rows) == set(ids)

    google = rows[ids[0]]
    assert google["geo_country"] == google["country"] == "US"
    assert google["geo_latitude"] == pytest.approx(37.39)
    assert google["geo_longitude"] == pytest.approx(-122.08)
    assert google["geo_is_private"] is False
    assert google["asn_org"] == "GOOGLE" and google["threat_categories"] == ["local_blocklist"]
    assert rows[ids[1]]["geo_is_private"] is True

    types = {f.name: f.dataType for f in parsed.schema.fields}
    assert types["event_timestamp"] == TimestampType()
    assert parsed.where(F.col("event_timestamp").isNull()).count() == 0
    assert [f.name for f in ENRICHED_EVENT_SCHEMA.fields] == list(ENRICHED_EVENT_FIELDS)


def test_invalid_json_parses_to_an_all_null_row_instead_of_failing(spark):
    parsed = parse_enriched_events(spark.createDataFrame([("{not json",)], ["value"]))
    row = parsed.collect()[0]
    assert row["event_id"] is None and row["asn_org"] is None