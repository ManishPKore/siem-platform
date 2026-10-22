"""Tests for enrichment/spark_enrichment.py (the Spark pipeline step)."""

import pytest

pytest.importorskip("pyspark")
pytest.importorskip("pyarrow")

from pyspark.sql.types import (
    BooleanType,
    DoubleType,
    StringType,
    StructField,
    StructType,
)

from enrichment.spark_enrichment import GEO_COLUMNS, add_geoip_columns
from tests.enrichment.conftest import UNKNOWN_PUBLIC_IP

INPUT_SCHEMA = StructType(
    [
        StructField("event_id", StringType(), True),
        StructField("source_ip", StringType(), True),
    ]
)


def make_df(spark, ips):
    return spark.createDataFrame(
        [(f"evt-{i}", ip) for i, ip in enumerate(ips)], schema=INPUT_SCHEMA
    )


def by_event(df):
    return {row["event_id"]: row.asDict() for row in df.collect()}


def test_adds_geo_columns_with_expected_types(spark, city_db):
    out = add_geoip_columns(make_df(spark, ["8.8.8.8"]), db_path=city_db)

    assert out.columns == ["event_id", "source_ip", *GEO_COLUMNS]
    types = {f.name: f.dataType for f in out.schema.fields}
    assert types["geo_country"] == StringType()
    assert types["geo_city"] == StringType()
    assert types["geo_latitude"] == DoubleType()
    assert types["geo_longitude"] == DoubleType()
    assert types["geo_is_private"] == BooleanType()


def test_enriches_public_private_unknown_and_invalid(spark, city_db):
    ips = ["8.8.8.8", "192.168.1.1", UNKNOWN_PUBLIC_IP, "not_an_ip", None]
    out = by_event(add_geoip_columns(make_df(spark, ips), db_path=city_db))

    public = out["evt-0"]
    assert public["geo_country"] == "US"
    assert public["geo_city"] == "Mountain View"
    assert public["geo_latitude"] == pytest.approx(37.39)
    assert public["geo_longitude"] == pytest.approx(-122.08)
    assert public["geo_is_private"] is False

    private = out["evt-1"]
    assert private["geo_is_private"] is True
    assert private["geo_country"] is None and private["geo_latitude"] is None

    unknown = out["evt-2"]
    assert unknown["geo_is_private"] is False and unknown["geo_country"] is None

    for event_id in ("evt-3", "evt-4"):  # invalid / null IP: all-null, no crash
        assert all(out[event_id][c] is None for c in GEO_COLUMNS)


def test_never_drops_or_reorders_rows(spark, city_db):
    ips = ["8.8.8.8", "10.0.0.1", "garbage", "81.2.69.142"] * 25
    df = make_df(spark, ips)
    out = add_geoip_columns(df, db_path=city_db)
    assert out.count() == df.count() == 100
    assert [r["source_ip"] for r in out.collect()] == ips


def test_missing_database_does_not_break_the_stream(spark, tmp_path):
    missing = str(tmp_path / "nope.mmdb")
    out = by_event(
        add_geoip_columns(make_df(spark, ["8.8.8.8", "10.0.0.1"]), db_path=missing)
    )
    assert out["evt-0"]["geo_country"] is None
    assert out["evt-0"]["geo_is_private"] is False
    assert out["evt-1"]["geo_is_private"] is True


def test_custom_ip_column(spark, city_db):
    df = spark.createDataFrame([("8.8.8.8",)], ["client_ip"])
    out = add_geoip_columns(df, ip_col="client_ip", db_path=city_db)
    assert out.collect()[0]["geo_country"] == "US"


def test_udf_is_evaluated_once_per_row_not_once_per_column(spark, city_db):
    """The five geo_* columns must come from one UDF pass."""
    plan = add_geoip_columns(
        make_df(spark, ["8.8.8.8"]), db_path=city_db
    )._jdf.queryExecution().executedPlan().toString()
    assert plan.count("ArrowEvalPython") == 1


def test_works_on_a_streaming_dataframe(spark, city_db, tmp_path):
    """spark_consumer.py applies the step to a streaming DataFrame."""
    source_dir = tmp_path / "events"
    source_dir.mkdir()
    (source_dir / "batch.json").write_text(
        "\n".join(
            [
                '{"event_id": "e1", "source_ip": "8.8.8.8"}',
                '{"event_id": "e2", "source_ip": "10.0.0.1"}',
                '{"event_id": "e3", "source_ip": "not_an_ip"}',
            ]
        )
    )

    stream = spark.readStream.schema(INPUT_SCHEMA).json(str(source_dir))
    enriched = add_geoip_columns(stream, db_path=city_db)
    assert enriched.isStreaming

    seen = []
    query = (
        enriched.writeStream.foreachBatch(
            lambda batch_df, _id: seen.extend(batch_df.collect())
        )
        .option("checkpointLocation", str(tmp_path / "checkpoint"))
        .trigger(availableNow=True)
        .start()
    )
    assert query.awaitTermination(120)

    rows = {row["event_id"]: row.asDict() for row in seen}
    assert (rows["e1"]["geo_country"], rows["e1"]["geo_is_private"]) == ("US", False)
    assert (rows["e2"]["geo_country"], rows["e2"]["geo_is_private"]) == (None, True)
    assert all(rows["e3"][c] is None for c in GEO_COLUMNS)