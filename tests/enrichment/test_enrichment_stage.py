"""The unified enrichment stage end to end (everything except the Kafka transport)."""

import json

import pytest

pytest.importorskip("pyspark")

import pandas as pd

from api.services.es_storage_service import ElasticsearchStorageService
from api.services.spark_dual_sink import write_valid_events_batch
from consumers.enriched_sink import make_enriched_batch_handler
from enrichment.spark_enrichment import (
    ENRICHMENT_COLUMNS,
    add_enrichment_columns,
    enrichment_frame,
    register_enrichment_udf,
)
from scripts.es_mapping import MAPPINGS
from tests.enrichment.pipeline_helpers import enriched_df, now_iso, raw_login
from tests.enrichment.test_enrichment_contract import CapturingWriter
from tests.enrichment.test_pipeline_enricher import Exploding


class KafkaCapture:
    topic = "logs-enriched"

    def __init__(self):
        self.events = []

    def write(self, payload_df):
        self.events.extend(json.loads(r["value"]) for r in payload_df.collect())


@pytest.fixture
def blocklist(tmp_path):
    path = tmp_path / "bad.txt"
    path.write_text("81.2.69.142\n")
    return path


def run_batch(spark, values, city_db, asn_db, blocklist):
    df, invalid = enriched_df(spark, values, city_db=city_db, asn_db=asn_db, blocklist=blocklist)
    writer, kafka = CapturingWriter(), KafkaCapture()
    make_enriched_batch_handler(write_valid_events_batch(writer), kafka)(df, 0)
    return writer.events, kafka.events, invalid


def test_raw_events_come_out_enriched_in_kafka_and_in_the_es_document(spark, city_db, asn_db, blocklist):
    values = [raw_login("8.8.8.8", timestamp=now_iso()), raw_login("81.2.69.142", timestamp=now_iso()),
              raw_login("192.168.1.1", timestamp=now_iso())]
    events, kafka, _ = run_batch(spark, values, city_db, asn_db, blocklist)

    assert len(events) == len(kafka) == 3
    by_ip = {e["source_ip"]: e for e in kafka}
    threat = by_ip["81.2.69.142"]
    assert (threat["country"], threat["city"]) == ("GB", "London")
    assert threat["asn_org"] == "BIG-PRIVATE-USE-ASN"
    assert threat["is_known_threat"] is True and threat["reputation_score"] == 100

    # Elasticsearch: location is a geo_point built from the same enriched row
    assert MAPPINGS["properties"]["location"]["type"] == "geo_point"
    stored = {e.source_ip: e for e in events}
    doc = ElasticsearchStorageService.to_document(stored["81.2.69.142"])
    assert doc["location"] == {"lat": pytest.approx(51.51), "lon": pytest.approx(-0.09)}
    assert doc["country"] == "GB" and doc["asn_org"] == "BIG-PRIVATE-USE-ASN"
    assert doc["is_known_threat"] is True
    assert set(doc) <= set(MAPPINGS["properties"])  # strict mapping accepts the document
    assert "location" not in ElasticsearchStorageService.to_document(stored["192.168.1.1"])


def test_dead_letter_rows_are_never_enriched(spark, city_db, asn_db, blocklist):
    events, kafka, invalid = run_batch(
        spark, [raw_login("8.8.8.8", timestamp=now_iso()), "{not json"], city_db, asn_db, blocklist
    )
    assert len(kafka) == 1 and invalid.count() == 1
    assert not set(ENRICHMENT_COLUMNS) & set(invalid.columns)


def test_enrichment_failures_do_not_crash_the_pipeline(spark, city_db, asn_db, tmp_path):
    corrupt = tmp_path / "corrupt.mmdb"
    corrupt.write_bytes(b"not a database")
    values = [raw_login("8.8.8.8", timestamp=now_iso()), raw_login("1.2.3.4", timestamp=now_iso())]
    events, kafka, _ = run_batch(spark, values, corrupt, corrupt, tmp_path / "missing.txt")

    assert len(kafka) == 2 and len(events) == 2  # events still delivered
    for event in kafka:
        assert event["country"] is None and event["asn_org"] is None
        assert event["is_known_threat"] is False and event["threat_categories"] == []


# ---- the unified UDF ---------------------------------------------------------------


def make_df(spark, ips):
    return spark.createDataFrame([(f"e{i}", ip) for i, ip in enumerate(ips)], "event_id string, source_ip string")


def test_one_udf_pass_adds_every_enrichment_column(spark, city_db, asn_db, blocklist):
    out = add_enrichment_columns(
        make_df(spark, ["8.8.8.8"]), geoip_db_path=city_db, asn_db_path=asn_db, blocklist_path=blocklist
    )
    assert out.columns == ["event_id", "source_ip", *ENRICHMENT_COLUMNS]
    types = {f.name: f.dataType.simpleString() for f in out.schema.fields}
    assert types["asn_number"] == "bigint" and types["reputation_score"] == "int"
    assert types["threat_categories"] == "array<string>" and types["geo_latitude"] == "double"
    plan = out._jdf.queryExecution().executedPlan().toString()
    assert plan.count("ArrowEvalPython") == 1


def test_unified_udf_values_nulls_and_row_preservation(spark, city_db, asn_db, blocklist):
    ips = ["8.8.8.8", "81.2.69.142", "10.0.0.1", "garbage", None] * 20
    rows = add_enrichment_columns(
        make_df(spark, ips), geoip_db_path=city_db, asn_db_path=asn_db, blocklist_path=blocklist
    ).collect()
    assert [r["source_ip"] for r in rows] == ips  # nothing dropped or reordered
    google, threat, private, bad, none = (r.asDict() for r in rows[:5])
    assert (google["geo_country"], google["asn_org"], google["is_known_threat"]) == ("US", "GOOGLE", False)
    assert threat["asn_number"] == 4_200_000_000 and threat["is_known_threat"] is True
    assert private["geo_is_private"] is True and private["asn_org"] is None
    for row in (bad, none):
        assert row["geo_country"] is None and row["is_known_threat"] is False
        assert row["threat_categories"] == [] and row["reputation_score"] is None


def test_the_composite_enricher_is_registered_as_a_sql_function(spark, city_db, asn_db, blocklist):
    register_enrichment_udf(
        spark, "enrich_ip_test", geoip_db_path=city_db, asn_db_path=asn_db, blocklist_path=blocklist
    )
    make_df(spark, ["8.8.8.8", "10.0.0.1"]).createOrReplaceTempView("events_for_sql")
    rows = spark.sql(
        "SELECT source_ip, enrich_ip_test(source_ip).geo_country AS country, "
        "enrich_ip_test(source_ip).asn_org AS org FROM events_for_sql ORDER BY source_ip"
    ).collect()
    assert [(r["source_ip"], r["country"], r["org"]) for r in rows] == [
        ("10.0.0.1", None, None), ("8.8.8.8", "US", "GOOGLE")]


def test_enrichment_frame_returns_nulls_instead_of_raising():
    ips = pd.Series(["8.8.8.8", None, "x"])
    for enricher in (None, type("Broken", (), {"enrich_many": lambda self, v: 1 / 0})()):
        frame = enrichment_frame(ips, enricher)
        assert len(frame) == 3 and list(frame.columns) == list(ENRICHMENT_COLUMNS)
        assert frame["geo_country"].isna().all() and not frame["is_known_threat"].any()
        assert str(frame["asn_number"].dtype) == "Int64"


def test_unified_udf_works_on_a_streaming_dataframe(spark, city_db, asn_db, blocklist, tmp_path):
    source = tmp_path / "events"
    source.mkdir()
    (source / "b.json").write_text('{"event_id":"a","source_ip":"8.8.8.8"}\n{"event_id":"b","source_ip":"10.0.0.1"}')
    stream = spark.readStream.schema("event_id string, source_ip string").json(str(source))
    enriched = add_enrichment_columns(stream, geoip_db_path=city_db, asn_db_path=asn_db, blocklist_path=blocklist)
    assert enriched.isStreaming
    seen = []
    query = (enriched.writeStream.foreachBatch(lambda d, _: seen.extend(d.collect()))
             .option("checkpointLocation", str(tmp_path / "ck")).trigger(availableNow=True).start())
    assert query.awaitTermination(120)
    rows = {r["event_id"]: r for r in seen}
    assert rows["a"]["asn_org"] == "GOOGLE" and rows["b"]["geo_is_private"] is True