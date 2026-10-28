"""Tests for consumers/enriched_sink.py (the Kafka + storage fan-out)."""

import json
import logging
from unittest.mock import MagicMock

import pytest

pytest.importorskip("pyspark")

from pyspark.sql import functions as F

from consumers.enriched_events import DEFAULT_ENRICHED_TOPIC
from consumers.enriched_sink import (
    DEFAULT_PRODUCER_OPTIONS,
    EnrichedBatchError,
    KafkaEnrichedWriter,
    KafkaSinkConfig,
    make_enriched_batch_handler,
    summarize_batch,
)
from tests.enrichment.pipeline_helpers import enriched_df, now_iso, raw_login


class Capture:
    """Stands in for both sinks and records what each one received."""

    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []
        self.cached_during_call = []

    def __call__(self, df, batch_id=None):
        self.cached_during_call.append(df.is_cached)
        self.calls.append((df, batch_id))
        if self.fail:
            raise RuntimeError("sink down")


class KafkaCapture:
    topic = "logs-enriched"

    def __init__(self, fail=False):
        self.fail = fail
        self.payloads = []
        self.cached = []

    def write(self, payload_df):
        self.cached.append(payload_df.is_cached)
        if self.fail:
            raise RuntimeError("kafka down")
        self.payloads.extend(json.loads(r["value"]) for r in payload_df.collect())


@pytest.fixture
def batch(spark, city_db, asn_db, tmp_path):
    blocklist = tmp_path / "bad.txt"
    blocklist.write_text("8.8.8.8\n")
    values = [raw_login("8.8.8.8", timestamp=now_iso()), raw_login("10.0.0.1", timestamp=now_iso()),
              raw_login("81.2.69.142", timestamp=now_iso())]
    df, _ = enriched_df(spark, values, city_db=city_db, asn_db=asn_db, blocklist=blocklist)
    return df


def handler(storage, kafka, **kwargs):
    return make_enriched_batch_handler(storage, kafka, **kwargs)


# ---- happy path ------------------------------------------------------------------


def test_one_batch_goes_to_kafka_and_storage_exactly_once_each(batch):
    storage, kafka = Capture(), KafkaCapture()
    handler(storage, kafka)(batch, 7)

    assert len(storage.calls) == 1 and storage.calls[0][1] == 7
    assert len(kafka.payloads) == 3
    assert {p["source_ip"] for p in kafka.payloads} == {"8.8.8.8", "10.0.0.1", "81.2.69.142"}
    assert sorted(p["is_known_threat"] for p in kafka.payloads) == [False, False, True]


def test_the_batch_is_persisted_while_sinks_run_and_released_after(batch):
    storage, kafka = Capture(), KafkaCapture()
    handler(storage, kafka)(batch, 1)
    assert storage.cached_during_call == [True]
    assert batch.is_cached is False


def test_enrichment_runs_exactly_once_per_event_across_all_sinks(spark):
    """Both sinks and the summary read one cached batch: no re-enrichment
    (which would call AbuseIPDB again for every event)."""
    evaluations = spark.sparkContext.accumulator(0)

    def counted(value):
        evaluations.add(1)
        return value

    counting_udf = F.udf(counted, "string").asNondeterministic()
    df = spark.range(60).withColumn("event_id", F.col("id").cast("string"))
    df = df.withColumn("source_ip", counting_udf(F.lit("8.8.8.8")))

    storage = Capture()
    storage_reads = lambda d, b: d.collect()
    kafka = KafkaCapture()
    handler(lambda d, b: (storage_reads(d, b), storage(d, b)), kafka)(df, 1)

    assert evaluations.value == 60  # 3 reads of the batch, 1 evaluation


def test_empty_batches_touch_no_sink(spark):
    empty = spark.createDataFrame([], "event_id string, is_known_threat boolean")
    storage, kafka = Capture(), KafkaCapture()
    handler(storage, kafka)(empty, 3)
    assert storage.calls == [] and kafka.payloads == [] and kafka.cached == []


# ---- failure handling ------------------------------------------------------------


def test_a_kafka_failure_still_writes_storage_then_raises(batch):
    storage, kafka = Capture(), KafkaCapture(fail=True)
    with pytest.raises(EnrichedBatchError) as info:
        handler(storage, kafka)(batch, 4)
    assert len(storage.calls) == 1
    assert set(info.value.errors) == {"kafka"} and info.value.batch_id == 4
    assert batch.is_cached is False  # released even on failure


def test_a_storage_failure_still_writes_kafka_then_raises(batch):
    storage, kafka = Capture(fail=True), KafkaCapture()
    with pytest.raises(EnrichedBatchError) as info:
        handler(storage, kafka)(batch, 5)
    assert len(kafka.payloads) == 3
    assert set(info.value.errors) == {"storage"}


def test_both_sinks_failing_reports_both(batch):
    with pytest.raises(EnrichedBatchError) as info:
        handler(Capture(fail=True), KafkaCapture(fail=True))(batch, 6)
    assert set(info.value.errors) == {"kafka", "storage"}
    assert "sink down" in str(info.value) and "kafka down" in str(info.value)


# ---- observability ----------------------------------------------------------------


def test_summary_counts_events_threats_and_lag(batch):
    summary = summarize_batch(batch)
    assert summary.events == 3 and summary.threats == 1
    assert summary.max_lag_seconds is not None and 0 <= summary.avg_lag_seconds <= summary.max_lag_seconds


def test_summary_without_enrichment_columns_still_works(spark):
    summary = summarize_batch(spark.range(5))
    assert (summary.events, summary.threats) == (5, 0)
    assert summary.max_lag_seconds is None


def test_a_batch_slower_than_the_latency_target_is_flagged(spark, city_db, asn_db, tmp_path, caplog):
    old = raw_login("8.8.8.8", timestamp="2026-10-19T10:00:00Z")  # days old: huge lag
    df, _ = enriched_df(spark, [old], city_db=city_db, asn_db=asn_db, blocklist=tmp_path / "b.txt")
    with caplog.at_level(logging.WARNING, logger="consumers.enriched_sink"):
        handler(Capture(), KafkaCapture())(df, 9)
    assert "target 10 s" in caplog.text


def test_a_fresh_batch_meets_the_latency_target_without_warnings(batch, caplog):
    with caplog.at_level(logging.WARNING, logger="consumers.enriched_sink"):
        handler(Capture(), KafkaCapture())(batch, 2)
    assert "target" not in caplog.text
    assert summarize_batch(batch).max_lag_seconds < 10


# ---- the real Kafka writer (Spark's Kafka batch sink) -------------------------------


def test_default_writer_uses_the_spark_kafka_sink_with_durable_producer_options():
    payload = MagicMock()
    writer = payload.write.format.return_value
    writer.option.return_value = writer

    KafkaEnrichedWriter(KafkaSinkConfig("broker:9092", topic="logs-enriched")).write(payload)

    payload.write.format.assert_called_once_with("kafka")
    options = {call.args[0]: call.args[1] for call in writer.option.call_args_list}
    assert options["kafka.bootstrap.servers"] == "broker:9092"
    assert options["topic"] == "logs-enriched"
    assert options["kafka.acks"] == "all"
    assert options["kafka.enable.idempotence"] == "true"
    writer.save.assert_called_once_with()


def test_kafka_sink_config_defaults():
    config = KafkaSinkConfig("b:9092")
    assert config.topic == DEFAULT_ENRICHED_TOPIC == "logs-enriched"
    assert dict(config.producer_options) == DEFAULT_PRODUCER_OPTIONS
    assert KafkaEnrichedWriter(config).topic == "logs-enriched"


def test_a_custom_write_function_replaces_the_spark_sink():
    seen = []
    KafkaEnrichedWriter(KafkaSinkConfig("b:9092"), write_fn=seen.append).write("df")
    assert seen == ["df"]