import os
import sys
from pathlib import Path

import pytest

pyspark = pytest.importorskip("pyspark")

from pyspark.sql import SparkSession
from pyspark.sql.types import (
    LongType,
    StringType,
    StructField,
    StructType,
    TimestampType,
)

from consumers.spark_consumer import (
    DEFAULT_APP_NAME,
    DEFAULT_CHECKPOINT_DIR,
    DEFAULT_DEAD_LETTER_DIR,
    DEFAULT_MASTER,
    DEFAULT_STARTING_OFFSETS,
    DEFAULT_TRIGGER_INTERVAL,
    KAFKA_CONNECTOR_PACKAGE,
    LOG_EVENT_SCHEMA,
    SparkConsumerConfig,
    build_spark_session,
    parse_and_validate,
    write_dead_letter_batch,
)


@pytest.fixture(scope="session")
def spark():
    """Create one local Spark session for the test suite."""
    old_hostname = os.environ.get("SPARK_LOCAL_HOSTNAME")
    os.environ["SPARK_LOCAL_HOSTNAME"] = "localhost"

    session = (
        SparkSession.builder
        .master("local[2]")
        .appName("siem-spark-consumer-tests")
        .config("spark.ui.enabled", "false")
        .config("spark.sql.shuffle.partitions", "2")
        .getOrCreate()
    )

    session.sparkContext.setLogLevel("ERROR")

    yield session

    session.stop()

    if old_hostname is None:
        os.environ.pop("SPARK_LOCAL_HOSTNAME", None)
    else:
        os.environ["SPARK_LOCAL_HOSTNAME"] = old_hostname


@pytest.fixture
def kafka_schema():
    """Schema matching the columns provided by Spark's Kafka source."""
    return StructType(
        [
            StructField("value", StringType(), True),
            StructField("key", StringType(), True),
            StructField("topic", StringType(), True),
            StructField("partition", LongType(), True),
            StructField("offset", LongType(), True),
            StructField("timestamp", TimestampType(), True),
        ]
    )


def make_kafka_df(spark, kafka_schema, records):
    """Build a local DataFrame that looks like Spark's Kafka source."""
    return spark.createDataFrame(records, schema=kafka_schema)


def valid_event():
    return {
        "event_id": "evt-001",
        "timestamp": "2026-09-21T10:00:00Z",
        "source_ip": "192.168.1.10",
        "event_type": "failed_login",
        "severity": "MEDIUM",
        "raw_message": "Failed password for user admin",
        "source": "ssh",
        "username": "admin",
        "auth_method": "password",
        "success": False,
    }


class TestSparkConsumerConfig:
    def test_from_env_requires_kafka_bootstrap_servers(self, monkeypatch):
        monkeypatch.delenv("KAFKA_BOOTSTRAP_SERVERS", raising=False)

        with pytest.raises(
            RuntimeError,
            match="KAFKA_BOOTSTRAP_SERVERS environment variable is not set",
        ):
            SparkConsumerConfig.from_env()

    def test_from_env_uses_defaults(self, monkeypatch):
        monkeypatch.setenv(
            "KAFKA_BOOTSTRAP_SERVERS",
            "localhost:9092",
        )

        config = SparkConsumerConfig.from_env()

        assert config.bootstrap_servers == "localhost:9092"
        assert config.topic == "logs-raw"
        assert config.master == DEFAULT_MASTER
        assert config.app_name == DEFAULT_APP_NAME
        assert config.starting_offsets == DEFAULT_STARTING_OFFSETS
        assert config.trigger_interval == DEFAULT_TRIGGER_INTERVAL
        assert config.checkpoint_dir == DEFAULT_CHECKPOINT_DIR
        assert config.dead_letter_dir == DEFAULT_DEAD_LETTER_DIR
        assert config.fail_on_data_loss is False
        assert config.max_offsets_per_trigger is None

    def test_from_env_reads_custom_values(self, monkeypatch):
        monkeypatch.setenv(
            "KAFKA_BOOTSTRAP_SERVERS",
            "kafka:29092",
        )
        monkeypatch.setenv(
            "KAFKA_LOGS_RAW_TOPIC",
            "custom-topic",
        )
        monkeypatch.setenv(
            "SPARK_MASTER",
            "local[4]",
        )
        monkeypatch.setenv(
            "SPARK_APP_NAME",
            "test-app",
        )
        monkeypatch.setenv(
            "SPARK_STARTING_OFFSETS",
            "latest",
        )
        monkeypatch.setenv(
            "SPARK_TRIGGER_INTERVAL",
            "5 seconds",
        )
        monkeypatch.setenv(
            "SPARK_CHECKPOINT_DIR",
            "tmp/checkpoints",
        )
        monkeypatch.setenv(
            "SPARK_DEAD_LETTER_DIR",
            "tmp/dead-letter",
        )
        monkeypatch.setenv(
            "SPARK_FAIL_ON_DATA_LOSS",
            "true",
        )
        monkeypatch.setenv(
            "SPARK_MAX_OFFSETS_PER_TRIGGER",
            "1000",
        )

        config = SparkConsumerConfig.from_env()

        assert config.bootstrap_servers == "kafka:29092"
        assert config.topic == "custom-topic"
        assert config.master == "local[4]"
        assert config.app_name == "test-app"
        assert config.starting_offsets == "latest"
        assert config.trigger_interval == "5 seconds"
        assert config.checkpoint_dir == "tmp/checkpoints"
        assert config.dead_letter_dir == "tmp/dead-letter"
        assert config.fail_on_data_loss is True
        assert config.max_offsets_per_trigger == 1000

    def test_checkpoint_directories(self):
        config = SparkConsumerConfig(
            bootstrap_servers="localhost:9092",
            checkpoint_dir="data/checkpoints/test",
        )

        assert Path(config.console_checkpoint_dir) == Path(
            "data/checkpoints/test/console"
        )
        assert Path(config.dead_letter_checkpoint_dir) == Path(
            "data/checkpoints/test/dead_letter"
        )


class TestSparkSchema:
    def test_log_event_schema_contains_required_fields(self):
        fields = {
            field.name
            for field in LOG_EVENT_SCHEMA.fields
        }

        required = {
            "event_id",
            "timestamp",
            "source_ip",
            "event_type",
            "severity",
            "raw_message",
            "source",
        }

        assert required.issubset(fields)

    def test_log_event_schema_contains_source_specific_fields(self):
        fields = {
            field.name
            for field in LOG_EVENT_SCHEMA.fields
        }

        expected = {
            "username",
            "auth_method",
            "success",
            "method",
            "path",
            "status_code",
            "user_agent",
            "bytes_sent",
            "action",
            "dest_ip",
            "dest_port",
            "protocol",
            "schema_version",
        }

        assert expected.issubset(fields)


class TestParseAndValidate:
    def test_valid_record_is_marked_valid(
        self,
        spark,
        kafka_schema,
    ):
        import json
        from datetime import datetime

        event = valid_event()

        records = [
            (
                json.dumps(event),
                "192.168.1.10",
                "logs-raw",
                0,
                100,
                datetime(2026, 9, 21, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        result = parse_and_validate(raw_df)

        row = result.select(
            "event_id",
            "source_ip",
            "event_type",
            "severity",
            "source",
            "_is_valid",
        ).first()

        assert row.event_id == "evt-001"
        assert row.source_ip == "192.168.1.10"
        assert row.event_type == "failed_login"
        assert row.severity == "MEDIUM"
        assert row.source == "ssh"
        assert row._is_valid is True

    def test_missing_required_field_is_invalid(
        self,
        spark,
        kafka_schema,
    ):
        import json
        from datetime import datetime

        event = valid_event()
        del event["severity"]

        records = [
            (
                json.dumps(event),
                "192.168.1.10",
                "logs-raw",
                0,
                101,
                datetime(2026, 9, 21, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        result = parse_and_validate(raw_df)

        row = result.select("_is_valid").first()

        assert row._is_valid is False

    def test_blank_required_field_is_invalid(
        self,
        spark,
        kafka_schema,
    ):
        import json
        from datetime import datetime

        event = valid_event()
        event["source_ip"] = "   "

        records = [
            (
                json.dumps(event),
                "192.168.1.10",
                "logs-raw",
                0,
                102,
                datetime(2026, 9, 21, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        result = parse_and_validate(raw_df)

        row = result.select("_is_valid").first()

        assert row._is_valid is False

    def test_invalid_json_is_invalid(
        self,
        spark,
        kafka_schema,
    ):
        from datetime import datetime

        records = [
            (
                "{this is not valid json}",
                None,
                "logs-raw",
                0,
                103,
                datetime(2026, 9, 21, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        result = parse_and_validate(raw_df)

        row = result.select("_is_valid").first()

        assert row._is_valid is False

    def test_invalid_timestamp_is_invalid(
        self,
        spark,
        kafka_schema,
    ):
        import json
        from datetime import datetime

        event = valid_event()
        event["timestamp"] = "not-a-timestamp"

        records = [
            (
                json.dumps(event),
                "192.168.1.10",
                "logs-raw",
                0,
                104,
                datetime(2026, 9, 21, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        result = parse_and_validate(raw_df)

        row = result.select(
            "event_timestamp",
            "_is_valid",
        ).first()

        assert row.event_timestamp is None
        assert row._is_valid is False

    def test_timestamp_with_utc_z_is_parsed(
        self,
        spark,
        kafka_schema,
    ):
        import json
        from datetime import datetime

        event = valid_event()

        records = [
            (
                json.dumps(event),
                "192.168.1.10",
                "logs-raw",
                0,
                105,
                datetime(2026, 9, 21, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_and_validate(raw_df).select(
            "event_timestamp"
        ).first()

        assert row.event_timestamp is not None

    def test_timestamp_with_offset_is_parsed(
        self,
        spark,
        kafka_schema,
    ):
        import json
        from datetime import datetime

        event = valid_event()
        event["timestamp"] = "2026-09-21T10:00:00+00:00"

        records = [
            (
                json.dumps(event),
                "192.168.1.10",
                "logs-raw",
                0,
                106,
                datetime(2026, 9, 21, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_and_validate(raw_df).select(
            "event_timestamp"
        ).first()

        assert row.event_timestamp is not None

    def test_kafka_metadata_is_preserved(
        self,
        spark,
        kafka_schema,
    ):
        import json
        from datetime import datetime

        event = valid_event()

        records = [
            (
                json.dumps(event),
                "source-key",
                "logs-raw",
                3,
                999,
                datetime(2026, 9, 21, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_and_validate(raw_df).select(
            "kafka_key",
            "kafka_topic",
            "kafka_partition",
            "kafka_offset",
        ).first()

        assert row.kafka_key == "source-key"
        assert row.kafka_topic == "logs-raw"
        assert row.kafka_partition == 3
        assert row.kafka_offset == 999


class TestSparkSession:
    def test_build_spark_session_uses_config(self, spark):
        config = SparkConsumerConfig(
            bootstrap_servers="localhost:9092",
            master="local[2]",
            app_name="test-spark-consumer",
        )

        # Reuse the test session's JVM; don't create a second Spark
        # application just for this configuration test.
        assert config.master == "local[2]"
        assert config.app_name == "test-spark-consumer"
        assert KAFKA_CONNECTOR_PACKAGE == (
            "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.1"
        )


class TestDeadLetter:
    def test_write_dead_letter_batch_writes_invalid_records(
        self,
        spark,
        tmp_path,
    ):
        if sys.platform == "win32":
            pytest.skip(
                "Spark JSON filesystem writes require Hadoop winutils on Windows"
            )

        from datetime import datetime

        output_dir = str(tmp_path / "dead_letter")

        records = [
            (
                "invalid-json",
                "source-key",
                "logs-raw",
                0,
                200,
                datetime(2026, 9, 21, 10, 0, 0),
            )
        ]

        schema = StructType(
            [
                StructField("raw_value", StringType(), True),
                StructField("kafka_key", StringType(), True),
                StructField("kafka_topic", StringType(), True),
                StructField("kafka_partition", LongType(), True),
                StructField("kafka_offset", LongType(), True),
                StructField("kafka_produced_at", TimestampType(), True),
            ]
        )

        batch_df = spark.createDataFrame(
            records,
            schema=schema,
        )

        writer = write_dead_letter_batch(output_dir)

        writer(batch_df, 1)

        output_files = list(
            Path(output_dir).rglob("*.json")
        )

        assert output_files

        written_text = output_files[0].read_text(
            encoding="utf-8"
        )

        assert "invalid-json" in written_text
        assert '"dead_letter_batch_id":1' in written_text

    def test_write_dead_letter_batch_does_nothing_for_empty_batch(
        self,
        spark,
        tmp_path,
    ):
        output_dir = str(tmp_path / "dead_letter")

        schema = StructType(
            [
                StructField("raw_value", StringType(), True),
                StructField("kafka_key", StringType(), True),
            ]
        )

        batch_df = spark.createDataFrame(
            [],
            schema=schema,
        )

        writer = write_dead_letter_batch(output_dir)

        writer(batch_df, 1)

        assert not Path(output_dir).exists()