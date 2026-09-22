import json
import os
import sys
from datetime import datetime
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

from consumers.normalizer import RAW_EVENT_SCHEMA
from consumers.spark_consumer import (
    DEFAULT_APP_NAME,
    DEFAULT_CHECKPOINT_DIR,
    DEFAULT_DEAD_LETTER_DIR,
    DEFAULT_MASTER,
    DEFAULT_STARTING_OFFSETS,
    DEFAULT_TRIGGER_INTERVAL,
    KAFKA_CONNECTOR_PACKAGE,
    SparkConsumerConfig,
    parse_normalize_and_validate,
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
        .config("spark.sql.session.timeZone", "UTC")
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


# --------------------------------------------------------------------------- #
# Raw producer events
#
# These match producers/log_generator.py output.
#
# IMPORTANT:
# These are intentionally NOT canonical LogEvent objects.
# Issue #11 exists to normalize these raw events before validation.
# --------------------------------------------------------------------------- #


def raw_ssh_failed_login(**overrides):
    event = {
        "schema_version": "1.0",
        "event_id": "evt-ssh-failed-1",
        "timestamp": "2026-09-22T10:00:00Z",
        "source_ip": "203.0.113.5",
        "event_type": "failed_login",
        "username": "admin",
        "service": "sshd",
        "outcome": "failure",
        "dest_port": 22,
        "raw_message": (
            "Failed password for admin from "
            "203.0.113.5 port 51234 ssh2"
        ),
    }

    event.update(overrides)
    return event


def raw_ssh_successful_login(**overrides):
    event = raw_ssh_failed_login(
        event_id="evt-ssh-success-1",
        event_type="successful_login",
        outcome="success",
        raw_message=(
            "Accepted password for admin from "
            "203.0.113.5 port 51234 ssh2"
        ),
    )

    event.update(overrides)
    return event


def raw_web_request(**overrides):
    event = {
        "schema_version": "1.0",
        "event_id": "evt-web-1",
        "timestamp": "2026-09-22T10:05:00Z",
        "source_ip": "198.51.100.23",
        "event_type": "web_access",
        "method": "GET",
        "path": "/login",
        "status_code": 200,
        "user_agent": "Mozilla/5.0",
        "bytes_sent": 512,
        "raw_message": (
            '198.51.100.23 - - '
            '[22/Sep/2026:10:05:00 +0000] '
            '"GET /login HTTP/1.1" 200 512 "-" '
            '"Mozilla/5.0"'
        ),
    }

    event.update(overrides)
    return event


def raw_firewall_drop(**overrides):
    event = {
        "schema_version": "1.0",
        "event_id": "evt-fw-1",
        "timestamp": "2026-09-22T10:10:00Z",
        "source_ip": "198.51.100.44",
        "event_type": "firewall_traffic",
        "dest_ip": "10.0.0.5",
        "dest_port": 22,
        "src_port": 51000,
        "protocol": "TCP",
        "action": "DROP",
        "raw_message": (
            "DROP IN=eth0 OUT= SRC=198.51.100.44 "
            "DST=10.0.0.5 PROTO=TCP SPT=51000 DPT=22"
        ),
    }

    event.update(overrides)
    return event


def raw_sudo_command(**overrides):
    event = {
        "schema_version": "1.0",
        "event_id": "evt-sudo-1",
        "timestamp": "2026-09-22T10:15:00Z",
        "source_ip": "203.0.113.9",
        "event_type": "sudo_command",
        "username": "alice",
        "service": "sudo",
        "outcome": "success",
        "raw_message": (
            "alice : TTY=pts/0 ; PWD=/home/alice ; "
            "USER=root ; COMMAND=/bin/bash"
        ),
    }

    event.update(overrides)
    return event


# --------------------------------------------------------------------------- #
# SparkConsumerConfig
# --------------------------------------------------------------------------- #


class TestSparkConsumerConfig:

    def test_from_env_requires_kafka_bootstrap_servers(
        self,
        monkeypatch,
    ):
        monkeypatch.delenv(
            "KAFKA_BOOTSTRAP_SERVERS",
            raising=False,
        )

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


# --------------------------------------------------------------------------- #
# Raw schema
#
# Issue #11 changes Spark parsing from the old canonical LOG_EVENT_SCHEMA
# to RAW_EVENT_SCHEMA because Kafka contains producer-shaped events.
# --------------------------------------------------------------------------- #


class TestRawEventSchema:

    def test_contains_universal_fields(self):
        fields = {
            field.name
            for field in RAW_EVENT_SCHEMA.fields
        }

        required = {
            "schema_version",
            "event_id",
            "timestamp",
            "source_ip",
            "event_type",
            "raw_message",
        }

        assert required.issubset(fields)

    def test_contains_ssh_auth_fields(self):
        fields = {
            field.name
            for field in RAW_EVENT_SCHEMA.fields
        }

        expected = {
            "username",
            "service",
            "outcome",
            "dest_port",
        }

        assert expected.issubset(fields)

    def test_contains_web_fields(self):
        fields = {
            field.name
            for field in RAW_EVENT_SCHEMA.fields
        }

        expected = {
            "method",
            "path",
            "status_code",
            "user_agent",
            "bytes_sent",
        }

        assert expected.issubset(fields)

    def test_contains_firewall_fields(self):
        fields = {
            field.name
            for field in RAW_EVENT_SCHEMA.fields
        }

        expected = {
            "dest_ip",
            "src_port",
            "protocol",
            "action",
        }

        assert expected.issubset(fields)


# --------------------------------------------------------------------------- #
# Spark parsing + Issue #11 normalization
# --------------------------------------------------------------------------- #


class TestParseAndValidate:

    def test_ssh_failed_login_is_normalized_and_valid(
        self,
        spark,
        kafka_schema,
    ):
        event = raw_ssh_failed_login()

        records = [
            (
                json.dumps(event),
                event["source_ip"],
                "logs-raw",
                0,
                100,
                datetime(2026, 9, 22, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        result = parse_normalize_and_validate(raw_df)

        row = result.select(
            "event_id",
            "source_ip",
            "event_type",
            "severity",
            "source",
            "username",
            "auth_method",
            "success",
            "_is_valid",
        ).first()

        assert row.event_id == "evt-ssh-failed-1"
        assert row.source_ip == "203.0.113.5"
        assert row.event_type == "failed_login"
        assert row.severity == "MEDIUM"
        assert row.source == "ssh"
        assert row.username == "admin"
        assert row.auth_method == "password"
        assert row.success is False
        assert row._is_valid is True

    def test_ssh_successful_login_is_normalized_and_valid(
        self,
        spark,
        kafka_schema,
    ):
        event = raw_ssh_successful_login()

        records = [
            (
                json.dumps(event),
                event["source_ip"],
                "logs-raw",
                0,
                101,
                datetime(2026, 9, 22, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_normalize_and_validate(raw_df).first()

        assert row.source == "ssh"
        assert row.event_type == "successful_login"
        assert row.severity == "INFO"
        assert row.success is True
        assert row._is_valid is True

    def test_web_access_is_normalized_to_web_request(
        self,
        spark,
        kafka_schema,
    ):
        event = raw_web_request()

        records = [
            (
                json.dumps(event),
                event["source_ip"],
                "logs-raw",
                0,
                102,
                datetime(2026, 9, 22, 10, 5, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_normalize_and_validate(raw_df).first()

        assert row.source == "web"
        assert row.event_type == "web_request"
        assert row.method == "GET"
        assert row.path == "/login"
        assert row.status_code == 200
        assert row.user_agent == "Mozilla/5.0"
        assert row.severity == "INFO"
        assert row._is_valid is True

    def test_firewall_drop_is_normalized(
        self,
        spark,
        kafka_schema,
    ):
        event = raw_firewall_drop()

        records = [
            (
                json.dumps(event),
                event["source_ip"],
                "logs-raw",
                0,
                103,
                datetime(2026, 9, 22, 10, 10, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_normalize_and_validate(raw_df).first()

        assert row.source == "firewall"
        assert row.event_type == "firewall_drop"
        assert row.action == "DROP"
        assert row.dest_ip == "10.0.0.5"
        assert row.dest_port == 22
        assert row.severity == "MEDIUM"
        assert row._is_valid is True

    def test_auth_event_is_normalized(
        self,
        spark,
        kafka_schema,
    ):
        event = raw_sudo_command()

        records = [
            (
                json.dumps(event),
                event["source_ip"],
                "logs-raw",
                0,
                104,
                datetime(2026, 9, 22, 10, 15, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_normalize_and_validate(raw_df).first()

        assert row.source == "auth"
        assert row.event_type == "sudo_attempt"
        assert row.auth_method == "sudo"
        assert row.success is True
        assert row.severity == "MEDIUM"
        assert row._is_valid is True

    def test_normalized_at_is_populated(
        self,
        spark,
        kafka_schema,
    ):
        event = raw_ssh_failed_login()

        records = [
            (
                json.dumps(event),
                event["source_ip"],
                "logs-raw",
                0,
                105,
                datetime(2026, 9, 22, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_normalize_and_validate(raw_df).select(
            "normalized_at"
        ).first()

        assert row.normalized_at is not None

    def test_event_timestamp_is_parsed(
        self,
        spark,
        kafka_schema,
    ):
        event = raw_ssh_failed_login()

        records = [
            (
                json.dumps(event),
                event["source_ip"],
                "logs-raw",
                0,
                106,
                datetime(2026, 9, 22, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_normalize_and_validate(raw_df).select(
            "event_timestamp"
        ).first()

        assert row.event_timestamp is not None

    def test_processing_lag_is_created(
        self,
        spark,
        kafka_schema,
    ):
        event = raw_ssh_failed_login()

        records = [
            (
                json.dumps(event),
                event["source_ip"],
                "logs-raw",
                0,
                107,
                datetime(2026, 9, 22, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_normalize_and_validate(raw_df).select(
            "processing_lag_seconds"
        ).first()

        assert row.processing_lag_seconds is not None


# --------------------------------------------------------------------------- #
# Invalid records
# --------------------------------------------------------------------------- #


class TestInvalidRecords:

    def test_unknown_event_type_is_invalid(
        self,
        spark,
        kafka_schema,
    ):
        event = raw_ssh_failed_login(
            event_type="totally_unknown_event",
        )

        records = [
            (
                json.dumps(event),
                event["source_ip"],
                "logs-raw",
                0,
                200,
                datetime(2026, 9, 22, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_normalize_and_validate(raw_df).first()

        assert row.source is None
        assert row.event_type is None
        assert row.severity is None
        assert row._is_valid is False

    def test_missing_event_id_is_invalid(
        self,
        spark,
        kafka_schema,
    ):
        event = raw_ssh_failed_login(
            event_id=None,
        )

        records = [
            (
                json.dumps(event),
                event["source_ip"],
                "logs-raw",
                0,
                201,
                datetime(2026, 9, 22, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_normalize_and_validate(raw_df).select(
            "_is_valid"
        ).first()

        assert row._is_valid is False

    def test_missing_source_ip_is_invalid(
        self,
        spark,
        kafka_schema,
    ):
        event = raw_ssh_failed_login(
            source_ip=None,
        )

        records = [
            (
                json.dumps(event),
                None,
                "logs-raw",
                0,
                202,
                datetime(2026, 9, 22, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_normalize_and_validate(raw_df).select(
            "_is_valid"
        ).first()

        assert row._is_valid is False

    def test_blank_source_ip_is_invalid(
        self,
        spark,
        kafka_schema,
    ):
        event = raw_ssh_failed_login(
            source_ip="   ",
        )

        records = [
            (
                json.dumps(event),
                "   ",
                "logs-raw",
                0,
                203,
                datetime(2026, 9, 22, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_normalize_and_validate(raw_df).select(
            "_is_valid"
        ).first()

        assert row._is_valid is False

    def test_invalid_timestamp_is_invalid(
        self,
        spark,
        kafka_schema,
    ):
        event = raw_ssh_failed_login(
            timestamp="not-a-timestamp",
        )

        records = [
            (
                json.dumps(event),
                event["source_ip"],
                "logs-raw",
                0,
                204,
                datetime(2026, 9, 22, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_normalize_and_validate(raw_df).select(
            "event_timestamp",
            "_is_valid",
        ).first()

        assert row.event_timestamp is None
        assert row._is_valid is False

    def test_unknown_firewall_action_is_invalid(
        self,
        spark,
        kafka_schema,
    ):
        event = raw_firewall_drop(
            action="UNKNOWN",
        )

        records = [
            (
                json.dumps(event),
                event["source_ip"],
                "logs-raw",
                0,
                205,
                datetime(2026, 9, 22, 10, 10, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_normalize_and_validate(raw_df).first()

        assert row.event_type is None
        assert row.severity is None
        assert row._is_valid is False

    def test_missing_firewall_action_is_invalid(
        self,
        spark,
        kafka_schema,
    ):
        event = raw_firewall_drop(
            action=None,
        )

        records = [
            (
                json.dumps(event),
                event["source_ip"],
                "logs-raw",
                0,
                206,
                datetime(2026, 9, 22, 10, 10, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_normalize_and_validate(raw_df).first()

        assert row.event_type is None
        assert row.severity is None
        assert row._is_valid is False


# --------------------------------------------------------------------------- #
# Malformed JSON
# --------------------------------------------------------------------------- #


class TestMalformedJson:

    def test_invalid_json_is_invalid(
        self,
        spark,
        kafka_schema,
    ):
        records = [
            (
                "{this is not valid json}",
                None,
                "logs-raw",
                0,
                300,
                datetime(2026, 9, 22, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_normalize_and_validate(raw_df).select(
            "_is_valid"
        ).first()

        assert row._is_valid is False


# --------------------------------------------------------------------------- #
# Kafka metadata
# --------------------------------------------------------------------------- #


class TestKafkaMetadata:

    def test_kafka_metadata_is_preserved(
        self,
        spark,
        kafka_schema,
    ):
        event = raw_ssh_failed_login()

        records = [
            (
                json.dumps(event),
                "source-key",
                "logs-raw",
                3,
                999,
                datetime(2026, 9, 22, 10, 0, 0),
            )
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        row = parse_normalize_and_validate(raw_df).select(
            "kafka_key",
            "kafka_topic",
            "kafka_partition",
            "kafka_offset",
        ).first()

        assert row.kafka_key == "source-key"
        assert row.kafka_topic == "logs-raw"
        assert row.kafka_partition == 3
        assert row.kafka_offset == 999


# --------------------------------------------------------------------------- #
# Mixed batch
#
# Verifies that different raw source types can be normalized in the same
# Spark DataFrame.
# --------------------------------------------------------------------------- #


class TestMixedBatch:

    def test_multiple_raw_sources_normalize_in_one_batch(
        self,
        spark,
        kafka_schema,
    ):
        events = [
            raw_ssh_failed_login(
                event_id="ssh-1",
            ),
            raw_web_request(
                event_id="web-1",
            ),
            raw_firewall_drop(
                event_id="fw-1",
            ),
            raw_sudo_command(
                event_id="auth-1",
            ),
        ]

        records = [
            (
                json.dumps(event),
                event["source_ip"],
                "logs-raw",
                0,
                index,
                datetime(2026, 9, 22, 10, 0, 0),
            )
            for index, event in enumerate(events)
        ]

        raw_df = make_kafka_df(
            spark,
            kafka_schema,
            records,
        )

        result = parse_normalize_and_validate(raw_df)

        rows = {
            row.event_id: row
            for row in result.collect()
        }

        assert len(rows) == 4

        assert rows["ssh-1"].source == "ssh"
        assert rows["ssh-1"].event_type == "failed_login"

        assert rows["web-1"].source == "web"
        assert rows["web-1"].event_type == "web_request"

        assert rows["fw-1"].source == "firewall"
        assert rows["fw-1"].event_type == "firewall_drop"

        assert rows["auth-1"].source == "auth"
        assert rows["auth-1"].event_type == "sudo_attempt"

        assert all(row._is_valid for row in rows.values())


# --------------------------------------------------------------------------- #
# Spark constants
# --------------------------------------------------------------------------- #


class TestSparkConstants:

    def test_kafka_connector_package_matches_spark_version(self):
        assert KAFKA_CONNECTOR_PACKAGE == (
            "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.1"
        )


# --------------------------------------------------------------------------- #
# Dead-letter writer
# --------------------------------------------------------------------------- #


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

        output_dir = str(tmp_path / "dead_letter")

        records = [
            (
                "invalid-json",
                "source-key",
                "logs-raw",
                0,
                200,
                datetime(2026, 9, 22, 10, 0, 0),
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