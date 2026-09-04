"""Unit tests for consumers.log_consumer, with Kafka fully mocked."""

import json
import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest

# Make `consumers` importable when pytest is run from the project root,
# mirroring the approach used in tests/producers/test_log_producer.py.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from confluent_kafka import KafkaError, KafkaException  # noqa: E402

from consumers.log_consumer import (  # noqa: E402
    ConsumerConfig,
    LogConsumer,
    REQUIRED_LOG_FIELDS,
    SchemaValidationError,
    validate_log_schema,
)


VALID_RECORD = {
    "event_id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2026-09-04T10:00:00Z",
    "source_ip": "10.0.0.5",
    "event_type": "login_attempt",
    "severity": "low",
    "raw_message": "user logged in",
    "source": "auth",
}


def make_msg(value=None, error=None, offset=42, partition=0):
    """Build a MagicMock standing in for a confluent_kafka.Message."""
    msg = MagicMock()
    msg.value.return_value = value
    msg.error.return_value = error
    msg.offset.return_value = offset
    msg.partition.return_value = partition
    return msg


def make_kafka_error(code=KafkaError.UNKNOWN):
    err = MagicMock(spec=KafkaError)
    err.code.return_value = code
    err.__str__ = lambda self: "mock kafka error"
    return err


@pytest.fixture
def mock_consumer():
    return MagicMock()


@pytest.fixture
def config():
    return ConsumerConfig(bootstrap_servers="kafka:9092", topic="logs-raw", group_id="siem-consumers")


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

class TestConsumerConfig:
    def test_from_env_reads_bootstrap_and_defaults(self, monkeypatch):
        monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
        monkeypatch.delenv("KAFKA_LOGS_RAW_TOPIC", raising=False)
        monkeypatch.delenv("KAFKA_CONSUMER_GROUP_ID", raising=False)

        cfg = ConsumerConfig.from_env()

        assert cfg.bootstrap_servers == "kafka:9092"
        assert cfg.topic == "logs-raw"
        assert cfg.group_id == "siem-consumers"

    def test_from_env_reads_explicit_overrides(self, monkeypatch):
        monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
        monkeypatch.setenv("KAFKA_LOGS_RAW_TOPIC", "custom-topic")
        monkeypatch.setenv("KAFKA_CONSUMER_GROUP_ID", "custom-group")

        cfg = ConsumerConfig.from_env()

        assert cfg.topic == "custom-topic"
        assert cfg.group_id == "custom-group"

    def test_from_env_missing_bootstrap_raises(self, monkeypatch):
        monkeypatch.delenv("KAFKA_BOOTSTRAP_SERVERS", raising=False)

        with pytest.raises(RuntimeError):
            ConsumerConfig.from_env()

    def test_to_confluent_config_disables_autocommit(self, config):
        cc = config.to_confluent_config()

        assert cc["enable.auto.commit"] is False
        assert cc["bootstrap.servers"] == "kafka:9092"
        assert cc["group.id"] == "siem-consumers"

    def test_bootstrap_never_hardcoded_to_localhost(self, config):
        assert "localhost" not in config.to_confluent_config()["bootstrap.servers"]


# --------------------------------------------------------------------------- #
# Schema validation
# --------------------------------------------------------------------------- #

class TestSchemaValidation:
    def test_valid_record_passes(self):
        validate_log_schema(VALID_RECORD)  # should not raise

    def test_missing_field_raises(self):
        incomplete = dict(VALID_RECORD)
        del incomplete["source_ip"]

        with pytest.raises(SchemaValidationError):
            validate_log_schema(incomplete)

    def test_all_required_fields_checked(self):
        for field in REQUIRED_LOG_FIELDS:
            incomplete = dict(VALID_RECORD)
            del incomplete[field]
            with pytest.raises(SchemaValidationError):
                validate_log_schema(incomplete)


# --------------------------------------------------------------------------- #
# Subscription
# --------------------------------------------------------------------------- #

class TestSubscribe:
    def test_subscribe_calls_consumer_subscribe_with_topic(self, config, mock_consumer):
        lc = LogConsumer(config, consumer=mock_consumer)

        lc.subscribe()

        mock_consumer.subscribe.assert_called_once_with(["logs-raw"])

    def test_run_subscribes_if_not_already(self, config, mock_consumer):
        mock_consumer.poll.return_value = None
        lc = LogConsumer(config, consumer=mock_consumer)
        lc._running = False  # force loop to exit immediately after subscribe

        def stop_after_first_poll(*args, **kwargs):
            lc.stop()
            return None

        mock_consumer.poll.side_effect = stop_after_first_poll
        lc.run()

        mock_consumer.subscribe.assert_called_once_with(["logs-raw"])


# --------------------------------------------------------------------------- #
# poll_once: happy path
# --------------------------------------------------------------------------- #

class TestPollOnceHappyPath:
    def test_no_message_returns_none(self, config, mock_consumer):
        mock_consumer.poll.return_value = None
        lc = LogConsumer(config, consumer=mock_consumer)

        result = lc.poll_once()

        assert result is None
        mock_consumer.commit.assert_not_called()

    def test_valid_record_is_dispatched_and_committed(self, config, mock_consumer):
        msg = make_msg(value=json.dumps(VALID_RECORD).encode("utf-8"))
        mock_consumer.poll.return_value = msg
        handler = MagicMock()
        lc = LogConsumer(config, on_record=handler, consumer=mock_consumer)

        result = lc.poll_once()

        assert result == VALID_RECORD
        handler.assert_called_once_with(VALID_RECORD)
        mock_consumer.commit.assert_called_once_with(message=msg, asynchronous=False)

    def test_commit_happens_after_handler_is_called(self, config, mock_consumer):
        msg = make_msg(value=json.dumps(VALID_RECORD).encode("utf-8"))
        mock_consumer.poll.return_value = msg
        events = []
        handler = lambda record: events.append("handled")
        mock_consumer.commit.side_effect = lambda **kw: events.append("committed")
        lc = LogConsumer(config, on_record=handler, consumer=mock_consumer)

        lc.poll_once()

        assert events == ["handled", "committed"]

    def test_default_handler_used_when_none_provided(self, config, mock_consumer, caplog):
        msg = make_msg(value=json.dumps(VALID_RECORD).encode("utf-8"))
        mock_consumer.poll.return_value = msg
        lc = LogConsumer(config, consumer=mock_consumer)

        with caplog.at_level(logging.INFO):
            lc.poll_once()

        assert mock_consumer.commit.called

    def test_str_value_is_accepted_not_only_bytes(self, config, mock_consumer):
        msg = make_msg(value=json.dumps(VALID_RECORD))  # plain str, not bytes
        mock_consumer.poll.return_value = msg
        handler = MagicMock()
        lc = LogConsumer(config, on_record=handler, consumer=mock_consumer)

        lc.poll_once()

        handler.assert_called_once_with(VALID_RECORD)


# --------------------------------------------------------------------------- #
# poll_once: malformed / invalid input is skipped, not crashed on
# --------------------------------------------------------------------------- #

class TestPollOnceMalformedInput:
    def test_malformed_json_is_skipped_and_committed(self, config, mock_consumer, caplog):
        msg = make_msg(value=b"{not valid json")
        mock_consumer.poll.return_value = msg
        handler = MagicMock()
        lc = LogConsumer(config, on_record=handler, consumer=mock_consumer)

        with caplog.at_level(logging.WARNING):
            result = lc.poll_once()

        assert result is None
        handler.assert_not_called()
        mock_consumer.commit.assert_called_once_with(message=msg, asynchronous=False)
        assert "malformed" in caplog.text.lower()

    def test_blank_message_is_skipped_and_committed(self, config, mock_consumer):
        msg = make_msg(value=b"   ")
        mock_consumer.poll.return_value = msg
        handler = MagicMock()
        lc = LogConsumer(config, on_record=handler, consumer=mock_consumer)

        result = lc.poll_once()

        assert result is None
        handler.assert_not_called()
        mock_consumer.commit.assert_called_once_with(message=msg, asynchronous=False)

    def test_empty_value_none_is_skipped_and_committed(self, config, mock_consumer):
        msg = make_msg(value=None)
        mock_consumer.poll.return_value = msg
        handler = MagicMock()
        lc = LogConsumer(config, on_record=handler, consumer=mock_consumer)

        result = lc.poll_once()

        assert result is None
        handler.assert_not_called()
        mock_consumer.commit.assert_called_once_with(message=msg, asynchronous=False)

    def test_schema_invalid_record_is_skipped_and_committed(self, config, mock_consumer, caplog):
        incomplete = {"timestamp": "2026-09-04T10:00:00Z"}
        msg = make_msg(value=json.dumps(incomplete).encode("utf-8"))
        mock_consumer.poll.return_value = msg
        handler = MagicMock()
        lc = LogConsumer(config, on_record=handler, consumer=mock_consumer)

        with caplog.at_level(logging.WARNING):
            result = lc.poll_once()

        assert result is None
        handler.assert_not_called()
        mock_consumer.commit.assert_called_once_with(message=msg, asynchronous=False)
        assert "invalid schema" in caplog.text.lower()

    def test_malformed_message_does_not_raise(self, config, mock_consumer):
        msg = make_msg(value=b"garbage")
        mock_consumer.poll.return_value = msg
        lc = LogConsumer(config, consumer=mock_consumer)

        lc.poll_once()  # must not raise


# --------------------------------------------------------------------------- #
# Kafka-level errors
# --------------------------------------------------------------------------- #

class TestKafkaErrors:
    def test_partition_eof_is_ignored_not_raised(self, config, mock_consumer):
        err = make_kafka_error(code=KafkaError._PARTITION_EOF)
        msg = make_msg(error=err)
        mock_consumer.poll.return_value = msg
        lc = LogConsumer(config, consumer=mock_consumer)

        result = lc.poll_once()  # must not raise

        assert result is None
        mock_consumer.commit.assert_not_called()

    def test_other_kafka_error_raises(self, config, mock_consumer):
        err = make_kafka_error(code=KafkaError.UNKNOWN)
        msg = make_msg(error=err)
        mock_consumer.poll.return_value = msg
        lc = LogConsumer(config, consumer=mock_consumer)

        with pytest.raises(KafkaException):
            lc.poll_once()

    def test_commit_failure_propagates(self, config, mock_consumer):
        msg = make_msg(value=json.dumps(VALID_RECORD).encode("utf-8"))
        mock_consumer.poll.return_value = msg
        mock_consumer.commit.side_effect = KafkaException(make_kafka_error())
        lc = LogConsumer(config, consumer=mock_consumer)

        with pytest.raises(KafkaException):
            lc.poll_once()


# --------------------------------------------------------------------------- #
# Offset retention / restart behavior
# --------------------------------------------------------------------------- #

class TestOffsetRetention:
    def test_offset_only_committed_after_successful_processing(self, config, mock_consumer):
        """Manual commit means a crash before commit leaves the offset
        uncommitted, so a restart re-reads from the last committed offset —
        this test asserts the commit call always carries the message that
        was just handled, proving commits are per-message and synchronous."""
        msg1 = make_msg(value=json.dumps(VALID_RECORD).encode("utf-8"), offset=1)
        msg2 = make_msg(value=json.dumps(VALID_RECORD).encode("utf-8"), offset=2)
        mock_consumer.poll.side_effect = [msg1, msg2]
        lc = LogConsumer(config, consumer=mock_consumer)

        lc.poll_once()
        lc.poll_once()

        mock_consumer.commit.assert_has_calls(
            [
                call(message=msg1, asynchronous=False),
                call(message=msg2, asynchronous=False),
            ]
        )


# --------------------------------------------------------------------------- #
# Lifecycle: run / stop / close
# --------------------------------------------------------------------------- #

class TestLifecycle:
    def test_stop_ends_run_loop(self, config, mock_consumer):
        mock_consumer.poll.return_value = None
        lc = LogConsumer(config, consumer=mock_consumer)

        call_count = {"n": 0}

        def poll_side_effect(timeout):
            call_count["n"] += 1
            if call_count["n"] >= 3:
                lc.stop()
            return None

        mock_consumer.poll.side_effect = poll_side_effect
        lc.run()

        assert call_count["n"] == 3
        mock_consumer.close.assert_called_once()

    def test_close_closes_underlying_consumer(self, config, mock_consumer):
        lc = LogConsumer(config, consumer=mock_consumer)

        lc.close()

        mock_consumer.close.assert_called_once()

    def test_close_swallows_exceptions(self, config, mock_consumer):
        mock_consumer.close.side_effect = Exception("boom")
        lc = LogConsumer(config, consumer=mock_consumer)

        lc.close()  # must not raise