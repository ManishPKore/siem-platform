import io
import json
import sys
from unittest.mock import MagicMock, patch

import pytest
from confluent_kafka import KafkaException

sys.path.insert(0, "producers")

from producers.log_producer import LogProducer, DEFAULT_TOPIC  # noqa: E402


SAMPLE_EVENT = {
    "source_ip": "10.0.0.5",
    "event_type": "login_attempt",
    "timestamp": "2026-09-03T10:00:00Z",
}


@pytest.fixture
def mock_producer_cls():
    """Patches confluent_kafka.Producer so no real broker connection is made."""
    with patch("producers.log_producer.Producer") as mock_cls:
        instance = MagicMock()
        instance.list_topics.return_value = MagicMock()
        instance.flush.return_value = 0
        mock_cls.return_value = instance
        yield mock_cls, instance


@pytest.fixture
def env_bootstrap(monkeypatch):
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")


class TestInitialization:
    def test_reads_bootstrap_servers_from_env(
        self, mock_producer_cls, env_bootstrap
    ):
        mock_cls, instance = mock_producer_cls

        lp = LogProducer()

        assert lp.bootstrap_servers == "localhost:9092"
        mock_cls.assert_called_once()

        config = mock_cls.call_args[0][0]
        assert config["bootstrap.servers"] == "localhost:9092"

    def test_explicit_bootstrap_servers_overrides_env(
        self, mock_producer_cls, monkeypatch
    ):
        monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "envhost:9092")

        lp = LogProducer(bootstrap_servers="explicit:9092")

        assert lp.bootstrap_servers == "explicit:9092"

    def test_missing_bootstrap_servers_raises(self, monkeypatch):
        monkeypatch.delenv("KAFKA_BOOTSTRAP_SERVERS", raising=False)

        with pytest.raises(RuntimeError):
            LogProducer()

    def test_default_topic(self, mock_producer_cls, env_bootstrap):
        lp = LogProducer()

        assert lp.topic == DEFAULT_TOPIC


class TestConnectionRetry:
    def test_retries_on_connect_failure_then_succeeds(self, env_bootstrap):
        instance = MagicMock()

        instance.list_topics.side_effect = [
            KafkaException("no broker"),
            KafkaException("no broker"),
            MagicMock(),
        ]

        with patch(
            "producers.log_producer.Producer",
            return_value=instance,
        ), patch(
            "producers.log_producer.time.sleep"
        ) as mock_sleep:
            lp = LogProducer(
                max_connect_retries=3,
                base_backoff_seconds=0.01,
            )

            assert instance.list_topics.call_count == 3
            assert mock_sleep.call_count == 2

    def test_raises_after_exhausting_retries(self, env_bootstrap):
        instance = MagicMock()
        instance.list_topics.side_effect = KafkaException("still down")

        with patch(
            "producers.log_producer.Producer",
            return_value=instance,
        ), patch(
            "producers.log_producer.time.sleep"
        ):
            with pytest.raises(ConnectionError):
                LogProducer(
                    max_connect_retries=3,
                    base_backoff_seconds=0.01,
                )

            assert instance.list_topics.call_count == 3

    def test_exponential_backoff_values(self, env_bootstrap):
        instance = MagicMock()
        instance.list_topics.side_effect = KafkaException("down")

        sleeps = []

        with patch(
            "producers.log_producer.Producer",
            return_value=instance,
        ), patch(
            "producers.log_producer.time.sleep",
            side_effect=sleeps.append,
        ), patch(
            "producers.log_producer.random.uniform",
            return_value=0,
        ):
            with pytest.raises(ConnectionError):
                LogProducer(
                    max_connect_retries=3,
                    base_backoff_seconds=1.0,
                )

        assert sleeps == [1.0, 2.0]


class TestPublish:
    def test_publish_serializes_event_to_json(
        self, mock_producer_cls, env_bootstrap
    ):
        _, instance = mock_producer_cls
        lp = LogProducer()

        lp.publish(SAMPLE_EVENT)

        instance.produce.assert_called_once()

        kwargs = instance.produce.call_args.kwargs

        assert kwargs["topic"] == DEFAULT_TOPIC
        assert json.loads(kwargs["value"].decode("utf-8")) == SAMPLE_EVENT

    def test_publish_uses_source_ip_as_key(
        self, mock_producer_cls, env_bootstrap
    ):
        _, instance = mock_producer_cls
        lp = LogProducer()

        lp.publish(SAMPLE_EVENT)

        kwargs = instance.produce.call_args.kwargs

        assert kwargs["key"] == b"10.0.0.5"

    def test_publish_without_source_ip_uses_none_key(
        self, mock_producer_cls, env_bootstrap
    ):
        _, instance = mock_producer_cls
        lp = LogProducer()

        lp.publish({"event_type": "no_ip"})

        kwargs = instance.produce.call_args.kwargs

        assert kwargs["key"] is None

    def test_publish_polls_after_produce(
        self, mock_producer_cls, env_bootstrap
    ):
        _, instance = mock_producer_cls
        lp = LogProducer()

        lp.publish(SAMPLE_EVENT)

        instance.poll.assert_called_with(0)

    def test_publish_handles_buffer_error_by_retrying(
        self, mock_producer_cls, env_bootstrap
    ):
        _, instance = mock_producer_cls
        lp = LogProducer()

        instance.produce.side_effect = [
            BufferError("queue full"),
            None,
        ]

        lp.publish(SAMPLE_EVENT)

        assert instance.produce.call_count == 2
        instance.poll.assert_any_call(1)


class TestDeliveryCallback:
    def test_delivery_failure_is_logged_to_stderr(
        self, mock_producer_cls, env_bootstrap, caplog
    ):
        _, instance = mock_producer_cls
        lp = LogProducer()

        fake_msg = MagicMock()
        fake_msg.key.return_value = b"10.0.0.5"
        fake_msg.topic.return_value = DEFAULT_TOPIC

        with caplog.at_level("ERROR"):
            lp._delivery_callback(
                err="broker not available",
                msg=fake_msg,
            )

        assert lp._failed_count == 1
        assert any(
            "Delivery failed" in record.message
            for record in caplog.records
        )

    def test_delivery_success_increments_sent_count(
        self, mock_producer_cls, env_bootstrap
    ):
        _, instance = mock_producer_cls
        lp = LogProducer()

        fake_msg = MagicMock()
        fake_msg.topic.return_value = DEFAULT_TOPIC
        fake_msg.partition.return_value = 0
        fake_msg.offset.return_value = 42

        lp._delivery_callback(err=None, msg=fake_msg)

        assert lp._sent_count == 1
        assert lp._failed_count == 0


class TestRunFromStdin:
    def test_run_publishes_each_line_from_stream(
        self, mock_producer_cls, env_bootstrap
    ):
        _, instance = mock_producer_cls
        lp = LogProducer()

        lines = [
            json.dumps(SAMPLE_EVENT) + "\n",
            json.dumps(SAMPLE_EVENT) + "\n",
        ]

        fake_stdin = io.StringIO("".join(lines))

        with patch("producers.log_producer.signal.signal"):
            lp.run(input_stream=fake_stdin)

        assert instance.produce.call_count == 2
        instance.flush.assert_called_once()

    def test_run_skips_malformed_json_lines(
        self, mock_producer_cls, env_bootstrap
    ):
        _, instance = mock_producer_cls
        lp = LogProducer()

        fake_stdin = io.StringIO(
            "not json\n" + json.dumps(SAMPLE_EVENT) + "\n"
        )

        with patch("producers.log_producer.signal.signal"):
            lp.run(input_stream=fake_stdin)

        assert instance.produce.call_count == 1

    def test_run_skips_blank_lines(
        self, mock_producer_cls, env_bootstrap
    ):
        _, instance = mock_producer_cls
        lp = LogProducer()

        fake_stdin = io.StringIO(
            "\n\n" + json.dumps(SAMPLE_EVENT) + "\n"
        )

        with patch("producers.log_producer.signal.signal"):
            lp.run(input_stream=fake_stdin)

        assert instance.produce.call_count == 1


class TestShutdown:
    def test_shutdown_flushes_producer(
        self, mock_producer_cls, env_bootstrap
    ):
        _, instance = mock_producer_cls
        instance.flush.return_value = 0

        lp = LogProducer()
        lp.shutdown()

        instance.flush.assert_called_once_with(timeout=10)

    def test_shutdown_warns_if_messages_remain(
        self, mock_producer_cls, env_bootstrap, caplog
    ):
        _, instance = mock_producer_cls
        instance.flush.return_value = 3

        lp = LogProducer()

        with caplog.at_level("WARNING"):
            lp.shutdown()

        assert any(
            "still in queue" in record.message
            for record in caplog.records
        )