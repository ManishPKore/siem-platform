"""
Tests for the BruteForceRule detection rule.

Covers Issue #12:

- More than 5 failed_login events from one source IP in a 5-minute window
  triggers an alert.
- 4 failed_login events do not trigger an alert.
- Events spread across more than one 5-minute window do not trigger an alert.
- Exactly the configured threshold does not trigger an alert.
- Only failed_login events are counted.
- Different source IPs are evaluated independently.
- Alert persistence is requested with the correct fields.
- Alert publication contains the expected alert information.
- Duplicate processing does not create or publish duplicate alerts.
- Threshold and window configuration come from the rules repository.
- Severity boundaries follow severity_for_count().
"""

import uuid
from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest

pyspark = pytest.importorskip("pyspark")

from pyspark.sql import Row, SparkSession

from detection_engine.rules.base import RuleConfig
from detection_engine.rules.brute_force import BruteForceRule
from detection_engine.rules.severity import severity_for_count


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def spark():
    """Create one local Spark session for the test suite."""
    session = (
        SparkSession.builder
        .master("local[2]")
        .appName("test_brute_force")
        .config("spark.sql.shuffle.partitions", "1")
        .getOrCreate()
    )

    yield session

    session.stop()


@pytest.fixture
def base_config():
    """Default brute-force rule configuration."""
    return RuleConfig(
        rule_name="brute_force",
        threshold=5,
        window_minutes=5,
        slide_minutes=1,
        enabled=True,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_events_df(spark, rows):
    """
    Create a Spark DataFrame containing normalized security events.

    Each row is:

        (event_id, source_ip, event_type, event_timestamp)
    """
    data = [
        Row(
            event_id=event_id,
            source_ip=source_ip,
            event_type=event_type,
            event_timestamp=timestamp,
        )
        for event_id, source_ip, event_type, timestamp in rows
    ]

    return spark.createDataFrame(data)


def events_at_minute_offsets(
    source_ip,
    event_type,
    offsets_minutes,
    base=None,
):
    """Create events at the requested minute offsets."""
    base = base or datetime(2026, 1, 1, 12, 0, 0)

    return [
        (
            str(uuid.uuid5(uuid.NAMESPACE_DNS, f"test-event-{index}")),
            source_ip,
            event_type,
            base + timedelta(minutes=offset),
        )
        for index, offset in enumerate(offsets_minutes)
    ]


def build_rule(
    alerts_repository=None,
    alert_publisher=None,
    rules_repository=None,
):
    """Create a BruteForceRule with injectable dependencies."""
    return BruteForceRule(
        rules_repository=rules_repository,
        alerts_repository=alerts_repository,
        alert_publisher=alert_publisher,
    )


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------


class TestDetectBoundaryConditions:

    def test_six_events_in_five_minutes_triggers_alert(
        self,
        spark,
        base_config,
    ):
        rows = events_at_minute_offsets(
            "192.168.1.10",
            "failed_login",
            [0, 1, 2, 3, 4, 4.5],
        )

        events_df = make_events_df(spark, rows)

        rule = build_rule()

        alerts = rule.detect(events_df, base_config).collect()

        assert len(alerts) == 1
        assert alerts[0]["source_ip"] == "192.168.1.10"
        assert alerts[0]["event_count"] == 6

    def test_four_events_do_not_trigger_alert(
        self,
        spark,
        base_config,
    ):
        rows = events_at_minute_offsets(
            "192.168.1.10",
            "failed_login",
            [0, 1, 2, 3],
        )

        events_df = make_events_df(spark, rows)

        rule = build_rule()

        alerts = rule.detect(events_df, base_config).collect()

        assert alerts == []

    def test_six_events_spread_over_ten_minutes_do_not_trigger(
        self,
        spark,
        base_config,
    ):
        """
        No single 5-minute window contains more than 5 events.
        """
        rows = events_at_minute_offsets(
            "192.168.1.10",
            "failed_login",
            [0, 2, 4, 6, 8, 10],
        )

        events_df = make_events_df(spark, rows)

        rule = build_rule()

        alerts = rule.detect(events_df, base_config).collect()

        assert alerts == []

    def test_exactly_at_threshold_does_not_trigger(
        self,
        spark,
        base_config,
    ):
        """
        threshold=5 means the rule triggers only when event_count > 5.
        """
        rows = events_at_minute_offsets(
            "192.168.1.10",
            "failed_login",
            [0, 1, 2, 3, 4],
        )

        events_df = make_events_df(spark, rows)

        rule = build_rule()

        alerts = rule.detect(events_df, base_config).collect()

        assert alerts == []

    def test_only_failed_login_events_are_counted(
        self,
        spark,
        base_config,
    ):
        failed_login_events = events_at_minute_offsets(
            "192.168.1.10",
            "failed_login",
            [0, 1, 2, 3, 4, 4.5],
        )

        other_events = events_at_minute_offsets(
            "192.168.1.10",
            "successful_login",
            [0, 1, 2, 3, 4, 4.5],
        )

        events_df = make_events_df(
            spark,
            failed_login_events + other_events,
        )

        rule = build_rule()

        alerts = rule.detect(events_df, base_config).collect()

        assert len(alerts) == 1
        assert alerts[0]["event_count"] == 6

    def test_different_source_ips_are_tracked_independently(
        self,
        spark,
        base_config,
    ):
        ip_a = events_at_minute_offsets(
            "192.168.1.10",
            "failed_login",
            [0, 1, 2, 3, 4, 4.5],
        )

        ip_b = events_at_minute_offsets(
            "10.0.0.5",
            "failed_login",
            [0, 1],
        )

        events_df = make_events_df(
            spark,
            ip_a + ip_b,
        )

        rule = build_rule()

        alerts = rule.detect(events_df, base_config).collect()

        assert len(alerts) == 1
        assert alerts[0]["source_ip"] == "192.168.1.10"
        assert alerts[0]["event_count"] == 6


# ---------------------------------------------------------------------------
# Alert persistence and publication
# ---------------------------------------------------------------------------


class TestAlertSideEffects:

    def test_alert_is_saved_and_published(
        self,
        spark,
        base_config,
    ):
        rows = events_at_minute_offsets(
            "192.168.1.10",
            "failed_login",
            [0, 1, 2, 3, 4, 4.5],
        )

        events_df = make_events_df(spark, rows)

        alerts_repository = Mock()
        alerts_repository.save.return_value = {
            "id": 1,
            "rule_name": "brute_force",
            "source_ip": "192.168.1.10",
            "event_count": 6,
            "severity": severity_for_count(6),
        }

        alert_publisher = Mock()

        rule = build_rule(
            alerts_repository=alerts_repository,
            alert_publisher=alert_publisher,
        )

        alert_df = rule.detect(events_df, base_config)

        rule.process_batch(
            alert_df,
            batch_id=0,
            config=base_config,
        )

        alerts_repository.save.assert_called_once()

        save_kwargs = alerts_repository.save.call_args.kwargs

        assert save_kwargs["rule_name"] == "brute_force"
        assert save_kwargs["source_ip"] == "192.168.1.10"
        assert save_kwargs["event_count"] == 6
        assert save_kwargs["severity"] == severity_for_count(6)
        assert save_kwargs["window_start"] is not None
        assert save_kwargs["window_end"] is not None
        assert save_kwargs["triggered_at"] is not None

        alert_publisher.publish.assert_called_once()

        published = alert_publisher.publish.call_args.args[0]

        assert published["rule_name"] == "brute_force"
        assert published["source_ip"] == "192.168.1.10"
        assert published["severity"] == severity_for_count(6)

        assert published["description"] == (
            "Detected 6 failed login attempts from "
            "192.168.1.10 within a 0:05:00 window"
        )

        assert len(published["source_event_ids"]) == 6

    def test_no_alert_means_nothing_is_saved_or_published(
        self,
        spark,
        base_config,
    ):
        rows = events_at_minute_offsets(
            "192.168.1.10",
            "failed_login",
            [0, 1, 2, 3],
        )

        events_df = make_events_df(spark, rows)

        alerts_repository = Mock()
        alert_publisher = Mock()

        rule = build_rule(
            alerts_repository=alerts_repository,
            alert_publisher=alert_publisher,
        )

        alert_df = rule.detect(events_df, base_config)

        rule.process_batch(
            alert_df,
            batch_id=0,
            config=base_config,
        )

        alerts_repository.save.assert_not_called()
        alert_publisher.publish.assert_not_called()

    def test_duplicate_alert_is_not_published_twice(
        self,
        spark,
        base_config,
    ):
        """
        Simulates Spark at-least-once processing.

        The repository returns None when the alert already exists.
        In that case the rule must not publish the duplicate alert.
        """
        rows = events_at_minute_offsets(
            "192.168.1.10",
            "failed_login",
            [0, 1, 2, 3, 4, 4.5],
        )

        events_df = make_events_df(spark, rows)

        alerts_repository = Mock()

        # First save succeeds.
        # Second save represents the repository detecting a duplicate.
        alerts_repository.save.side_effect = [
            {
                "id": 1,
                "rule_name": "brute_force",
                "source_ip": "192.168.1.10",
                "event_count": 6,
                "severity": severity_for_count(6),
            },
            None,
        ]

        alert_publisher = Mock()

        rule = build_rule(
            alerts_repository=alerts_repository,
            alert_publisher=alert_publisher,
        )

        alert_df = rule.detect(events_df, base_config)

        rule.process_batch(
            alert_df,
            batch_id=0,
            config=base_config,
        )

        rule.process_batch(
            alert_df,
            batch_id=0,
            config=base_config,
        )

        assert alerts_repository.save.call_count == 2

        # Only the first alert should be published.
        assert alert_publisher.publish.call_count == 1


# ---------------------------------------------------------------------------
# Rule configuration
# ---------------------------------------------------------------------------


class TestRuleConfiguration:

    def test_rule_uses_repository_configuration(
        self,
        spark,
    ):
        rules_repository = Mock()

        rules_repository.get_config.return_value = RuleConfig(
            rule_name="brute_force",
            threshold=10,
            window_minutes=3,
            slide_minutes=1,
            enabled=True,
        )

        rule = build_rule(
            rules_repository=rules_repository,
        )

        config = rule.load_config()

        rules_repository.get_config.assert_called_once()

        assert config.threshold == 10
        assert config.window_minutes == 3
        assert config.slide_minutes == 1
        assert config.enabled is True

    def test_database_threshold_changes_detection_result(
        self,
        spark,
    ):
        """
        Six events trigger with threshold=5 but not with threshold=10.
        """
        rules_repository = Mock()

        rules_repository.get_config.return_value = RuleConfig(
            rule_name="brute_force",
            threshold=10,
            window_minutes=5,
            slide_minutes=1,
            enabled=True,
        )

        config = rules_repository.get_config("brute_force")

        rows = events_at_minute_offsets(
            "192.168.1.10",
            "failed_login",
            [0, 1, 2, 3, 4, 4.5],
        )

        events_df = make_events_df(spark, rows)

        rule = build_rule(
            rules_repository=rules_repository,
        )

        alerts = rule.detect(events_df, config).collect()

        assert len(alerts) == 0


# ---------------------------------------------------------------------------
# Disabled rule
# ---------------------------------------------------------------------------


class TestDisabledRule:

    def test_disabled_rule_does_not_create_streaming_query(
        self,
        spark,
        tmp_path,
    ):
        """
        A disabled rule should not create a streaming query.
        """
        rules_repository = Mock()

        rules_repository.get_config.return_value = RuleConfig(
            rule_name="brute_force",
            threshold=5,
            window_minutes=5,
            slide_minutes=1,
            enabled=False,
        )

        rule = build_rule(
            rules_repository=rules_repository,
        )

        # A minimal streaming DataFrame with the required columns.
        events_df = (
            spark.readStream
            .format("rate")
            .option("rowsPerSecond", 1)
            .load()
            .selectExpr(
                "CAST(value AS STRING) AS event_id",
                "'192.168.1.10' AS source_ip",
                "'failed_login' AS event_type",
                "timestamp AS event_timestamp",
            )
        )

        query = rule.build_streaming_query(
            events_df,
            checkpoint_location=str(tmp_path / "checkpoint"),
        )

        assert query is None


# ---------------------------------------------------------------------------
# Severity scale
# ---------------------------------------------------------------------------


class TestSeverityScale:

    @pytest.mark.parametrize(
        "count, expected",
        [
            (5, "MEDIUM"),
            (9, "MEDIUM"),
            (10, "HIGH"),
            (19, "HIGH"),
            (20, "CRITICAL"),
            (50, "CRITICAL"),
        ],
    )
    def test_severity_boundaries(self, count, expected):
        assert severity_for_count(count) == expected