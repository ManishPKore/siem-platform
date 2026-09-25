"""
Tests for the PortScanRule detection rule.

Covers Issue #13:

- One IP hitting 25 distinct ports in a 2-minute tumbling window
  triggers an alert.
- One IP hitting 15 distinct ports does not trigger an alert.
- One IP hitting 25 requests to the SAME port does not trigger an alert
  (repeated port, not scanning).
- Only firewall-source events are counted.
- Ports spread across more than one 2-minute tumbling window do not
  trigger an alert.
- Different source IPs are evaluated independently.
- Alert persistence is requested with the correct fields
  (source_ip, distinct_port_count via event_count, window_start,
  window_end, severity="HIGH").
- Alert publication uses the publisher's actual interface (no `topic`
  kwarg) and contains the expected alert information.
- Duplicate processing does not create or publish duplicate alerts.
- Threshold configuration is actually sourced from the rules repository
  before detection runs.
- A disabled rule does not create a streaming query.
"""

import uuid
from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest

pyspark = pytest.importorskip("pyspark")

from pyspark.sql import Row, SparkSession

from detection_engine.rules.base import RuleConfig
from detection_engine.rules.port_scan import ALERT_SEVERITY, PortScanRule


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def spark():
    """Create one local Spark session for the test suite."""
    session = (
        SparkSession.builder
        .master("local[2]")
        .appName("test_port_scan")
        .config("spark.sql.shuffle.partitions", "1")
        .getOrCreate()
    )

    yield session

    session.stop()


@pytest.fixture
def base_config():
    """Default port-scan rule configuration."""
    return RuleConfig(
        rule_name="port_scan",
        threshold=20,
        window_minutes=2,
        slide_minutes=2,
        enabled=True,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_events_df(spark, rows):
    """
    Create a Spark DataFrame containing normalized security events.

    Each row is:

        (event_id, source_ip, source, dest_port, event_timestamp)
    """
    data = [
        Row(
            event_id=event_id,
            source_ip=source_ip,
            source=source,
            dest_port=dest_port,
            event_timestamp=timestamp,
        )
        for event_id, source_ip, source, dest_port, timestamp in rows
    ]

    return spark.createDataFrame(data)


def firewall_events_at_second_offsets(
    source_ip,
    dest_ports,
    offsets_seconds,
    base=None,
    source="firewall",
):
    """
    Create firewall events at the requested second offsets, one per
    dest_port in `dest_ports` (same length as `offsets_seconds`).
    """
    base = base or datetime(2026, 1, 1, 12, 0, 0)

    return [
        (
            str(uuid.uuid5(uuid.NAMESPACE_DNS, f"test-event-{index}-{port}")),
            source_ip,
            source,
            port,
            base + timedelta(seconds=offset),
        )
        for index, (port, offset) in enumerate(zip(dest_ports, offsets_seconds))
    ]


def spread_offsets(n, span_seconds):
    """n timestamps evenly spread across [0, span_seconds]."""
    if n == 1:
        return [0.0]
    return [span_seconds * i / (n - 1) for i in range(n)]


def sequential_ports(n, start=1000):
    """n deterministic, distinct port numbers starting at `start`."""
    return list(range(start, start + n))


def build_rule(
    alerts_repository=None,
    alert_publisher=None,
    rules_repository=None,
):
    """Create a PortScanRule with injectable dependencies."""
    return PortScanRule(
        rules_repository=rules_repository,
        alerts_repository=alerts_repository,
        alert_publisher=alert_publisher,
    )


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------


class TestDetectBoundaryConditions:

    def test_25_distinct_ports_triggers_alert(
        self,
        spark,
        base_config,
    ):
        ports = sequential_ports(25, start=1000)
        rows = firewall_events_at_second_offsets(
            "203.0.113.5",
            ports,
            spread_offsets(25, span_seconds=110),
        )

        events_df = make_events_df(spark, rows)

        rule = build_rule()

        alerts = rule.detect(events_df, base_config).collect()

        assert len(alerts) == 1
        assert alerts[0]["source_ip"] == "203.0.113.5"
        assert alerts[0]["distinct_port_count"] == 25

    def test_15_distinct_ports_does_not_trigger_alert(
        self,
        spark,
        base_config,
    ):
        ports = sequential_ports(15, start=1000)
        rows = firewall_events_at_second_offsets(
            "203.0.113.5",
            ports,
            spread_offsets(15, span_seconds=110),
        )

        events_df = make_events_df(spark, rows)

        rule = build_rule()

        alerts = rule.detect(events_df, base_config).collect()

        assert alerts == []

    def test_25_requests_to_same_port_does_not_trigger_alert(
        self,
        spark,
        base_config,
    ):
        """
        Repeated hits to a single port is not scanning behavior —
        distinct_port_count must be 1, well under the threshold.
        """
        ports = [443] * 25
        rows = firewall_events_at_second_offsets(
            "203.0.113.5",
            ports,
            spread_offsets(25, span_seconds=110),
        )

        events_df = make_events_df(spark, rows)

        rule = build_rule()

        alerts = rule.detect(events_df, base_config).collect()

        assert alerts == []

    def test_only_firewall_source_events_are_counted(
        self,
        spark,
        base_config,
    ):
        """
        A high-port-diversity burst on a non-firewall source (e.g. "web")
        must not count toward port-scan detection.
        """
        firewall_ports = sequential_ports(15, start=1000)
        firewall_rows = firewall_events_at_second_offsets(
            "203.0.113.5",
            firewall_ports,
            spread_offsets(15, span_seconds=110),
        )

        web_ports = sequential_ports(25, start=2000)
        web_rows = firewall_events_at_second_offsets(
            "203.0.113.5",
            web_ports,
            spread_offsets(25, span_seconds=110),
            source="web",
        )

        events_df = make_events_df(spark, firewall_rows + web_rows)

        rule = build_rule()

        alerts = rule.detect(events_df, base_config).collect()

        # Only the 15 firewall-sourced ports count -> below threshold.
        assert alerts == []

    def test_ports_spread_over_two_tumbling_windows_do_not_trigger(
        self,
        spark,
        base_config,
    ):
        """
        25 distinct ports split evenly across two non-overlapping
        2-minute windows means neither window alone crosses the
        threshold of 20.
        """
        base = datetime(2026, 1, 1, 12, 0, 0)

        window_one_ports = sequential_ports(13, start=1000)
        window_one_rows = firewall_events_at_second_offsets(
            "203.0.113.5",
            window_one_ports,
            spread_offsets(13, span_seconds=100),
            base=base,
        )

        window_two_ports = sequential_ports(12, start=2000)
        window_two_rows = firewall_events_at_second_offsets(
            "203.0.113.5",
            window_two_ports,
            spread_offsets(12, span_seconds=100),
            base=base + timedelta(minutes=2, seconds=1),
        )

        events_df = make_events_df(spark, window_one_rows + window_two_rows)

        rule = build_rule()

        alerts = rule.detect(events_df, base_config).collect()

        assert alerts == []

    def test_different_source_ips_are_tracked_independently(
        self,
        spark,
        base_config,
    ):
        scanner_ports = sequential_ports(25, start=1000)
        scanner_rows = firewall_events_at_second_offsets(
            "203.0.113.5",
            scanner_ports,
            spread_offsets(25, span_seconds=110),
        )

        normal_ports = sequential_ports(3, start=2000)
        normal_rows = firewall_events_at_second_offsets(
            "198.51.100.9",
            normal_ports,
            spread_offsets(3, span_seconds=60),
        )

        events_df = make_events_df(spark, scanner_rows + normal_rows)

        rule = build_rule()

        alerts = rule.detect(events_df, base_config).collect()

        assert len(alerts) == 1
        assert alerts[0]["source_ip"] == "203.0.113.5"
        assert alerts[0]["distinct_port_count"] == 25


# ---------------------------------------------------------------------------
# Alert persistence and publication
# ---------------------------------------------------------------------------


class TestAlertSideEffects:

    def test_alert_is_saved_and_published(
        self,
        spark,
        base_config,
    ):
        ports = sequential_ports(25, start=1000)
        rows = firewall_events_at_second_offsets(
            "203.0.113.5",
            ports,
            spread_offsets(25, span_seconds=110),
        )

        events_df = make_events_df(spark, rows)

        alerts_repository = Mock()
        alerts_repository.save.return_value = {
            "id": 1,
            "rule_name": "port_scan",
            "source_ip": "203.0.113.5",
            "event_count": 25,
            "severity": ALERT_SEVERITY,
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

        assert save_kwargs["rule_name"] == "port_scan"
        assert save_kwargs["source_ip"] == "203.0.113.5"
        # distinct_port_count is intentionally stored via the generic
        # event_count column (see EVENT_COUNT_FIELD note in port_scan.py).
        assert save_kwargs["event_count"] == 25
        assert save_kwargs["severity"] == "HIGH"
        assert save_kwargs["window_start"] is not None
        assert save_kwargs["window_end"] is not None
        assert save_kwargs["triggered_at"] is not None

        # publish() must be called with the dict only — no `topic` kwarg,
        # matching AlertPublisher's actual interface.
        alert_publisher.publish.assert_called_once()
        assert alert_publisher.publish.call_args.kwargs == {}
        assert len(alert_publisher.publish.call_args.args) == 1

        published = alert_publisher.publish.call_args.args[0]

        assert published["rule_name"] == "port_scan"
        assert published["source_ip"] == "203.0.113.5"
        assert published["severity"] == "HIGH"
        assert "25 distinct destination ports" in published["description"]
        assert len(published["source_event_ids"]) == 25

    def test_no_alert_means_nothing_is_saved_or_published(
        self,
        spark,
        base_config,
    ):
        ports = sequential_ports(15, start=1000)
        rows = firewall_events_at_second_offsets(
            "203.0.113.5",
            ports,
            spread_offsets(15, span_seconds=110),
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
        ports = sequential_ports(25, start=1000)
        rows = firewall_events_at_second_offsets(
            "203.0.113.5",
            ports,
            spread_offsets(25, span_seconds=110),
        )

        events_df = make_events_df(spark, rows)

        alerts_repository = Mock()

        # First save succeeds.
        # Second save represents the repository detecting a duplicate.
        alerts_repository.save.side_effect = [
            {
                "id": 1,
                "rule_name": "port_scan",
                "source_ip": "203.0.113.5",
                "event_count": 25,
                "severity": ALERT_SEVERITY,
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
            rule_name="port_scan",
            threshold=10,
            window_minutes=1,
            slide_minutes=1,
            enabled=True,
        )

        rule = build_rule(
            rules_repository=rules_repository,
        )

        config = rule.load_config()

        rules_repository.get_config.assert_called_once()

        assert config.threshold == 10
        assert config.window_minutes == 1
        assert config.enabled is True

    def test_repository_configured_threshold_actually_drives_detection(
        self,
        spark,
    ):
        """
        End-to-end through the rule's own load_config(), not a
        hand-assembled config: PortScanRule.load_config() pulls
        threshold=30 from RulesRepository, and detect() is run with
        that fetched config — 25 distinct ports must NOT trigger an
        alert against that higher threshold.
        """
        rules_repository = Mock()

        rules_repository.get_config.return_value = RuleConfig(
            rule_name="port_scan",
            threshold=30,
            window_minutes=2,
            slide_minutes=2,
            enabled=True,
        )

        ports = sequential_ports(25, start=1000)
        rows = firewall_events_at_second_offsets(
            "203.0.113.5",
            ports,
            spread_offsets(25, span_seconds=110),
        )

        events_df = make_events_df(spark, rows)

        rule = build_rule(
            rules_repository=rules_repository,
        )

        # Go through the rule's own load_config(), not a hand-built config.
        config = rule.load_config()
        alerts = rule.detect(events_df, config).collect()

        rules_repository.get_config.assert_called_once()
        assert alerts == []


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
            rule_name="port_scan",
            threshold=20,
            window_minutes=2,
            slide_minutes=2,
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
                "'203.0.113.5' AS source_ip",
                "'firewall' AS source",
                "443 AS dest_port",
                "timestamp AS event_timestamp",
            )
        )

        query = rule.build_streaming_query(
            events_df,
            checkpoint_location=str(tmp_path / "checkpoint"),
        )

        assert query is None