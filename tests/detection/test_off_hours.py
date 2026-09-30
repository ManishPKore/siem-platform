"""Tests for OffHoursLoginRule."""

from __future__ import annotations

import uuid
from datetime import datetime, time, timezone
from unittest.mock import ANY, Mock

import pytest

pyspark = pytest.importorskip("pyspark")

from pyspark.sql import Row, SparkSession

from detection_engine.rules.base import RuleConfig
from detection_engine.rules.off_hours import (
    ALERT_SEVERITY,
    DEFAULT_OFF_HOURS_END,
    DEFAULT_OFF_HOURS_START,
    OffHoursLoginRule,
)


BASE_DATE = datetime(
    2026,
    1,
    15,
    tzinfo=timezone.utc,
)

SOURCE_IP = "203.0.113.10"
USERNAME = "alice"


@pytest.fixture(scope="session")
def spark():
    """Shared local Spark session."""

    session = (
        SparkSession.builder
        .master("local[2]")
        .appName("test_off_hours_login")
        .config(
            "spark.sql.shuffle.partitions",
            "1",
        )
        .config(
            "spark.sql.session.timeZone",
            "UTC",
        )
        .config(
            "spark.ui.enabled",
            "false",
        )
        .getOrCreate()
    )

    yield session

    session.stop()


@pytest.fixture
def base_config():
    """Default 22:00 -> 06:00 configuration."""

    return RuleConfig(
        rule_name="off_hours_login",
        threshold=1,
        window_minutes=1,
        slide_minutes=1,
        enabled=True,
        off_hours_start=DEFAULT_OFF_HOURS_START,
        off_hours_end=DEFAULT_OFF_HOURS_END,
    )


def build_rule(
    rules_repository=None,
    alerts_repository=None,
    alert_publisher=None,
):
    """Build an OffHoursLoginRule with optional test doubles."""

    return OffHoursLoginRule(
        rules_repository=rules_repository,
        alerts_repository=alerts_repository,
        alert_publisher=alert_publisher,
    )


def make_event(
    timestamp: datetime,
    *,
    event_type: str = "successful_login",
    username: str = USERNAME,
    source_ip: str = SOURCE_IP,
    event_id: str | None = None,
):
    """Create a Spark-compatible login event.

    Spark/PySpark on Windows can reinterpret timezone-aware Python
    datetimes using the local machine timezone when creating a
    DataFrame. The SIEM pipeline stores event timestamps as UTC,
    so normalize aware timestamps to naive UTC before handing them
    to Spark.
    """

    if timestamp.tzinfo is not None:
        spark_timestamp = (
            timestamp
            .astimezone(timezone.utc)
            .replace(tzinfo=None)
        )
    else:
        spark_timestamp = timestamp

    return Row(
        event_id=event_id or str(uuid.uuid4()),
        timestamp=spark_timestamp,
        event_timestamp=spark_timestamp,
        source_ip=source_ip,
        username=username,
        event_type=event_type,
    )


def make_df(
    spark,
    timestamp: datetime,
    **kwargs,
):
    """Create a single-row Spark DataFrame."""

    return spark.createDataFrame(
        [
            make_event(
                timestamp,
                **kwargs,
            )
        ]
    )


# ---------------------------------------------------------------------------
# Pure boundary tests
# ---------------------------------------------------------------------------


class TestOffHoursBoundaries:

    def test_exactly_22_00_is_off_hours(
        self,
    ):
        assert OffHoursLoginRule._is_off_hours(
            time(22, 0),
            time(22, 0),
            time(6, 0),
        ) is True

    def test_exactly_06_00_is_business_hours(
        self,
    ):
        assert OffHoursLoginRule._is_off_hours(
            time(6, 0),
            time(22, 0),
            time(6, 0),
        ) is False

    def test_02_00_is_off_hours(
        self,
    ):
        assert OffHoursLoginRule._is_off_hours(
            time(2, 0),
            time(22, 0),
            time(6, 0),
        ) is True

    def test_15_00_is_business_hours(
        self,
    ):
        assert OffHoursLoginRule._is_off_hours(
            time(15, 0),
            time(22, 0),
            time(6, 0),
        ) is False

    def test_21_59_is_business_hours(
        self,
    ):
        assert OffHoursLoginRule._is_off_hours(
            time(21, 59),
            time(22, 0),
            time(6, 0),
        ) is False

    def test_05_59_is_off_hours(
        self,
    ):
        assert OffHoursLoginRule._is_off_hours(
            time(5, 59),
            time(22, 0),
            time(6, 0),
        ) is True


# ---------------------------------------------------------------------------
# UTC -> local timezone
# ---------------------------------------------------------------------------


class TestTimezoneConversion:

    def test_utc_timestamp_converts_to_server_timezone(
        self,
        monkeypatch,
    ):
        monkeypatch.setenv(
            "TZ",
            "Asia/Kolkata",
        )

        timestamp = datetime(
            2026,
            1,
            15,
            16,
            30,
            tzinfo=timezone.utc,
        )

        # 16:30 UTC = 22:00 IST.
        assert OffHoursLoginRule._local_time(
            timestamp
        ) == time(22, 0)

    def test_utc_timestamp_at_0030_becomes_0600_ist(
        self,
        monkeypatch,
    ):
        monkeypatch.setenv(
            "TZ",
            "Asia/Kolkata",
        )

        timestamp = datetime(
            2026,
            1,
            15,
            0,
            30,
            tzinfo=timezone.utc,
        )

        # 00:30 UTC = 06:00 IST.
        assert OffHoursLoginRule._local_time(
            timestamp
        ) == time(6, 0)


# ---------------------------------------------------------------------------
# Detection filtering
# ---------------------------------------------------------------------------


class TestDetect:

    def test_only_successful_login_events_are_candidates(
        self,
        spark,
        base_config,
    ):
        rows = [
            make_event(
                BASE_DATE,
                event_type="successful_login",
            ),
            make_event(
                BASE_DATE,
                event_type="failed_login",
            ),
            make_event(
                BASE_DATE,
                event_type="web_request",
            ),
        ]

        events_df = spark.createDataFrame(rows)

        rule = build_rule()

        result = rule.detect(
            events_df,
            base_config,
        )

        assert result.count() == 1

        row = result.first()

        assert row.event_type == "successful_login"


# ---------------------------------------------------------------------------
# Acceptance criteria
# ---------------------------------------------------------------------------


class TestAcceptanceCriteria:

    def test_successful_login_at_2am_creates_medium_alert(
        self,
        spark,
        base_config,
        monkeypatch,
    ):
        monkeypatch.setenv(
            "TZ",
            "UTC",
        )

        timestamp = datetime(
            2026,
            1,
            15,
            2,
            0,
            tzinfo=timezone.utc,
        )

        batch_df = make_df(
            spark,
            timestamp,
        )

        alerts_repository = Mock()
        alerts_repository.save.return_value = {
            "id": 1,
        }

        alert_publisher = Mock()

        rule = build_rule(
            alerts_repository=alerts_repository,
            alert_publisher=alert_publisher,
        )

        rule.process_batch(
            batch_df,
            batch_id=0,
            config=base_config,
        )

        alerts_repository.save.assert_called_once()

        save_kwargs = alerts_repository.save.call_args.kwargs

        assert save_kwargs["rule_name"] == "off_hours_login"
        assert save_kwargs["severity"] == ALERT_SEVERITY
        assert save_kwargs["severity"] == "MEDIUM"
        assert save_kwargs["event_count"] == 1
        assert save_kwargs["source_ip"] == SOURCE_IP

        alert_publisher.publish.assert_called_once()

        published = alert_publisher.publish.call_args.args[0]

        assert published["severity"] == "MEDIUM"
        assert published["rule_name"] == "off_hours_login"
        assert published["source_ip"] == SOURCE_IP
        assert len(published["source_event_ids"]) == 1

    def test_successful_login_at_3pm_creates_no_alert(
        self,
        spark,
        base_config,
        monkeypatch,
    ):
        monkeypatch.setenv(
            "TZ",
            "UTC",
        )

        timestamp = datetime(
            2026,
            1,
            15,
            15,
            0,
            tzinfo=timezone.utc,
        )

        batch_df = make_df(
            spark,
            timestamp,
        )

        alerts_repository = Mock()
        alert_publisher = Mock()

        rule = build_rule(
            alerts_repository=alerts_repository,
            alert_publisher=alert_publisher,
        )

        rule.process_batch(
            batch_df,
            batch_id=0,
            config=base_config,
        )

        alerts_repository.save.assert_not_called()
        alert_publisher.publish.assert_not_called()

    def test_exactly_22_00_creates_alert(
        self,
        spark,
        base_config,
        monkeypatch,
    ):
        monkeypatch.setenv(
            "TZ",
            "UTC",
        )

        timestamp = datetime(
            2026,
            1,
            15,
            22,
            0,
            tzinfo=timezone.utc,
        )

        batch_df = make_df(
            spark,
            timestamp,
        )

        alerts_repository = Mock()
        alerts_repository.save.return_value = {
            "id": 1,
        }

        alert_publisher = Mock()

        rule = build_rule(
            alerts_repository=alerts_repository,
            alert_publisher=alert_publisher,
        )

        rule.process_batch(
            batch_df,
            batch_id=0,
            config=base_config,
        )

        alerts_repository.save.assert_called_once()
        alert_publisher.publish.assert_called_once()

    def test_exactly_06_00_creates_no_alert(
        self,
        spark,
        base_config,
        monkeypatch,
    ):
        monkeypatch.setenv(
            "TZ",
            "UTC",
        )

        timestamp = datetime(
            2026,
            1,
            15,
            6,
            0,
            tzinfo=timezone.utc,
        )

        batch_df = make_df(
            spark,
            timestamp,
        )

        alerts_repository = Mock()
        alert_publisher = Mock()

        rule = build_rule(
            alerts_repository=alerts_repository,
            alert_publisher=alert_publisher,
        )

        rule.process_batch(
            batch_df,
            batch_id=0,
            config=base_config,
        )

        alerts_repository.save.assert_not_called()
        alert_publisher.publish.assert_not_called()


# ---------------------------------------------------------------------------
# Database configuration
# ---------------------------------------------------------------------------


class TestRuleConfiguration:

    def test_default_configuration(
        self,
    ):
        rule = build_rule()

        config = rule.load_config()

        assert config.rule_name == "off_hours_login"
        assert config.off_hours_start == time(22, 0)
        assert config.off_hours_end == time(6, 0)
        assert config.enabled is True

    def test_configuration_is_loaded_from_repository(
        self,
    ):
        rules_repository = Mock()

        rules_repository.get_config.return_value = RuleConfig(
            rule_name="off_hours_login",
            threshold=1,
            window_minutes=1,
            slide_minutes=1,
            enabled=True,
            off_hours_start=time(23, 0),
            off_hours_end=time(5, 0),
        )

        rule = build_rule(
            rules_repository=rules_repository,
        )

        config = rule.load_config()

        rules_repository.get_config.assert_called_once_with(
            "off_hours_login",
            default=ANY,
        )

        assert config.off_hours_start == time(23, 0)
        assert config.off_hours_end == time(5, 0)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestValidation:

    def test_missing_start_time_is_rejected(
        self,
    ):
        config = RuleConfig(
            rule_name="off_hours_login",
            threshold=1,
            window_minutes=1,
            slide_minutes=1,
            enabled=True,
            off_hours_start=None,
            off_hours_end=time(6, 0),
        )

        with pytest.raises(ValueError):
            OffHoursLoginRule._validate_config(
                config
            )

    def test_missing_end_time_is_rejected(
        self,
    ):
        config = RuleConfig(
            rule_name="off_hours_login",
            threshold=1,
            window_minutes=1,
            slide_minutes=1,
            enabled=True,
            off_hours_start=time(22, 0),
            off_hours_end=None,
        )

        with pytest.raises(ValueError):
            OffHoursLoginRule._validate_config(
                config
            )

    def test_invalid_timezone_is_rejected(
        self,
        monkeypatch,
    ):
        monkeypatch.setenv(
            "TZ",
            "Definitely/Not_A_Timezone",
        )

        with pytest.raises(ValueError):
            OffHoursLoginRule._server_timezone()


# ---------------------------------------------------------------------------
# Disabled rule
# ---------------------------------------------------------------------------


class TestDisabledRule:

    def test_disabled_rule_does_not_create_alert(
        self,
        spark,
        base_config,
        monkeypatch,
    ):
        monkeypatch.setenv(
            "TZ",
            "UTC",
        )

        disabled_config = RuleConfig(
            rule_name="off_hours_login",
            threshold=1,
            window_minutes=1,
            slide_minutes=1,
            enabled=False,
            off_hours_start=time(22, 0),
            off_hours_end=time(6, 0),
        )

        timestamp = datetime(
            2026,
            1,
            15,
            2,
            0,
            tzinfo=timezone.utc,
        )

        batch_df = make_df(
            spark,
            timestamp,
        )

        alerts_repository = Mock()
        alert_publisher = Mock()

        rule = build_rule(
            alerts_repository=alerts_repository,
            alert_publisher=alert_publisher,
        )

        rule.process_batch(
            batch_df,
            batch_id=0,
            config=disabled_config,
        )

        alerts_repository.save.assert_not_called()
        alert_publisher.publish.assert_not_called()


# ---------------------------------------------------------------------------
# Duplicate handling
# ---------------------------------------------------------------------------


class TestDuplicateHandling:

    def test_duplicate_alert_is_not_published(
        self,
        spark,
        base_config,
        monkeypatch,
    ):
        monkeypatch.setenv(
            "TZ",
            "UTC",
        )

        timestamp = datetime(
            2026,
            1,
            15,
            2,
            0,
            tzinfo=timezone.utc,
        )

        batch_df = make_df(
            spark,
            timestamp,
        )

        alerts_repository = Mock()

        alerts_repository.save.side_effect = [
            {"id": 1},
            None,
        ]

        alert_publisher = Mock()

        rule = build_rule(
            alerts_repository=alerts_repository,
            alert_publisher=alert_publisher,
        )

        rule.process_batch(
            batch_df,
            batch_id=0,
            config=base_config,
        )

        rule.process_batch(
            batch_df,
            batch_id=1,
            config=base_config,
        )

        assert alerts_repository.save.call_count == 2
        assert alert_publisher.publish.call_count == 1