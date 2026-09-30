"""
Off-hours login detection rule.

Detects successful logins occurring outside the configured business
hours.

Default:
    Off-hours: 22:00 through 06:00
    Server timezone: TZ environment variable

Examples with the default configuration:

    21:59 -> normal
    22:00 -> alert
    23:30 -> alert
    02:00 -> alert
    05:59 -> alert
    06:00 -> normal
    15:00 -> normal

Only successful_login events are considered.

MITRE ATT&CK context:
    T1078 - Valid Accounts

Important:
    Event timestamps are stored and persisted as UTC. The rule converts
    them to the configured server timezone only for determining the
    local wall-clock time.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, time, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from consumers.schemas import AlertEvent
from detection_engine.publishers.alert_publisher import AlertPublisher
from detection_engine.repositories.alerts_repository import AlertsRepository
from detection_engine.repositories.rules_repository import RulesRepository
from detection_engine.rules.base import BaseRule, RuleConfig

logger = logging.getLogger(__name__)

RULE_NAME = "off_hours_login"
MITRE_TECHNIQUE = "T1078"

ALERT_SEVERITY = "MEDIUM"

DEFAULT_OFF_HOURS_START = time(22, 0)
DEFAULT_OFF_HOURS_END = time(6, 0)

DEFAULT_TIMEZONE = "UTC"

DEFAULT_CONFIG = RuleConfig(
    rule_name=RULE_NAME,
    threshold=1,
    window_minutes=1,
    slide_minutes=1,
    enabled=True,
    off_hours_start=DEFAULT_OFF_HOURS_START,
    off_hours_end=DEFAULT_OFF_HOURS_END,
)

TIMESTAMP_COL = "event_timestamp"
FALLBACK_TIMESTAMP_COL = "timestamp"

EVENT_TYPE_COL = "event_type"
EVENT_ID_COL = "event_id"
SOURCE_IP_COL = "source_ip"
USERNAME_COL = "username"

SUCCESSFUL_LOGIN_EVENT_TYPE = "successful_login"


class OffHoursLoginRule(BaseRule):
    """
    Detect successful logins outside configured local business hours.

    Event timestamps remain UTC. Local-time conversion happens only
    during rule evaluation.
    """

    def __init__(
        self,
        rules_repository: RulesRepository | None = None,
        alerts_repository: AlertsRepository | None = None,
        alert_publisher: AlertPublisher | None = None,
    ) -> None:
        self.rules_repository = rules_repository
        self.alerts_repository = alerts_repository
        self.alert_publisher = alert_publisher

        self.rule_name = RULE_NAME

    def load_config(self) -> RuleConfig:
        """
        Load configuration from the rules database.

        A default exists for isolated unit tests. Production deployments
        should configure the rule explicitly in the rules table.
        """

        if self.rules_repository is None:
            config = DEFAULT_CONFIG
        else:
            config = self.rules_repository.get_config(
                self.rule_name,
                default=DEFAULT_CONFIG,
            )

        self._validate_config(config)

        return config

    @staticmethod
    def _validate_config(config: RuleConfig) -> None:
        """Validate off-hours configuration before processing events."""

        if config.rule_name != RULE_NAME:
            raise ValueError(
                f"Invalid rule configuration: expected "
                f"'{RULE_NAME}', got '{config.rule_name}'"
            )

        if config.off_hours_start is None:
            raise ValueError(
                "off_hours_start must be configured for "
                f"rule '{RULE_NAME}'"
            )

        if config.off_hours_end is None:
            raise ValueError(
                "off_hours_end must be configured for "
                f"rule '{RULE_NAME}'"
            )

        if not isinstance(config.off_hours_start, time):
            raise ValueError(
                "off_hours_start must be a datetime.time value"
            )

        if not isinstance(config.off_hours_end, time):
            raise ValueError(
                "off_hours_end must be a datetime.time value"
            )

    @staticmethod
    def _server_timezone() -> ZoneInfo:
        """
        Resolve the configured server timezone.

        TZ should contain an IANA timezone such as:
            Asia/Kolkata
            America/New_York
            Europe/London

        UTC is used when TZ is not explicitly configured.
        """

        timezone_name = os.environ.get(
            "TZ",
            DEFAULT_TIMEZONE,
        ).strip()

        if not timezone_name:
            timezone_name = DEFAULT_TIMEZONE

        try:
            return ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(
                f"Invalid TZ environment variable: "
                f"{timezone_name!r}. "
                "Expected an IANA timezone such as "
                "'Asia/Kolkata'."
            ) from exc

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        """
        Return a timezone-aware UTC datetime.

        Spark may return timestamps as naive datetime objects depending
        on the execution environment. Pipeline timestamps are stored
        as UTC, so naive values are interpreted as UTC.
        """

        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)

        return value.astimezone(timezone.utc)

    @classmethod
    def _local_time(
        cls,
        timestamp: datetime,
    ) -> time:
        """Convert a UTC timestamp into configured server local time."""

        utc_timestamp = cls._as_utc(timestamp)

        local_timestamp = utc_timestamp.astimezone(
            cls._server_timezone()
        )

        return local_timestamp.timetz().replace(
            tzinfo=None
        )

    @staticmethod
    def _is_off_hours(
        local_time: time,
        start: time,
        end: time,
    ) -> bool:
        """
        Determine whether a local wall-clock time is off-hours.

        For a normal interval:

            start <= local_time < end

        For an overnight interval such as 22:00 -> 06:00:

            local_time >= 22:00 OR local_time < 06:00

        Therefore:

            22:00 -> off-hours
            06:00 -> business hours
        """

        if start == end:
            # Equal boundaries represent a full-day off-hours window.
            return True

        if start < end:
            return start <= local_time < end

        # Overnight interval.
        return local_time >= start or local_time < end

    @staticmethod
    def _get_timestamp(
        row: Any,
    ) -> datetime | None:
        """
        Get the event timestamp from a Spark Row.

        event_timestamp is preferred because it is the canonical
        normalized timestamp. timestamp is retained as a fallback
        for compatibility with earlier pipeline stages and tests.
        """

        timestamp = row[TIMESTAMP_COL]

        if timestamp is not None:
            return timestamp

        try:
            return row[FALLBACK_TIMESTAMP_COL]
        except (KeyError, IndexError):
            return None

    def detect(
        self,
        events_df: DataFrame,
        config: RuleConfig,
    ) -> DataFrame:
        """
        Filter successful logins.

        This is intentionally a pure Spark transformation.

        Timezone-dependent evaluation and alert side effects happen
        inside process_batch().
        """

        if not config.enabled:
            return events_df.limit(0)

        self._validate_config(config)

        return events_df.filter(
            F.col(EVENT_TYPE_COL)
            == SUCCESSFUL_LOGIN_EVENT_TYPE
        )

    def _handle_alert_row(
        self,
        row: Any,
        config: RuleConfig,
    ) -> None:
        """Evaluate and persist one successful-login event."""

        if self.alerts_repository is None:
            raise RuntimeError(
                "AlertsRepository is required to save alerts"
            )

        if self.alert_publisher is None:
            raise RuntimeError(
                "AlertPublisher is required to publish alerts"
            )

        self._validate_config(config)

        timestamp = self._get_timestamp(row)

        if timestamp is None:
            logger.warning(
                "Skipping off-hours login with missing timestamp"
            )
            return

        event_id = row[EVENT_ID_COL]

        if event_id is None:
            logger.warning(
                "Skipping off-hours login with missing event_id"
            )
            return

        source_ip = row[SOURCE_IP_COL]

        if source_ip is None:
            logger.warning(
                "Skipping off-hours login with missing source_ip "
                "event_id=%s",
                event_id,
            )
            return

        event_type = row[EVENT_TYPE_COL]

        if event_type != SUCCESSFUL_LOGIN_EVENT_TYPE:
            logger.debug(
                "Skipping non-successful login event "
                "event_id=%s event_type=%s",
                event_id,
                event_type,
            )
            return

        timestamp_utc = self._as_utc(timestamp)

        local_timezone = self._server_timezone()

        local_timestamp = timestamp_utc.astimezone(
            local_timezone
        )

        local_time = local_timestamp.timetz().replace(
            tzinfo=None
        )

        if not self._is_off_hours(
            local_time,
            config.off_hours_start,
            config.off_hours_end,
        ):
            return

        username = row[USERNAME_COL]

        if username is None:
            username = "unknown"

        source_event_id = str(event_id)
        source_ip = str(source_ip)

        triggered_at = datetime.now(timezone.utc)

        description = (
            "Successful login outside configured business hours "
            f"for user '{username}' from {source_ip} at "
            f"{local_timestamp.isoformat()} "
            f"(local timezone: {local_timezone.key}, "
            f"off-hours: "
            f"{config.off_hours_start.strftime('%H:%M')}-"
            f"{config.off_hours_end.strftime('%H:%M')}; "
            f"MITRE {MITRE_TECHNIQUE})"
        )

        alert_event = AlertEvent(
            rule_name=self.rule_name,
            severity=ALERT_SEVERITY,
            description=description,
            source_ip=source_ip,
            source_event_ids=[source_event_id],
            triggered_at=triggered_at,
        )

        saved = self.alerts_repository.save(
            rule_name=self.rule_name,
            source_ip=source_ip,
            severity=ALERT_SEVERITY,
            event_count=1,
            window_start=timestamp_utc,
            window_end=timestamp_utc,
            triggered_at=triggered_at,
        )

        if saved is None:
            logger.info(
                "Skipping duplicate off-hours-login alert "
                "event_id=%s source_ip=%s timestamp=%s",
                source_event_id,
                source_ip,
                timestamp_utc,
            )
            return

        self.alert_publisher.publish(
            alert_event.model_dump(mode="json")
        )

        logger.info(
            "Off-hours login alert created "
            "alert_id=%s event_id=%s username=%s "
            "source_ip=%s local_time=%s timezone=%s",
            alert_event.alert_id,
            source_event_id,
            username,
            source_ip,
            local_timestamp.isoformat(),
            local_timezone.key,
        )

    def process_batch(
        self,
        batch_df: DataFrame,
        batch_id: int,
        config: RuleConfig,
    ) -> None:
        """
        Evaluate events in a micro-batch and persist triggered alerts.

        The batch is passed through detect() first so process_batch()
        behaves consistently whether it receives a raw streaming batch
        or a batch from a test.
        """

        if not config.enabled:
            return

        self._validate_config(config)

        candidate_df = self.detect(
            batch_df,
            config,
        )

        rows = candidate_df.collect()

        logger.debug(
            "Processing off-hours-login "
            "batch_id=%s candidate_rows=%d",
            batch_id,
            len(rows),
        )

        for row in rows:
            self._handle_alert_row(
                row,
                config,
            )

    def build_detection_stream(
        self,
        valid_events_stream_df: DataFrame,
    ) -> DataFrame:
        """Build the stream containing candidate successful logins."""

        config = self.load_config()

        if not config.enabled:
            logger.info(
                "Rule '%s' is disabled",
                self.rule_name,
            )

            return valid_events_stream_df.limit(0)

        return self.detect(
            valid_events_stream_df,
            config,
        )

    def build_streaming_query(
        self,
        valid_events_stream_df: DataFrame,
        checkpoint_location: str,
    ):
        """Attach foreachBatch to the candidate-login stream."""

        config = self.load_config()

        if not config.enabled:
            logger.info(
                "Rule '%s' is disabled",
                self.rule_name,
            )
            return None

        candidate_stream = self.detect(
            valid_events_stream_df,
            config,
        )

        return (
            candidate_stream.writeStream
            .foreachBatch(
                lambda batch_df, batch_id: self.process_batch(
                    batch_df,
                    batch_id,
                    config,
                )
            )
            .option(
                "checkpointLocation",
                checkpoint_location,
            )
            .outputMode("append")
            .start()
        )


def build_default_rule() -> OffHoursLoginRule:
    """Construct the production off-hours rule."""

    from api.database import SessionLocal
    from detection_engine.publishers.kafka_alert_publisher import (
        KafkaAlertPublisher,
    )

    bootstrap_servers = os.environ.get(
        "KAFKA_BOOTSTRAP_SERVERS"
    )

    if not bootstrap_servers:
        raise RuntimeError(
            "KAFKA_BOOTSTRAP_SERVERS environment variable is required"
        )

    return OffHoursLoginRule(
        rules_repository=RulesRepository(
            session_factory=SessionLocal,
        ),
        alerts_repository=AlertsRepository(
            session_factory=SessionLocal,
        ),
        alert_publisher=KafkaAlertPublisher(
            bootstrap_servers=bootstrap_servers,
        ),
    )