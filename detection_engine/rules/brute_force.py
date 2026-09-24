"""
Brute-force detection rule.

Detects more than N failed_login events from the same source IP
within a configurable sliding time window.

Issue #12:
- Spark sliding window
- configurable threshold/window from rules DB
- PostgreSQL alert persistence
- Kafka alert publication
- duplicate-safe processing
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from consumers.schemas import AlertEvent, EventType
from detection_engine.publishers.alert_publisher import (
    AlertPublisher,
    DEFAULT_ALERTS_TOPIC,
)
from detection_engine.repositories.alerts_repository import AlertsRepository
from detection_engine.repositories.rules_repository import RulesRepository
from detection_engine.rules.base import BaseRule, RuleConfig
from detection_engine.rules.severity import severity_for_count

logger = logging.getLogger(__name__)

RULE_NAME = "brute_force"
MITRE_TECHNIQUE = "T1110"

SLIDE_MINUTES = 1

DEFAULT_CONFIG = RuleConfig(
    rule_name=RULE_NAME,
    threshold=5,
    window_minutes=5,
    slide_minutes=SLIDE_MINUTES,
    enabled=True,
)

TIMESTAMP_COL = "event_timestamp"
SOURCE_IP_COL = "source_ip"
EVENT_TYPE_COL = "event_type"
EVENT_ID_COL = "event_id"

FAILED_LOGIN_EVENT_TYPE = "failed_login"


class BruteForceRule(BaseRule):
    """
    Detect repeated failed logins from a single source IP.

    The Spark aggregation is performed on the streaming DataFrame itself.
    This is important: putting window() inside foreachBatch would reset
    the aggregation for every micro-batch.
    """

    def __init__(
        self,
        rules_repository: RulesRepository | None,
        alerts_repository: AlertsRepository | None,
        alert_publisher: AlertPublisher | None,
    ) -> None:
        self.rules_repository = rules_repository
        self.alerts_repository = alerts_repository
        self.alert_publisher = alert_publisher

        self.rule_name = RULE_NAME

    def load_config(self) -> RuleConfig:
        """
        Load the rule configuration from the rules database.

        A default is retained for isolated unit tests where no repository
        is provided. Production startup should seed the rules table.
        """
        if self.rules_repository is None:
            return DEFAULT_CONFIG

        return self.rules_repository.get_config(
            self.rule_name,
            default=DEFAULT_CONFIG,
        )

    def detect(
        self,
        events_df: DataFrame,
        config: RuleConfig,
    ) -> DataFrame:
        """
        Build the Spark detection aggregation.

        Returns one row per source IP / time window that exceeds
        the configured threshold.
        """

        window_duration = f"{config.window_minutes} minutes"
        slide_duration = f"{config.slide_minutes} minutes"

        failed_logins = events_df.filter(
            F.col(EVENT_TYPE_COL) == FAILED_LOGIN_EVENT_TYPE
        )

        # event_id is retained so AlertEvent can reference the source
        # events that caused the alert.
        windowed_counts = (
            failed_logins
            .withWatermark(TIMESTAMP_COL, window_duration)
            .groupBy(
                F.window(
                    F.col(TIMESTAMP_COL),
                    window_duration,
                    slide_duration,
                ),
                F.col(SOURCE_IP_COL),
            )
            .agg(
                F.count("*").alias("event_count"),
                F.collect_set(EVENT_ID_COL).alias("source_event_ids"),
            )
        )

        return (
            windowed_counts
            .filter(F.col("event_count") > config.threshold)
            .select(
                F.col(SOURCE_IP_COL).alias("source_ip"),
                F.col("event_count"),
                F.col("window.start").alias("window_start"),
                F.col("window.end").alias("window_end"),
                F.col("source_event_ids"),
            )
        )

    def _as_utc(self, value: datetime) -> datetime:
        """Return a timezone-aware UTC datetime."""
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)

        return value.astimezone(timezone.utc)

    def _handle_alert_row(self, row: Any) -> None:
        """
        Persist one aggregated alert and publish it to Kafka.

        The database write happens first. If the alert is a duplicate,
        nothing is published to Kafka.
        """

        if self.alerts_repository is None:
            raise RuntimeError("AlertsRepository is required to save alerts")

        if self.alert_publisher is None:
            raise RuntimeError("AlertPublisher is required to publish alerts")

        source_ip = str(row["source_ip"])
        event_count = int(row["event_count"])

        window_start = self._as_utc(row["window_start"])
        window_end = self._as_utc(row["window_end"])

        severity = severity_for_count(event_count)

        triggered_at = datetime.now(timezone.utc)

        source_event_ids = [
            str(event_id)
            for event_id in (row["source_event_ids"] or [])
        ]

        if not source_event_ids:
            logger.warning(
                "Brute-force alert has no source event IDs "
                "source_ip=%s window_start=%s window_end=%s",
                source_ip,
                window_start,
                window_end,
            )

            # AlertEvent requires at least one source event ID.
            # This should not happen in the production normalized stream.
            return

        # ---------------------------------------------------------------
        # 1. Persist first
        # ---------------------------------------------------------------
        saved = self.alerts_repository.save(
            rule_name=self.rule_name,
            source_ip=source_ip,
            severity=severity,
            event_count=event_count,
            window_start=window_start,
            window_end=window_end,
            triggered_at=triggered_at,
        )

        # Duplicate alert: database already contains this rule/IP/window.
        # Do NOT publish the same alert to Kafka again.
        if saved is None:
            logger.info(
                "Skipping duplicate brute-force alert "
                "source_ip=%s window_start=%s window_end=%s",
                source_ip,
                window_start,
                window_end,
            )
            return

        # ---------------------------------------------------------------
        # 2. Build canonical AlertEvent
        # ---------------------------------------------------------------
        alert_event = AlertEvent(
            rule_name=self.rule_name,
            description=(
                f"Detected {event_count} failed login attempts from "
                f"{source_ip} within a {window_end - window_start} window"
            ),
            severity=severity,
            source_ip=source_ip,
            source_event_ids=source_event_ids,
            triggered_at=triggered_at,
        )

        # ---------------------------------------------------------------
        # 3. Publish only after successful DB insert
        # ---------------------------------------------------------------
        self.alert_publisher.publish(
            alert_event.model_dump(mode="json"),
            topic=DEFAULT_ALERTS_TOPIC,
        )

        logger.info(
            "Brute-force alert created "
            "alert_id=%s source_ip=%s event_count=%d severity=%s",
            alert_event.alert_id,
            source_ip,
            event_count,
            severity,
        )

    def process_batch(
        self,
        batch_df: DataFrame,
        batch_id: int,
        config: RuleConfig,
    ) -> None:
        """
        Process already-aggregated alert rows.

        Important:
        detect() must NOT be called here. Spark window aggregation
        happens before foreachBatch so streaming state is preserved.
        """

        rows = batch_df.collect()

        logger.debug(
            "Processing brute-force alert batch_id=%s rows=%d",
            batch_id,
            len(rows),
        )

        for row in rows:
            self._handle_alert_row(row)

    def build_detection_stream(
        self,
        valid_events_stream_df: DataFrame,
    ) -> DataFrame:
        """
        Build the streaming DataFrame containing triggered alerts.

        Windowing happens here, while Spark is still managing the
        streaming query/state.
        """

        config = self.load_config()

        if not config.enabled:
            logger.info("Rule '%s' is disabled", self.rule_name)

            # Return an empty DataFrame with the expected alert schema.
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
        """
        Attach foreachBatch to the already-aggregated alert stream.
        """

        config = self.load_config()

        if not config.enabled:
            logger.info("Rule '%s' is disabled", self.rule_name)
            return None

        alert_stream = self.detect(
            valid_events_stream_df,
            config,
        )

        return (
            alert_stream.writeStream
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
            .outputMode("update")
            .start()
        )


def build_default_rule() -> BruteForceRule:
    """
    Construct the production brute-force rule using environment
    configuration.
    """

    from detection_engine.publishers.kafka_alert_publisher import (
        KafkaAlertPublisher,
    )

    bootstrap_servers = os.environ.get("KAFKA_BOOTSTRAP_SERVERS")

    if not bootstrap_servers:
        raise RuntimeError(
            "KAFKA_BOOTSTRAP_SERVERS environment variable is required"
        )

    return BruteForceRule(
        rules_repository=RulesRepository(),
        alerts_repository=AlertsRepository(),
        alert_publisher=KafkaAlertPublisher(
            bootstrap_servers=bootstrap_servers,
        ),
    )