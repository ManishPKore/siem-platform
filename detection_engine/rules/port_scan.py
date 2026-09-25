"""
Port-scan detection rule.

Detects a single source IP contacting an unusually high number of
distinct destination ports on firewall events within a short, fixed
(tumbling) time window — a classic network service discovery / port
scan indicator.

Issue #13:
- 2-minute tumbling window (non-overlapping, unlike brute_force's
  sliding window)
- countDistinct(dest_port) per source_ip
- configurable threshold, default 20 distinct ports
- firewall events only (source == "firewall")
- PostgreSQL alert persistence
- Kafka alert publication
- duplicate-safe processing

MITRE ATT&CK: T1046 (Network Service Discovery)
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from consumers.schemas import AlertEvent
from detection_engine.publishers.alert_publisher import AlertPublisher
from detection_engine.repositories.alerts_repository import AlertsRepository
from detection_engine.repositories.rules_repository import RulesRepository
from detection_engine.rules.base import BaseRule, RuleConfig

logger = logging.getLogger(__name__)

RULE_NAME = "port_scan"
MITRE_TECHNIQUE = "T1046"

# Port scanning is classified as HIGH severity outright, regardless of how
# far over the threshold a given window lands (unlike brute_force, which
# scales severity with event count via severity_for_count()). This matches
# the acceptance criteria's fixed severity="HIGH".
ALERT_SEVERITY = "HIGH"

# window_minutes == slide_minutes here purely to satisfy RuleConfig's
# required field (it's shared with brute_force and the `rules` DB table
# schema). IMPORTANT: detect() below does NOT read config.slide_minutes.
# Port scanning uses a true, non-overlapping tumbling window
# (F.window(col, window_duration) with no slideDuration argument), not a
# sliding one — do not infer sliding behavior from this default.
DEFAULT_CONFIG = RuleConfig(
    rule_name=RULE_NAME,
    threshold=20,
    window_minutes=2,
    slide_minutes=2,
    enabled=True,
)

TIMESTAMP_COL = "event_timestamp"
SOURCE_IP_COL = "source_ip"
SOURCE_COL = "source"
DEST_PORT_COL = "dest_port"
EVENT_ID_COL = "event_id"

FIREWALL_SOURCE = "firewall"

# Alert.event_count (api/models/alert.py) is a generic "count that
# triggered this alert" column shared across every rule. For port_scan
# that value IS the distinct destination-port count — there is no
# separate distinct_port_count column on the alerts table, so we
# intentionally write it through the existing event_count field rather
# than adding a new DB column. If a dedicated distinct_port_count column
# (or a generic JSON metadata column shared across rules) is added to
# api/models/alert.py later, update _handle_alert_row() to use it instead.
EVENT_COUNT_FIELD = "event_count"


class PortScanRule(BaseRule):
    """
    Detect a single source IP hitting many distinct destination ports
    within a 2-minute tumbling window.

    As with BruteForceRule, the Spark aggregation happens on the
    streaming DataFrame itself (outside foreachBatch) so windowed
    state is preserved across micro-batches.
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

        Returns one row per source IP / tumbling window whose distinct
        destination-port count exceeds the configured threshold.
        """

        window_duration = f"{config.window_minutes} minutes"

        # Firewall events only, and defensively drop any row with a null
        # dest_port (should not occur once normalization/required-field
        # filtering is correct, but countDistinct() would silently ignore
        # nulls anyway — this just makes the intent explicit).
        firewall_events = events_df.filter(
            (F.col(SOURCE_COL) == FIREWALL_SOURCE)
            & F.col(DEST_PORT_COL).isNotNull()
        )

        # event_id is retained so AlertEvent can reference the source
        # events that caused the alert, same as brute_force.
        #
        # F.window(col, window_duration) with NO slideDuration argument
        # produces non-overlapping (tumbling) windows — this is the key
        # difference from brute_force's F.window(col, window, slide).
        windowed_counts = (
            firewall_events
            .withWatermark(TIMESTAMP_COL, window_duration)
            .groupBy(
                F.window(F.col(TIMESTAMP_COL), window_duration),
                F.col(SOURCE_IP_COL),
            )
            .agg(
                F.countDistinct(DEST_PORT_COL).alias("distinct_port_count"),
                F.collect_set(EVENT_ID_COL).alias("source_event_ids"),
            )
        )

        return (
            windowed_counts
            .filter(F.col("distinct_port_count") > config.threshold)
            .select(
                F.col(SOURCE_IP_COL).alias("source_ip"),
                F.col("distinct_port_count"),
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
        distinct_port_count = int(row["distinct_port_count"])

        window_start = self._as_utc(row["window_start"])
        window_end = self._as_utc(row["window_end"])

        triggered_at = datetime.now(timezone.utc)

        source_event_ids = [
            str(event_id)
            for event_id in (row["source_event_ids"] or [])
        ]

        if not source_event_ids:
            logger.warning(
                "Port-scan alert has no source event IDs "
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
        #
        # See EVENT_COUNT_FIELD note above: distinct_port_count is
        # deliberately written through the generic event_count column.
        # ---------------------------------------------------------------
        saved = self.alerts_repository.save(
            rule_name=self.rule_name,
            source_ip=source_ip,
            severity=ALERT_SEVERITY,
            **{EVENT_COUNT_FIELD: distinct_port_count},
            window_start=window_start,
            window_end=window_end,
            triggered_at=triggered_at,
        )

        # Duplicate alert: database already contains this rule/IP/window.
        # Do NOT publish the same alert to Kafka again.
        if saved is None:
            logger.info(
                "Skipping duplicate port-scan alert "
                "source_ip=%s window_start=%s window_end=%s",
                source_ip,
                window_start,
                window_end,
            )
            return

        # ---------------------------------------------------------------
        # 2. Build canonical AlertEvent
        #
        # AlertEvent (consumers/schemas.py) has extra="forbid" and no
        # distinct_port_count field, so the count is only machine-readable
        # via the DB alert (event_count) — not on the Kafka payload. It IS
        # included in the human-readable description below. If downstream
        # consumers of the `alerts` topic need it as a structured field,
        # that requires widening the shared AlertEvent schema, which
        # affects every rule and should be a separate, deliberate change.
        # ---------------------------------------------------------------
        alert_event = AlertEvent(
            rule_name=self.rule_name,
            description=(
                f"Detected port scan from {source_ip}: "
                f"{distinct_port_count} distinct destination ports "
                f"contacted within a {window_end - window_start} window "
                f"(MITRE {MITRE_TECHNIQUE})"
            ),
            severity=ALERT_SEVERITY,
            source_ip=source_ip,
            source_event_ids=source_event_ids,
            triggered_at=triggered_at,
        )

        # ---------------------------------------------------------------
        # 3. Publish only after successful DB insert.
        #
        # AlertPublisher.publish(alert_dict) takes the dict only — there
        # is no `topic` parameter on either the Protocol or
        # KafkaAlertPublisher (topic is bound at publisher construction
        # time instead). Passing topic= here would raise a TypeError
        # against the real Kafka implementation.
        # ---------------------------------------------------------------
        self.alert_publisher.publish(
            alert_event.model_dump(mode="json"),
        )

        logger.info(
            "Port-scan alert created "
            "alert_id=%s source_ip=%s distinct_port_count=%d severity=%s",
            alert_event.alert_id,
            source_ip,
            distinct_port_count,
            ALERT_SEVERITY,
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
            "Processing port-scan alert batch_id=%s rows=%d",
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


def build_default_rule() -> PortScanRule:
    """
    Construct the production port-scan rule using environment
    configuration.

    TODO(unverified): AlertsRepository requires a `session_factory`
    (see detection_engine/repositories/alerts_repository.py) and
    RulesRepository's constructor is not yet confirmed in this codebase.
    Do not deploy this function until both are wired to the real session
    factory (likely from api/database.py) — see the note left in the
    chat; this mirrors an existing, equally-unverified gap in
    detection_engine/rules/brute_force.py::build_default_rule().
    """

    from detection_engine.publishers.kafka_alert_publisher import (
        KafkaAlertPublisher,
    )

    bootstrap_servers = os.environ.get("KAFKA_BOOTSTRAP_SERVERS")

    if not bootstrap_servers:
        raise RuntimeError(
            "KAFKA_BOOTSTRAP_SERVERS environment variable is required"
        )

    return PortScanRule(
        rules_repository=RulesRepository(),
        alerts_repository=AlertsRepository(),
        alert_publisher=KafkaAlertPublisher(
            bootstrap_servers=bootstrap_servers,
        ),
    )