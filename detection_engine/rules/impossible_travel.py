"""
Impossible-travel detection rule.

Detects the same username logging in successfully from two geographically
distant locations within a short time window -- a physically impossible
travel time between them, which usually means stolen or shared credentials.

Issue #14:
- Track the most recent successful_login per username (stateful, per key)
- Haversine distance between the two logins' GeoIP coordinates
- Alert when time delta < window_minutes (default 60) AND
  distance > threshold km (default 1000)
- Operates on enriched events (logs-enriched), not raw events
- PostgreSQL alert persistence
- Kafka alert publication
- duplicate-safe processing

MITRE ATT&CK: T1078 (Valid Accounts)

Dependency: requires GeoIP enrichment (latitude / longitude / country) on
the enriched stream. See the *_COL constants below for the exact column
names this rule reads.

Design
------
"Two most recent logins per user" is per-key state, which Spark SQL windows
do not express in streaming mode. This rule uses PySpark's
``applyInPandasWithState`` (the Python counterpart of Scala's
``flatMapGroupsWithState``; Spark >= 3.4, needs pandas + pyarrow):

* State per username = the single most recent login seen so far.
* Each new login is compared against that state, then replaces it.
* State expires via an event-time timeout once the last login is older than
  the window, because nothing older than the window can ever trigger.

The comparison logic itself lives in plain Python (``find_travel_anomalies``
and ``haversine_km``) so it is unit-testable without Spark.

Rule config mapping (RuleConfig is shared by every rule):
    threshold      -> minimum distance in km (alert when distance > threshold)
    window_minutes -> maximum time gap in minutes (alert when delta < window)
    slide_minutes  -> unused by this rule (kept for RuleConfig shape parity)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from math import atan2, cos, radians, sin, sqrt
from typing import Any, Iterator, Optional

from pyspark.sql import DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import (
    ArrayType,
    DoubleType,
    LongType,
    StringType,
    StructField,
    StructType,
)

from consumers.schemas import AlertEvent
from detection_engine.publishers.alert_publisher import AlertPublisher
from detection_engine.repositories.alerts_repository import AlertsRepository
from detection_engine.repositories.rules_repository import RulesRepository
from detection_engine.rules.base import BaseRule, RuleConfig

logger = logging.getLogger(__name__)

RULE_NAME = "impossible_travel"
MITRE_TECHNIQUE = "T1078"
ALERT_SEVERITY = "CRITICAL"

# threshold = km, window_minutes = maximum minutes between the two logins.
# slide_minutes is required by RuleConfig but is not used by this rule.
DEFAULT_CONFIG = RuleConfig(
    rule_name=RULE_NAME,
    threshold=1000,
    window_minutes=60,
    slide_minutes=60,
    enabled=True,
)

# --- Input columns on the enriched stream -------------------------------
# username / event_type / event_id / source_ip / event_timestamp come from
# the normalizer. The three geo_* columns are the GeoIP enrichment contract
# this rule depends on.
USERNAME_COL = "username"
EVENT_TYPE_COL = "event_type"
EVENT_ID_COL = "event_id"
SOURCE_IP_COL = "source_ip"
TIMESTAMP_COL = "event_timestamp"
COUNTRY_COL = "geo_country"
LATITUDE_COL = "geo_latitude"
LONGITUDE_COL = "geo_longitude"

SUCCESSFUL_LOGIN_EVENT_TYPE = "successful_login"
UNKNOWN_COUNTRY = "Unknown"

EARTH_RADIUS_KM = 6371.0088
MILLIS_PER_MINUTE = 60_000

# Alert.event_count is the generic count column shared by every rule.
# An impossible-travel alert is always produced by exactly two logins.
LOGINS_PER_ALERT = 2

# --- Spark schemas for the stateful step --------------------------------

STATE_SCHEMA = StructType(
    [
        StructField("last_ts_ms", LongType(), False),
        StructField("latitude", DoubleType(), False),
        StructField("longitude", DoubleType(), False),
        StructField("country", StringType(), True),
        StructField("event_id", StringType(), False),
        StructField("source_ip", StringType(), True),
    ]
)

ANOMALY_SCHEMA = StructType(
    [
        StructField("username", StringType(), False),
        StructField("login_1_country", StringType(), True),
        StructField("login_2_country", StringType(), True),
        StructField("login_1_ip", StringType(), True),
        StructField("login_2_ip", StringType(), True),
        StructField("login_1_ts_ms", LongType(), False),
        StructField("login_2_ts_ms", LongType(), False),
        StructField("time_delta_minutes", DoubleType(), False),
        StructField("distance_km", DoubleType(), False),
        StructField("source_event_ids", ArrayType(StringType()), False),
    ]
)

ANOMALY_COLUMNS = [
    field.name for field in ANOMALY_SCHEMA.fields
]


# ---------------------------------------------------------------------------
# Pure-Python detection logic
# ---------------------------------------------------------------------------


def haversine_km(
    lat1: float,
    lon1: float,
    lat2: float,
    lon2: float,
) -> float:
    """Return the great-circle distance in kilometres between two points."""

    phi1 = radians(lat1)
    phi2 = radians(lat2)

    delta_phi = radians(lat2 - lat1)
    delta_lambda = radians(lon2 - lon1)

    a = (
        sin(delta_phi / 2) ** 2
        + cos(phi1)
        * cos(phi2)
        * sin(delta_lambda / 2) ** 2
    )

    # Protect against tiny floating-point errors around 0 and 1.
    a = min(1.0, max(0.0, a))

    return EARTH_RADIUS_KM * 2 * atan2(
        sqrt(a),
        sqrt(1 - a),
    )


@dataclass(frozen=True)
class LoginRecord:
    """One successful login with its GeoIP location."""

    timestamp_ms: int
    latitude: float
    longitude: float
    country: str
    event_id: str
    source_ip: str


@dataclass(frozen=True)
class TravelAnomaly:
    """Two logins that could not physically have happened."""

    first: LoginRecord
    second: LoginRecord
    time_delta_minutes: float
    distance_km: float


def find_travel_anomalies(
    previous: Optional[LoginRecord],
    logins: list[LoginRecord],
    *,
    max_minutes: float,
    min_distance_km: float,
) -> tuple[list[TravelAnomaly], Optional[LoginRecord]]:
    """
    Compare new logins against the most recent known login for one user.

    Args:
        previous:
            The user's most recent login from earlier processing.

        logins:
            New successful logins for the same user, in any order.

        max_minutes:
            Alert only when the time gap is strictly below this value.

        min_distance_km:
            Alert only when the distance is strictly above this value.

    Returns:
        A tuple containing:
        - detected travel anomalies
        - newest login to retain as state

    Late/out-of-order logins are compared against the newest known login,
    but they do not replace newer state.

    A login with the same event_id as the newest known login is treated as
    a replay and is not compared with itself.
    """

    anomalies: list[TravelAnomaly] = []
    newest = previous

    for login in sorted(
        logins,
        key=lambda item: (
            item.timestamp_ms,
            item.event_id,
        ),
    ):
        if newest is not None and login.event_id != newest.event_id:
            if login.timestamp_ms >= newest.timestamp_ms:
                earlier = newest
                later = login
            else:
                earlier = login
                later = newest

            delta_minutes = (
                later.timestamp_ms - earlier.timestamp_ms
            ) / MILLIS_PER_MINUTE

            if delta_minutes < max_minutes:
                distance_km = haversine_km(
                    earlier.latitude,
                    earlier.longitude,
                    later.latitude,
                    later.longitude,
                )

                if distance_km > min_distance_km:
                    anomalies.append(
                        TravelAnomaly(
                            first=earlier,
                            second=later,
                            time_delta_minutes=delta_minutes,
                            distance_km=distance_km,
                        )
                    )

        if (
            newest is None
            or login.timestamp_ms >= newest.timestamp_ms
        ):
            newest = login

    return anomalies, newest


# ---------------------------------------------------------------------------
# Spark stateful function
# ---------------------------------------------------------------------------


def _state_to_record(state_tuple: tuple) -> LoginRecord:
    """Convert Spark state tuple into a LoginRecord."""

    (
        ts_ms,
        latitude,
        longitude,
        country,
        event_id,
        source_ip,
    ) = state_tuple

    return LoginRecord(
        timestamp_ms=int(ts_ms),
        latitude=float(latitude),
        longitude=float(longitude),
        country=country or UNKNOWN_COUNTRY,
        event_id=str(event_id),
        source_ip=str(source_ip),
    )


def _record_to_state(record: LoginRecord) -> tuple:
    """Convert a LoginRecord into the Spark state representation."""

    return (
        record.timestamp_ms,
        record.latitude,
        record.longitude,
        record.country,
        record.event_id,
        record.source_ip,
    )


def make_state_function(
    max_minutes: float,
    min_distance_km: float,
):
    """
    Build the function passed to ``applyInPandasWithState``.

    Spark calls this once per username per micro-batch and again when
    event-time state timeout occurs.
    """

    window_ms = int(
        max_minutes * MILLIS_PER_MINUTE
    )

    def update_user(
        key,
        pdf_iter,
        state,
    ) -> Iterator[Any]:
        import pandas as pd

        # If the state timed out, nothing older than the configured
        # travel window can produce a useful comparison anymore.
        if state.hasTimedOut:
            state.remove()
            yield pd.DataFrame(
                columns=ANOMALY_COLUMNS
            )
            return

        username = str(key[0])

        previous = (
            _state_to_record(state.get)
            if state.exists
            else None
        )

        logins: list[LoginRecord] = []

        for pdf in pdf_iter:
            for rec in pdf.to_dict("records"):
                logins.append(
                    LoginRecord(
                        timestamp_ms=int(
                            rec["event_ts_ms"]
                        ),
                        latitude=float(
                            rec["latitude"]
                        ),
                        longitude=float(
                            rec["longitude"]
                        ),
                        country=(
                            rec["country"]
                            or UNKNOWN_COUNTRY
                        ),
                        event_id=str(
                            rec["event_id"]
                        ),
                        source_ip=str(
                            rec["source_ip"]
                        ),
                    )
                )

        anomalies, newest = find_travel_anomalies(
            previous,
            logins,
            max_minutes=max_minutes,
            min_distance_km=min_distance_km,
        )

        if newest is not None:
            state.update(
                _record_to_state(newest)
            )

            timeout_timestamp = (
                newest.timestamp_ms + window_ms
            )

            # Do not schedule a timeout before Spark's current
            # watermark.
            state.setTimeoutTimestamp(
                max(
                    timeout_timestamp,
                    state.getCurrentWatermarkMs(),
                )
            )

        yield pd.DataFrame(
            [
                {
                    "username": username,
                    "login_1_country": (
                        anomaly.first.country
                    ),
                    "login_2_country": (
                        anomaly.second.country
                    ),
                    "login_1_ip": (
                        anomaly.first.source_ip
                    ),
                    "login_2_ip": (
                        anomaly.second.source_ip
                    ),
                    "login_1_ts_ms": (
                        anomaly.first.timestamp_ms
                    ),
                    "login_2_ts_ms": (
                        anomaly.second.timestamp_ms
                    ),
                    "time_delta_minutes": (
                        anomaly.time_delta_minutes
                    ),
                    "distance_km": (
                        anomaly.distance_km
                    ),
                    "source_event_ids": [
                        anomaly.first.event_id,
                        anomaly.second.event_id,
                    ],
                }
                for anomaly in anomalies
            ],
            columns=ANOMALY_COLUMNS,
        )

    return update_user


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------


class ImpossibleTravelRule(BaseRule):
    """
    Detect the same user logging in from two locations too far apart
    to have travelled between in the elapsed time.

    The stateful detection step runs on the streaming DataFrame.
    ``foreachBatch`` is used only for persistence and publication.
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
        Load configuration from the rules database.

        A default is retained for isolated unit tests where no repository
        is provided.
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
        Build the stateful impossible-travel detection.

        Returns one row per finding containing:
        - username
        - login countries
        - login IPs
        - login timestamps
        - time delta
        - distance
        - source event IDs
        """

        if (
            config.window_minutes <= 0
            or config.threshold <= 0
        ):
            raise ValueError(
                "impossible_travel requires positive "
                "threshold (km) and window_minutes; "
                f"got threshold={config.threshold}, "
                f"window_minutes={config.window_minutes}"
            )

        watermark_delay = (
            f"{config.window_minutes} minutes"
        )

        valid_logins = events_df.filter(
            (F.col(EVENT_TYPE_COL)
             == SUCCESSFUL_LOGIN_EVENT_TYPE)
            & F.col(USERNAME_COL).isNotNull()
            & (F.trim(F.col(USERNAME_COL)) != "")
            & F.col(EVENT_ID_COL).isNotNull()
            & F.col(SOURCE_IP_COL).isNotNull()
            & F.col(TIMESTAMP_COL).isNotNull()
            & F.col(LATITUDE_COL).between(
                -90.0,
                90.0,
            )
            & F.col(LONGITUDE_COL).between(
                -180.0,
                180.0,
            )
        )

        stateful_input = (
            valid_logins
            .withWatermark(
                TIMESTAMP_COL,
                watermark_delay,
            )
            .select(
                F.col(USERNAME_COL).alias(
                    "username"
                ),
                F.col(EVENT_ID_COL)
                .cast("string")
                .alias("event_id"),
                F.col(SOURCE_IP_COL)
                .cast("string")
                .alias("source_ip"),
                F.col(COUNTRY_COL)
                .cast("string")
                .alias("country"),
                F.col(LATITUDE_COL)
                .cast("double")
                .alias("latitude"),
                F.col(LONGITUDE_COL)
                .cast("double")
                .alias("longitude"),
                F.col(TIMESTAMP_COL),
                (
                    F.col(TIMESTAMP_COL)
                    .cast("double")
                    * 1000
                )
                .cast("long")
                .alias("event_ts_ms"),
            )
        )

        anomalies = (
            stateful_input
            .groupBy("username")
            .applyInPandasWithState(
                make_state_function(
                    max_minutes=config.window_minutes,
                    min_distance_km=config.threshold,
                ),
                outputStructType=ANOMALY_SCHEMA,
                stateStructType=STATE_SCHEMA,
                outputMode="Update",
                timeoutConf="EventTimeTimeout",
            )
        )

        return anomalies.select(
            F.col("username"),
            F.col("login_1_country"),
            F.col("login_2_country"),
            F.col("login_1_ip"),
            F.col("login_2_ip"),
            (
                F.col("login_1_ts_ms") / 1000
            )
            .cast("timestamp")
            .alias("window_start"),
            (
                F.col("login_2_ts_ms") / 1000
            )
            .cast("timestamp")
            .alias("window_end"),
            F.col("time_delta_minutes"),
            F.col("distance_km"),
            F.col("source_event_ids"),
        )

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        """Return a timezone-aware UTC datetime."""

        if value.tzinfo is None:
            return value.replace(
                tzinfo=timezone.utc
            )

        return value.astimezone(
            timezone.utc
        )

    def _handle_alert_row(self, row: Any) -> None:
        """
        Persist one impossible-travel finding and publish it to Kafka.

        The AlertEvent is built and validated before the database write.
        This prevents an invalid alert from leaving a persisted record
        that cannot subsequently be published.
        """

        if self.alerts_repository is None:
            raise RuntimeError(
                "AlertsRepository is required to save alerts"
            )

        if self.alert_publisher is None:
            raise RuntimeError(
                "AlertPublisher is required to publish alerts"
            )

        username = str(
            row["username"]
        )

        login_1_country = (
            row["login_1_country"]
            or UNKNOWN_COUNTRY
        )

        login_2_country = (
            row["login_2_country"]
            or UNKNOWN_COUNTRY
        )

        login_1_ip = str(
            row["login_1_ip"]
        )

        login_2_ip = str(
            row["login_2_ip"]
        )

        time_delta_minutes = float(
            row["time_delta_minutes"]
        )

        distance_km = float(
            row["distance_km"]
        )

        window_start = self._as_utc(
            row["window_start"]
        )

        window_end = self._as_utc(
            row["window_end"]
        )

        triggered_at = datetime.now(
            timezone.utc
        )

        source_event_ids = [
            str(event_id)
            for event_id in (
                row["source_event_ids"]
                or []
            )
        ]

        # An impossible-travel finding must always reference
        # exactly the two login events that produced it.
        if len(source_event_ids) != LOGINS_PER_ALERT:
            logger.warning(
                "Impossible-travel alert requires "
                "exactly %d source event IDs, got %d "
                "username=%s",
                LOGINS_PER_ALERT,
                len(source_event_ids),
                username,
            )
            return

        # ---------------------------------------------------------------
        # Build and validate the alert BEFORE persistence.
        # ---------------------------------------------------------------

        alert_event = AlertEvent(
            rule_name=self.rule_name,
            description=(
                f"Impossible travel for user "
                f"'{username}': successful login "
                f"from {login_1_country} "
                f"({login_1_ip}) then from "
                f"{login_2_country} "
                f"({login_2_ip}); "
                f"time_delta_minutes="
                f"{time_delta_minutes:.1f}, "
                f"distance_km="
                f"{distance_km:.0f} "
                f"(MITRE {MITRE_TECHNIQUE})"
            ),
            severity=ALERT_SEVERITY,
            source_ip=login_2_ip,
            source_event_ids=source_event_ids,
            triggered_at=triggered_at,

            # Structured Issue #14 fields.
            username=username,
            login_1_country=login_1_country,
            login_2_country=login_2_country,
            time_delta_minutes=time_delta_minutes,
            distance_km=distance_km,
        )

        # ---------------------------------------------------------------
        # Persist first.
        # ---------------------------------------------------------------

        saved = self.alerts_repository.save(
            rule_name=self.rule_name,
            source_ip=login_2_ip,
            severity=ALERT_SEVERITY,
            event_count=LOGINS_PER_ALERT,
            window_start=window_start,
            window_end=window_end,
            triggered_at=triggered_at,
        )

        if saved is None:
            logger.info(
                "Skipping duplicate impossible-travel "
                "alert username=%s "
                "window_start=%s window_end=%s",
                username,
                window_start,
                window_end,
            )
            return

        # ---------------------------------------------------------------
        # Publish only after successful persistence.
        # The publisher already knows its Kafka topic.
        # ---------------------------------------------------------------

        self.alert_publisher.publish(
            alert_event.model_dump(
                mode="json"
            )
        )

        logger.info(
            "Impossible-travel alert created "
            "alert_id=%s username=%s %s->%s "
            "time_delta_minutes=%.1f "
            "distance_km=%.0f severity=%s",
            alert_event.alert_id,
            username,
            login_1_country,
            login_2_country,
            time_delta_minutes,
            distance_km,
            ALERT_SEVERITY,
        )

    def process_batch(
        self,
        batch_df: DataFrame,
        batch_id: int,
        config: RuleConfig,
    ) -> None:
        """
        Process already-detected alert rows.

        ``detect()`` must NOT be called here because the stateful step
        needs to run on the streaming DataFrame so state survives
        micro-batches.
        """

        rows = batch_df.collect()

        logger.debug(
            "Processing impossible-travel "
            "batch_id=%s rows=%d",
            batch_id,
            len(rows),
        )

        for row in rows:
            self._handle_alert_row(row)

    def build_detection_stream(
        self,
        valid_events_stream_df: DataFrame,
    ) -> DataFrame:
        """Build the streaming DataFrame containing triggered alerts."""

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
        """Attach foreachBatch to the stateful alert stream."""

        config = self.load_config()

        if not config.enabled:
            logger.info(
                "Rule '%s' is disabled",
                self.rule_name,
            )
            return None

        alert_stream = self.detect(
            valid_events_stream_df,
            config,
        )

        return (
            alert_stream.writeStream
            .foreachBatch(
                lambda batch_df, batch_id:
                self.process_batch(
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


def build_default_rule() -> ImpossibleTravelRule:
    """
    Construct the production impossible-travel rule using
    environment configuration.
    """

    from api.database import SessionLocal

    from detection_engine.publishers.kafka_alert_publisher import (
        KafkaAlertPublisher,
    )

    bootstrap_servers = os.environ.get(
        "KAFKA_BOOTSTRAP_SERVERS"
    )

    if not bootstrap_servers:
        raise RuntimeError(
            "KAFKA_BOOTSTRAP_SERVERS environment variable "
            "is required"
        )

    return ImpossibleTravelRule(
        rules_repository=RulesRepository(
            session_factory=SessionLocal
        ),
        alerts_repository=AlertsRepository(
            session_factory=SessionLocal
        ),
        alert_publisher=KafkaAlertPublisher(
            bootstrap_servers=bootstrap_servers,
        ),
    )