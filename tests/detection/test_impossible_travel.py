"""
Tests for the ImpossibleTravelRule detection rule.

Covers Issue #14:

- Same user: Mumbai then New York within 10 minutes -> CRITICAL alert.
- Same user: Mumbai then Pune (~120 km) within 10 minutes -> no alert.
- Same user: Mumbai then New York 5 hours apart -> no alert.
- Alert contains username, login_1_country, login_2_country,
  time_delta_minutes, distance_km and severity="CRITICAL".
- Only successful_login events with GeoIP coordinates are considered.
- Users are tracked independently and state survives micro-batches.
- Thresholds come from the rules repository.
- Persistence / publication / duplicate handling.

Layers:
1. Haversine + comparison logic -- plain Python, no Spark.
2. detect() -- a real Spark streaming query over mock enriched events.
3. process_batch() side effects -- mocked repository and publisher.
"""

import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest

pyspark = pytest.importorskip("pyspark")
pytest.importorskip("pandas")
pytest.importorskip("pyarrow")

from pyspark.sql import Row, SparkSession
from pyspark.sql.types import (
    DoubleType,
    StringType,
    StructField,
    StructType,
    TimestampType,
)

from detection_engine.rules.base import RuleConfig
from detection_engine.rules.impossible_travel import (
    ALERT_SEVERITY,
    ImpossibleTravelRule,
    LoginRecord,
    find_travel_anomalies,
    haversine_km,
)


# ---------------------------------------------------------------------------
# Locations / constants
# ---------------------------------------------------------------------------

MUMBAI = (
    "India",
    19.07,
    72.87,
    "49.36.10.1",
)

PUNE = (
    "India",
    18.52,
    73.86,
    "49.36.20.2",
)

NEW_YORK = (
    "United States",
    40.71,
    -74.00,
    "203.0.113.30",
)

BASE_TIME = datetime(
    2026,
    1,
    1,
    12,
    0,
    0,
    tzinfo=timezone.utc,
)

MINUTE_MS = 60_000

EVENT_SCHEMA = StructType(
    [
        StructField(
            "event_id",
            StringType(),
            True,
        ),
        StructField(
            "username",
            StringType(),
            True,
        ),
        StructField(
            "source_ip",
            StringType(),
            True,
        ),
        StructField(
            "event_type",
            StringType(),
            True,
        ),
        StructField(
            "geo_country",
            StringType(),
            True,
        ),
        StructField(
            "geo_latitude",
            DoubleType(),
            True,
        ),
        StructField(
            "geo_longitude",
            DoubleType(),
            True,
        ),
        StructField(
            "event_timestamp",
            TimestampType(),
            True,
        ),
    ]
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def spark():
    """One local Spark session for the whole suite."""

    session = (
        SparkSession.builder
        .master("local[2]")
        .appName("test_impossible_travel")
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
    """Default impossible-travel configuration."""

    return RuleConfig(
        rule_name="impossible_travel",
        threshold=1000,
        window_minutes=60,
        slide_minutes=60,
        enabled=True,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def build_rule(
    alerts_repository=None,
    alert_publisher=None,
    rules_repository=None,
):
    return ImpossibleTravelRule(
        rules_repository=rules_repository,
        alerts_repository=alerts_repository,
        alert_publisher=alert_publisher,
    )


def make_login(
    location,
    minutes,
    key="e",
):
    """Create a LoginRecord at `minutes` after BASE_TIME."""

    country, lat, lon, ip = location

    return LoginRecord(
        timestamp_ms=(
            int(BASE_TIME.timestamp() * 1000)
            + int(minutes * MINUTE_MS)
        ),
        latitude=lat,
        longitude=lon,
        country=country,
        event_id=str(
            uuid.uuid5(
                uuid.NAMESPACE_DNS,
                f"{key}-{location[0]}-{minutes}",
            )
        ),
        source_ip=ip,
    )


def enriched_event(
    username,
    location,
    minutes,
    event_type="successful_login",
    latitude=None,
    longitude=None,
    key="e",
):
    """Create a mock enriched event tuple."""

    country, lat, lon, ip = location

    return (
        str(
            uuid.uuid5(
                uuid.NAMESPACE_DNS,
                f"{key}-{username}-{country}-{minutes}",
            )
        ),
        username,
        ip,
        event_type,
        country,
        lat if latitude is None else latitude,
        lon if longitude is None else longitude,
        BASE_TIME + timedelta(
            minutes=minutes
        ),
    )


def run_detection(
    spark,
    tmp_path,
    batches,
    config,
):
    """
    Run detect() as a real streaming query over mock enriched events.

    Each element of `batches` is written as its own input file.
    maxFilesPerTrigger=1 makes each file a separate micro-batch so
    multiple batches exercise the per-user state carried between them.
    """

    source_dir = (
        tmp_path
        / f"src-{uuid.uuid4().hex}"
    )

    source_dir.mkdir()

    # Write the mock input files with Python instead of Spark's
    # DataFrameWriter. On Windows, Spark's Hadoop filesystem writer tries
    # to call winutils.exe for filesystem permission handling. Creating
    # the JSON files directly avoids that Windows-only dependency while
    # preserving the real file-based Structured Streaming source and
    # maxFilesPerTrigger micro-batch behavior.
    for batch_index, batch in enumerate(batches):
        file_path = source_dir / f"batch-{batch_index:04d}.json"

        with file_path.open("w", encoding="utf-8") as file:
            for row in batch:
                event = {
                    "event_id": row[0],
                    "username": row[1],
                    "source_ip": row[2],
                    "event_type": row[3],
                    "geo_country": row[4],
                    "geo_latitude": row[5],
                    "geo_longitude": row[6],
                    "event_timestamp": (
                        row[7].isoformat()
                        if row[7] is not None
                        else None
                    ),
                }
                file.write(json.dumps(event) + "\n")

    stream_df = (
        spark.readStream
        .schema(EVENT_SCHEMA)
        .option(
            "maxFilesPerTrigger",
            1,
        )
        .json(str(source_dir))
    )

    alerts_df = build_rule().detect(
        stream_df,
        config,
    )

    table = (
        f"alerts_{uuid.uuid4().hex}"
    )

    query = (
        alerts_df.writeStream
        .format("memory")
        .queryName(table)
        .outputMode("update")
        .option(
            "checkpointLocation",
            str(
                tmp_path
                / f"ckpt-{uuid.uuid4().hex}"
            ),
        )
        .trigger(availableNow=True)
        .start()
    )

    query.awaitTermination()

    return spark.table(table).collect()


def alert_row(**overrides):
    """Create a Row shaped like detect() output."""

    values = {
        "username": "alice",
        "login_1_country": "India",
        "login_2_country": "United States",
        "login_1_ip": "49.36.10.1",
        "login_2_ip": "203.0.113.30",
        # Spark/PySpark on Windows can reinterpret timezone-aware Python
        # datetimes using the host timezone when creating a DataFrame.
        # Keep these fixture timestamps naive; ImpossibleTravelRule._as_utc()
        # explicitly interprets naive timestamps as UTC.
        "window_start": BASE_TIME.replace(tzinfo=None),
        "window_end": (
            BASE_TIME
            + timedelta(minutes=10)
        ).replace(tzinfo=None),
        "time_delta_minutes": 10.0,
        "distance_km": 12540.0,
        "source_event_ids": [
            str(uuid.uuid4()),
            str(uuid.uuid4()),
        ],
    }

    values.update(overrides)

    return Row(**values)


# ---------------------------------------------------------------------------
# 1. Haversine
# ---------------------------------------------------------------------------


class TestHaversine:

    def test_mumbai_to_new_york(self):
        distance = haversine_km(
            19.07,
            72.87,
            40.71,
            -74.00,
        )

        assert 12_400 < distance < 12_700

    def test_mumbai_to_pune_is_short(self):
        distance = haversine_km(
            19.07,
            72.87,
            18.52,
            73.86,
        )

        assert 100 < distance < 200

    def test_same_point_is_zero(self):
        assert haversine_km(
            19.07,
            72.87,
            19.07,
            72.87,
        ) == pytest.approx(0.0)

    def test_distance_is_symmetric(self):
        forward = haversine_km(
            19.07,
            72.87,
            40.71,
            -74.00,
        )

        backward = haversine_km(
            40.71,
            -74.00,
            19.07,
            72.87,
        )

        assert forward == pytest.approx(
            backward
        )

    def test_antipodal_points_do_not_raise(self):
        distance = haversine_km(
            0.0,
            0.0,
            0.0,
            180.0,
        )

        assert distance == pytest.approx(
            20_015,
            rel=0.01,
        )


# ---------------------------------------------------------------------------
# 2. Comparison logic
# ---------------------------------------------------------------------------


class TestFindTravelAnomalies:

    def run(
        self,
        previous,
        logins,
        **overrides,
    ):
        kwargs = {
            "max_minutes": 60,
            "min_distance_km": 1000,
        }

        kwargs.update(overrides)

        return find_travel_anomalies(
            previous,
            logins,
            **kwargs,
        )

    def test_mumbai_then_new_york_in_10_minutes_alerts(
        self,
    ):
        anomalies, _ = self.run(
            None,
            [
                make_login(MUMBAI, 0),
                make_login(NEW_YORK, 10),
            ],
        )

        assert len(anomalies) == 1
        assert (
            anomalies[0].first.country
            == "India"
        )
        assert (
            anomalies[0].second.country
            == "United States"
        )
        assert (
            anomalies[0].time_delta_minutes
            == pytest.approx(10.0)
        )
        assert (
            anomalies[0].distance_km
            > 1000
        )

    def test_mumbai_then_pune_in_10_minutes_does_not_alert(
        self,
    ):
        anomalies, _ = self.run(
            None,
            [
                make_login(MUMBAI, 0),
                make_login(PUNE, 10),
            ],
        )

        assert anomalies == []

    def test_mumbai_then_new_york_5_hours_apart_does_not_alert(
        self,
    ):
        anomalies, _ = self.run(
            None,
            [
                make_login(MUMBAI, 0),
                make_login(NEW_YORK, 300),
            ],
        )

        assert anomalies == []

    def test_exactly_60_minutes_does_not_alert(
        self,
    ):
        anomalies, _ = self.run(
            None,
            [
                make_login(MUMBAI, 0),
                make_login(NEW_YORK, 60),
            ],
        )

        assert anomalies == []

    def test_59_minutes_alerts(self):
        anomalies, _ = self.run(
            None,
            [
                make_login(MUMBAI, 0),
                make_login(NEW_YORK, 59),
            ],
        )

        assert len(anomalies) == 1

    def test_distance_exactly_at_threshold_does_not_alert(
        self,
    ):
        exact = haversine_km(
            19.07,
            72.87,
            40.71,
            -74.00,
        )

        anomalies, _ = self.run(
            None,
            [
                make_login(MUMBAI, 0),
                make_login(NEW_YORK, 10),
            ],
            min_distance_km=exact,
        )

        assert anomalies == []

    def test_single_login_returns_it_as_state(
        self,
    ):
        login = make_login(
            MUMBAI,
            0,
        )

        anomalies, newest = self.run(
            None,
            [login],
        )

        assert anomalies == []
        assert newest == login

    def test_previous_state_is_used_for_comparison(
        self,
    ):
        previous = make_login(
            MUMBAI,
            0,
        )

        anomalies, newest = self.run(
            previous,
            [
                make_login(
                    NEW_YORK,
                    10,
                )
            ],
        )

        assert len(anomalies) == 1
        assert (
            newest.country
            == "United States"
        )

    def test_input_order_does_not_matter(
        self,
    ):
        anomalies, newest = self.run(
            None,
            [
                make_login(
                    NEW_YORK,
                    10,
                ),
                make_login(
                    MUMBAI,
                    0,
                ),
            ],
        )

        assert len(anomalies) == 1
        assert (
            anomalies[0].first.country
            == "India"
        )
        assert (
            newest.country
            == "United States"
        )

    def test_only_the_most_recent_login_is_compared(
        self,
    ):
        """Mumbai -> Pune -> New York compares New York with Pune."""

        anomalies, _ = self.run(
            None,
            [
                make_login(MUMBAI, 0),
                make_login(PUNE, 5),
                make_login(NEW_YORK, 10),
            ],
        )

        assert len(anomalies) == 1
        assert (
            anomalies[0].first.source_ip
            == PUNE[3]
        )
        assert (
            anomalies[0].second.source_ip
            == NEW_YORK[3]
        )

    def test_late_login_is_compared_but_does_not_replace_state(
        self,
    ):
        previous = make_login(
            NEW_YORK,
            10,
        )

        anomalies, newest = self.run(
            previous,
            [
                make_login(
                    MUMBAI,
                    0,
                )
            ],
        )

        assert len(anomalies) == 1
        assert (
            anomalies[0].first.country
            == "India"
        )
        assert (
            anomalies[0].second.country
            == "United States"
        )
        assert newest == previous

    def test_replayed_event_is_not_compared_with_itself(
        self,
    ):
        login = make_login(
            MUMBAI,
            0,
        )

        anomalies, newest = self.run(
            login,
            [login],
        )

        assert anomalies == []
        assert newest == login


# ---------------------------------------------------------------------------
# 3. detect() over a real streaming query
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason=(
        "Spark Structured Streaming file-source tests require "
        "Hadoop local filesystem support; run them under Linux/Docker/WSL."
    ),
)
class TestDetectStreaming:

    def test_mumbai_then_new_york_in_10_minutes_triggers_alert(
        self,
        spark,
        tmp_path,
        base_config,
    ):
        rows = run_detection(
            spark,
            tmp_path,
            [
                [
                    enriched_event(
                        "alice",
                        MUMBAI,
                        0,
                    ),
                    enriched_event(
                        "alice",
                        NEW_YORK,
                        10,
                    ),
                ]
            ],
            base_config,
        )

        assert len(rows) == 1

        alert = rows[0]

        assert alert["username"] == "alice"
        assert (
            alert["login_1_country"]
            == "India"
        )
        assert (
            alert["login_2_country"]
            == "United States"
        )
        assert (
            alert["time_delta_minutes"]
            == pytest.approx(10.0)
        )
        assert (
            12_400
            < alert["distance_km"]
            < 12_700
        )

        assert (
            alert["login_1_ip"]
            == MUMBAI[3]
        )
        assert (
            alert["login_2_ip"]
            == NEW_YORK[3]
        )

        assert len(
            alert["source_event_ids"]
        ) == 2

        assert (
            alert["window_end"]
            - alert["window_start"]
        ) == timedelta(minutes=10)

    def test_mumbai_then_pune_in_10_minutes_does_not_trigger(
        self,
        spark,
        tmp_path,
        base_config,
    ):
        rows = run_detection(
            spark,
            tmp_path,
            [
                [
                    enriched_event(
                        "alice",
                        MUMBAI,
                        0,
                    ),
                    enriched_event(
                        "alice",
                        PUNE,
                        10,
                    ),
                ]
            ],
            base_config,
        )

        assert rows == []

    def test_mumbai_then_new_york_5_hours_apart_does_not_trigger(
        self,
        spark,
        tmp_path,
        base_config,
    ):
        rows = run_detection(
            spark,
            tmp_path,
            [
                [
                    enriched_event(
                        "alice",
                        MUMBAI,
                        0,
                    ),
                    enriched_event(
                        "alice",
                        NEW_YORK,
                        300,
                    ),
                ]
            ],
            base_config,
        )

        assert rows == []

    def test_state_is_carried_across_micro_batches(
        self,
        spark,
        tmp_path,
        base_config,
    ):
        rows = run_detection(
            spark,
            tmp_path,
            [
                [
                    enriched_event(
                        "alice",
                        MUMBAI,
                        0,
                    )
                ],
                [
                    enriched_event(
                        "alice",
                        NEW_YORK,
                        10,
                    )
                ],
            ],
            base_config,
        )

        assert len(rows) == 1
        assert (
            rows[0]["login_1_country"]
            == "India"
        )
        assert (
            rows[0]["login_2_country"]
            == "United States"
        )

    def test_users_are_tracked_independently(
        self,
        spark,
        tmp_path,
        base_config,
    ):
        rows = run_detection(
            spark,
            tmp_path,
            [
                [
                    enriched_event(
                        "alice",
                        MUMBAI,
                        0,
                    ),
                    enriched_event(
                        "bob",
                        NEW_YORK,
                        5,
                    ),
                ]
            ],
            base_config,
        )

        assert rows == []

    def test_only_the_offending_user_is_reported(
        self,
        spark,
        tmp_path,
        base_config,
    ):
        rows = run_detection(
            spark,
            tmp_path,
            [
                [
                    enriched_event(
                        "alice",
                        MUMBAI,
                        0,
                    ),
                    enriched_event(
                        "alice",
                        NEW_YORK,
                        10,
                    ),
                    enriched_event(
                        "bob",
                        MUMBAI,
                        0,
                    ),
                    enriched_event(
                        "bob",
                        PUNE,
                        10,
                    ),
                ]
            ],
            base_config,
        )

        assert [
            row["username"]
            for row in rows
        ] == ["alice"]

    def test_failed_logins_are_ignored(
        self,
        spark,
        tmp_path,
        base_config,
    ):
        rows = run_detection(
            spark,
            tmp_path,
            [
                [
                    enriched_event(
                        "alice",
                        MUMBAI,
                        0,
                    ),
                    enriched_event(
                        "alice",
                        NEW_YORK,
                        10,
                        event_type="failed_login",
                    ),
                ]
            ],
            base_config,
        )

        assert rows == []

    def test_logins_without_geo_coordinates_are_ignored(
        self,
        spark,
        tmp_path,
        base_config,
    ):
        no_geo = (
            str(uuid.uuid4()),
            "alice",
            "10.0.0.5",
            "successful_login",
            None,
            None,
            None,
            BASE_TIME
            + timedelta(minutes=10),
        )

        rows = run_detection(
            spark,
            tmp_path,
            [
                [
                    enriched_event(
                        "alice",
                        MUMBAI,
                        0,
                    ),
                    no_geo,
                ]
            ],
            base_config,
        )

        assert rows == []

    def test_configured_distance_threshold_is_respected(
        self,
        spark,
        tmp_path,
    ):
        config = RuleConfig(
            rule_name="impossible_travel",
            threshold=15_000,
            window_minutes=60,
            slide_minutes=60,
            enabled=True,
        )

        rows = run_detection(
            spark,
            tmp_path,
            [
                [
                    enriched_event(
                        "alice",
                        MUMBAI,
                        0,
                    ),
                    enriched_event(
                        "alice",
                        NEW_YORK,
                        10,
                    ),
                ]
            ],
            config,
        )

        assert rows == []

    def test_configured_time_window_is_respected(
        self,
        spark,
        tmp_path,
    ):
        config = RuleConfig(
            rule_name="impossible_travel",
            threshold=1000,
            window_minutes=5,
            slide_minutes=5,
            enabled=True,
        )

        rows = run_detection(
            spark,
            tmp_path,
            [
                [
                    enriched_event(
                        "alice",
                        MUMBAI,
                        0,
                    ),
                    enriched_event(
                        "alice",
                        NEW_YORK,
                        10,
                    ),
                ]
            ],
            config,
        )

        assert rows == []

    def test_non_positive_config_is_rejected(
        self,
        spark,
        tmp_path,
    ):
        config = RuleConfig(
            rule_name="impossible_travel",
            threshold=1000,
            window_minutes=0,
            slide_minutes=0,
            enabled=True,
        )

        events_df = spark.createDataFrame(
            [
                enriched_event(
                    "alice",
                    MUMBAI,
                    0,
                )
            ],
            EVENT_SCHEMA,
        )

        with pytest.raises(ValueError):
            build_rule().detect(
                events_df,
                config,
            )


# ---------------------------------------------------------------------------
# 4. Alert persistence and publication
# ---------------------------------------------------------------------------


class TestAlertSideEffects:

    def test_alert_is_saved_and_published(
        self,
        spark,
        base_config,
    ):
        row = alert_row()

        batch_df = spark.createDataFrame(
            [row]
        )

        alerts_repository = Mock()
        alerts_repository.save.return_value = {
            "id": 1
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

        save_kwargs = (
            alerts_repository
            .save
            .call_args
            .kwargs
        )

        assert (
            save_kwargs["rule_name"]
            == "impossible_travel"
        )
        assert (
            save_kwargs["source_ip"]
            == "203.0.113.30"
        )
        assert (
            save_kwargs["severity"]
            == "CRITICAL"
        )
        assert (
            save_kwargs["event_count"]
            == 2
        )
        assert (
            save_kwargs["window_start"]
            == BASE_TIME
        )
        assert (
            save_kwargs["window_end"]
            == BASE_TIME
            + timedelta(minutes=10)
        )
        assert (
            save_kwargs["triggered_at"]
            is not None
        )

        alert_publisher.publish.assert_called_once()

        assert (
            alert_publisher
            .publish
            .call_args
            .kwargs
            == {}
        )

        assert len(
            alert_publisher
            .publish
            .call_args
            .args
        ) == 1

        published = (
            alert_publisher
            .publish
            .call_args
            .args[0]
        )

        assert (
            published["rule_name"]
            == "impossible_travel"
        )
        assert (
            published["severity"]
            == "CRITICAL"
        )
        assert (
            published["source_ip"]
            == "203.0.113.30"
        )

        assert len(
            published["source_event_ids"]
        ) == 2

        # Structured Issue #14 fields.
        assert (
            published["username"]
            == "alice"
        )
        assert (
            published["login_1_country"]
            == "India"
        )
        assert (
            published["login_2_country"]
            == "United States"
        )
        assert (
            published["time_delta_minutes"]
            == pytest.approx(10.0)
        )
        assert (
            published["distance_km"]
            == pytest.approx(
                12540.0,
                abs=100,
            )
        )

        description = (
            published["description"]
        )

        assert "alice" in description
        assert "India" in description
        assert "United States" in description
        assert (
            "time_delta_minutes=10.0"
            in description
        )
        assert (
            "distance_km=12540"
            in description
        )
        assert "T1078" in description

    def test_alert_contains_structured_impossible_travel_fields(
        self,
        spark,
        base_config,
    ):
        row = alert_row()

        batch_df = spark.createDataFrame(
            [row]
        )

        alerts_repository = Mock()
        alerts_repository.save.return_value = {
            "id": 1
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

        published = (
            alert_publisher
            .publish
            .call_args
            .args[0]
        )

        assert (
            published["username"]
            == "alice"
        )
        assert (
            published["login_1_country"]
            == "India"
        )
        assert (
            published["login_2_country"]
            == "United States"
        )
        assert (
            published["time_delta_minutes"]
            == pytest.approx(10.0)
        )
        assert (
            published["distance_km"]
            == pytest.approx(
                12540.0,
                abs=100,
            )
        )
        assert (
            published["severity"]
            == "CRITICAL"
        )

    def test_no_alert_rows_means_nothing_is_saved_or_published(
        self,
        spark,
        base_config,
    ):
        empty_df = (
            spark.createDataFrame(
                [alert_row()]
            )
            .limit(0)
        )

        alerts_repository = Mock()
        alert_publisher = Mock()

        rule = build_rule(
            alerts_repository=alerts_repository,
            alert_publisher=alert_publisher,
        )

        rule.process_batch(
            empty_df,
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
        batch_df = spark.createDataFrame(
            [alert_row()]
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
            batch_id=0,
            config=base_config,
        )

        assert (
            alerts_repository
            .save
            .call_count
            == 2
        )

        assert (
            alert_publisher
            .publish
            .call_count
            == 1
        )

    def test_alert_without_source_event_ids_is_skipped(
        self,
        spark,
        base_config,
    ):
        batch_df = spark.createDataFrame(
            [
                alert_row(
                    source_event_ids=[]
                )
            ],
            schema=(
                "username string, "
                "login_1_country string, "
                "login_2_country string, "
                "login_1_ip string, "
                "login_2_ip string, "
                "window_start timestamp, "
                "window_end timestamp, "
                "time_delta_minutes double, "
                "distance_km double, "
                "source_event_ids array<string>"
            ),
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

    def test_invalid_alert_fails_before_anything_is_persisted(
        self,
        spark,
        base_config,
    ):
        """
        An alert that cannot be validated must not leave a saved
        but never-published row behind.
        """

        batch_df = spark.createDataFrame(
            [
                alert_row(
                    login_2_ip="not-an-ip"
                )
            ]
        )

        alerts_repository = Mock()
        alert_publisher = Mock()

        rule = build_rule(
            alerts_repository=alerts_repository,
            alert_publisher=alert_publisher,
        )

        with pytest.raises(Exception):
            rule.process_batch(
                batch_df,
                batch_id=0,
                config=base_config,
            )

        alerts_repository.save.assert_not_called()
        alert_publisher.publish.assert_not_called()

    def test_missing_dependencies_raise(
        self,
        spark,
        base_config,
    ):
        batch_df = spark.createDataFrame(
            [alert_row()]
        )

        with pytest.raises(RuntimeError):
            build_rule(
                alerts_repository=None,
                alert_publisher=Mock(),
            ).process_batch(
                batch_df,
                batch_id=0,
                config=base_config,
            )

        with pytest.raises(RuntimeError):
            build_rule(
                alerts_repository=Mock(),
                alert_publisher=None,
            ).process_batch(
                batch_df,
                batch_id=0,
                config=base_config,
            )

    def test_severity_is_critical(self):
        assert ALERT_SEVERITY == "CRITICAL"


# ---------------------------------------------------------------------------
# 5. Rule configuration
# ---------------------------------------------------------------------------


class TestRuleConfiguration:

    def test_default_config_without_repository(
        self,
    ):
        config = build_rule().load_config()

        assert (
            config.rule_name
            == "impossible_travel"
        )
        assert config.threshold == 1000
        assert config.window_minutes == 60
        assert config.enabled is True

    def test_rule_uses_repository_configuration(
        self,
    ):
        rules_repository = Mock()

        rules_repository.get_config.return_value = (
            RuleConfig(
                rule_name="impossible_travel",
                threshold=500,
                window_minutes=30,
                slide_minutes=30,
                enabled=True,
            )
        )

        config = build_rule(
            rules_repository=rules_repository
        ).load_config()

        rules_repository.get_config.assert_called_once()

        assert config.threshold == 500
        assert config.window_minutes == 30

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason=(
            "This test uses the Spark file-streaming helper; "
            "run it under Linux/Docker/WSL on Windows."
        ),
    )
    def test_repository_configured_threshold_drives_detection(
        self,
        spark,
        tmp_path,
    ):
        rules_repository = Mock()

        rules_repository.get_config.return_value = (
            RuleConfig(
                rule_name="impossible_travel",
                threshold=15_000,
                window_minutes=60,
                slide_minutes=60,
                enabled=True,
            )
        )

        rule = build_rule(
            rules_repository=rules_repository
        )

        config = rule.load_config()

        rows = run_detection(
            spark,
            tmp_path,
            [
                [
                    enriched_event(
                        "alice",
                        MUMBAI,
                        0,
                    ),
                    enriched_event(
                        "alice",
                        NEW_YORK,
                        10,
                    ),
                ]
            ],
            config,
        )

        rules_repository.get_config.assert_called_once()

        assert rows == []

    def test_disabled_rule_does_not_create_streaming_query(
        self,
        spark,
        tmp_path,
    ):
        rules_repository = Mock()

        rules_repository.get_config.return_value = (
            RuleConfig(
                rule_name="impossible_travel",
                threshold=1000,
                window_minutes=60,
                slide_minutes=60,
                enabled=False,
            )
        )

        rule = build_rule(
            rules_repository=rules_repository
        )

        events_df = (
            spark.readStream
            .format("rate")
            .option(
                "rowsPerSecond",
                1,
            )
            .load()
            .selectExpr(
                "CAST(value AS STRING) AS event_id",
                "'alice' AS username",
                "'49.36.10.1' AS source_ip",
                "'successful_login' AS event_type",
                "'India' AS geo_country",
                "19.07 AS geo_latitude",
                "72.87 AS geo_longitude",
                "timestamp AS event_timestamp",
            )
        )

        query = rule.build_streaming_query(
            events_df,
            checkpoint_location=str(
                tmp_path
                / "checkpoint"
            ),
        )

        assert query is None