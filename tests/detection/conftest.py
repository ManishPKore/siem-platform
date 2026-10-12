"""
Shared fixtures for tests/detection/.

Provides:
- One local Spark session for the detection test suite.
- Deterministic timestamps and sample event data.
- Event builders for authentication, firewall, and geographic events.
- Reusable RuleConfig instances.
- Mocked repositories and alert publishers.
- Factories for the four existing detection rules.

Rule interfaces are based on the existing SIEM project:
    detection_engine.rules.brute_force.BruteForceRule
    detection_engine.rules.port_scan.PortScanRule
    detection_engine.rules.impossible_travel.ImpossibleTravelRule
    detection_engine.rules.off_hours.OffHoursLoginRule

No live Kafka broker or database is required by these fixtures.
"""

from __future__ import annotations

import os
import sys
import time as monotonic_time
import uuid
from datetime import datetime, time, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

# Configure the Python executable before starting Spark.
# On Windows, sys.executable points to the active Python interpreter.
os.environ.setdefault("PYSPARK_PYTHON", sys.executable)
os.environ.setdefault("PYSPARK_DRIVER_PYTHON", sys.executable)

import pytest
from pyspark.sql import Row, SparkSession
from pyspark.sql.types import (
    DoubleType,
    IntegerType,
    StringType,
    StructField,
    StructType,
    TimestampType,
)

from detection_engine.rules.base import RuleConfig


# ===========================================================================
# Constants
# ===========================================================================

BASE_TS = datetime(2026, 10, 14, 10, 0, 0)

DEFAULT_SOURCE_IP = "192.168.1.10"
DEFAULT_USERNAME = "alice"

FAILED_LOGIN = "failed_login"
SUCCESSFUL_LOGIN = "successful_login"
FIREWALL_DROP = "firewall_drop"

SOURCE_AUTH = "auth"
SOURCE_FIREWALL = "firewall"

RULE_BRUTE_FORCE = "brute_force"
RULE_PORT_SCAN = "port_scan"
RULE_IMPOSSIBLE_TRAVEL = "impossible_travel"
RULE_OFF_HOURS = "off_hours_login"

# Geographic test locations.
MUMBAI = ("India", 19.07, 72.87)
PUNE = ("India", 18.52, 73.86)
NEW_YORK = ("United States", 40.71, -74.00)

NYC = (40.7128, -74.0060)
LONDON = (51.5074, -0.1278)


# ===========================================================================
# Spark schemas
# ===========================================================================

# Common superset of the event columns used by the existing rules.
#
# Explicit schemas prevent Spark from failing to infer a type when a
# test contains only null values in a particular column.
EVENT_SCHEMA = StructType(
    [
        StructField("event_id", StringType(), True),
        StructField("timestamp", TimestampType(), True),
        StructField("event_timestamp", TimestampType(), True),
        StructField("source", StringType(), True),
        StructField("event_type", StringType(), True),
        StructField("source_ip", StringType(), True),
        StructField("username", StringType(), True),
        StructField("dest_port", IntegerType(), True),
        StructField("country", StringType(), True),
        StructField("geo_country", StringType(), True),
        StructField("latitude", DoubleType(), True),
        StructField("longitude", DoubleType(), True),
        StructField("geo_latitude", DoubleType(), True),
        StructField("geo_longitude", DoubleType(), True),
    ]
)


# ===========================================================================
# Deterministic event builders
# ===========================================================================

def event(
    ts: datetime = BASE_TS,
    *,
    event_id: str | None = None,
    event_type: str = FAILED_LOGIN,
    source: str = SOURCE_AUTH,
    source_ip: str = DEFAULT_SOURCE_IP,
    username: str = DEFAULT_USERNAME,
    dest_port: int | None = None,
    country: str | None = None,
    latitude: float | None = None,
    longitude: float | None = None,
    geo_country: str | None = None,
    geo_latitude: float | None = None,
    geo_longitude: float | None = None,
) -> dict:
    """
    Build one event containing the common fields used by detection rules.

    Aware datetimes are converted to naive UTC because Spark SQL timestamps
    in this project represent UTC timestamps.
    """
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)

    return {
        "event_id": event_id or str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                (
                    f"{ts.isoformat()}|{event_type}|{source_ip}|"
                    f"{username}|{source}|{dest_port}"
                ),
            )
        ),
        "timestamp": ts,
        "event_timestamp": ts,
        "source": source,
        "event_type": event_type,
        "source_ip": source_ip,
        "username": username,
        "dest_port": dest_port,
        "country": country or geo_country,
        "geo_country": geo_country or country,
        "latitude": latitude if latitude is not None else geo_latitude,
        "longitude": longitude if longitude is not None else geo_longitude,
        "geo_latitude": (
            geo_latitude if geo_latitude is not None else latitude
        ),
        "geo_longitude": (
            geo_longitude if geo_longitude is not None else longitude
        ),
    }


def make_df(spark: SparkSession, rows: list[dict]):
    """
    Create a DataFrame using the shared event schema.

    The input rows may be produced by event() or supplied as dictionaries.
    """
    normalized_rows = []

    for item in rows:
        row = dict(item)

        # Accept either timestamp column as the source of the timestamp.
        timestamp = row.get("event_timestamp") or row.get("timestamp")

        if timestamp is not None and timestamp.tzinfo is not None:
            timestamp = timestamp.astimezone(timezone.utc).replace(
                tzinfo=None
            )

        row["timestamp"] = row.get("timestamp") or timestamp
        row["event_timestamp"] = row.get("event_timestamp") or timestamp

        normalized_rows.append(
            tuple(row.get(field.name) for field in EVENT_SCHEMA.fields)
        )

    return spark.createDataFrame(normalized_rows, schema=EVENT_SCHEMA)


def events_at_minute_offsets(
    source_ip: str,
    event_type: str,
    offsets_minutes: list[float],
    *,
    base: datetime = BASE_TS,
    username: str = DEFAULT_USERNAME,
) -> list[dict]:
    """Build deterministic events at the requested minute offsets."""
    return [
        event(
            base + timedelta(minutes=offset),
            event_id=str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"{source_ip}|{event_type}|minute|{index}|{offset}",
                )
            ),
            source_ip=source_ip,
            username=username,
            event_type=event_type,
        )
        for index, offset in enumerate(offsets_minutes)
    ]


def firewall_events_at_second_offsets(
    source_ip: str,
    dest_ports: list[int],
    offsets_seconds: list[float],
    *,
    base: datetime = BASE_TS,
    source: str = SOURCE_FIREWALL,
) -> list[dict]:
    """Build deterministic firewall events at the requested second offsets."""
    if len(dest_ports) != len(offsets_seconds):
        raise ValueError(
            "dest_ports and offsets_seconds must have the same length"
        )

    return [
        event(
            base + timedelta(seconds=offset),
            event_id=str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"{source_ip}|{port}|{offset}|{index}",
                )
            ),
            source=source,
            source_ip=source_ip,
            event_type=FIREWALL_DROP,
            dest_port=port,
        )
        for index, (port, offset) in enumerate(
            zip(dest_ports, offsets_seconds)
        )
    ]


def sequential_ports(count: int, start: int = 1000) -> list[int]:
    """Generate a deterministic sequence of distinct destination ports."""
    if count < 0:
        raise ValueError("count must be non-negative")

    if start < 0 or start + count > 65536:
        raise ValueError("Generated ports must be between 0 and 65535")

    return list(range(start, start + count))


def spread_offsets(count: int, span_seconds: float) -> list[float]:
    """Spread event timestamps evenly across a fixed time interval."""
    if count < 0:
        raise ValueError("count must be non-negative")

    if count == 0:
        return []

    if count == 1:
        return [0.0]

    return [
        span_seconds * index / (count - 1)
        for index in range(count)
    ]


def enriched_login_event(
    username: str,
    location: tuple[str, float, float],
    offset_minutes: float,
    *,
    source_ip: str = DEFAULT_SOURCE_IP,
    base: datetime = BASE_TS,
) -> dict:
    """Build a successful login event with geographic enrichment."""
    country, latitude, longitude = location

    return event(
        base + timedelta(minutes=offset_minutes),
        source_ip=source_ip,
        username=username,
        event_type=SUCCESSFUL_LOGIN,
        source=SOURCE_AUTH,
        country=country,
        latitude=latitude,
        longitude=longitude,
        geo_country=country,
        geo_latitude=latitude,
        geo_longitude=longitude,
    )


# ===========================================================================
# Shared Spark session
# ===========================================================================

@pytest.fixture(scope="session")
def spark():
    """
    Start one local Spark session for the entire detection test suite.

    This uses local Spark rather than a separately running Spark cluster.
    """
    session = (
        SparkSession.builder
        .master("local[2]")
        .appName("siem-detection-tests")
        .config("spark.sql.shuffle.partitions", "1")
        .config("spark.default.parallelism", "1")
        .config("spark.sql.adaptive.enabled", "false")
        .config("spark.sql.session.timeZone", "UTC")
        .config("spark.ui.enabled", "false")
        .config("spark.driver.bindAddress", "127.0.0.1")
        .config("spark.driver.host", "127.0.0.1")
        .getOrCreate()
    )

    session.sparkContext.setLogLevel("ERROR")

    yield session

    session.stop()


# ===========================================================================
# Reusable sample DataFrames
# ===========================================================================

@pytest.fixture
def sample_df(spark):
    """Provide a small mixed event DataFrame for schema and smoke tests."""
    return make_df(
        spark,
        [
            event(
                BASE_TS,
                event_type=FAILED_LOGIN,
                source_ip="10.0.0.1",
            ),
            event(
                BASE_TS + timedelta(seconds=10),
                event_type=FIREWALL_DROP,
                source=SOURCE_FIREWALL,
                source_ip="10.0.0.2",
                dest_port=22,
            ),
            event(
                BASE_TS + timedelta(seconds=20),
                event_type=SUCCESSFUL_LOGIN,
                source_ip="10.0.0.3",
                country="India",
                latitude=MUMBAI[1],
                longitude=MUMBAI[2],
            ),
        ],
    )


@pytest.fixture
def brute_force_events(spark):
    """Provide six failed logins from one IP inside five minutes."""
    rows = events_at_minute_offsets(
        DEFAULT_SOURCE_IP,
        FAILED_LOGIN,
        [0, 1, 2, 3, 4, 4.5],
    )
    return make_df(spark, rows)


@pytest.fixture
def port_scan_events(spark):
    """Provide distinct firewall ports inside a two-minute window."""
    rows = firewall_events_at_second_offsets(
        "203.0.113.5",
        sequential_ports(25),
        spread_offsets(25, 110),
    )
    return make_df(spark, rows)


@pytest.fixture
def impossible_travel_events(spark):
    """Provide two geographically distant successful logins."""
    rows = [
        enriched_login_event("alice", MUMBAI, 0),
        enriched_login_event(
            "alice",
            NEW_YORK,
            10,
            source_ip="203.0.113.30",
        ),
    ]
    return make_df(spark, rows)


@pytest.fixture
def off_hours_event(spark):
    """Provide a successful login at 02:00 UTC."""
    ts = datetime(2026, 10, 14, 2, 0, 0, tzinfo=timezone.utc)
    return make_df(
        spark,
        [
            event(
                ts,
                event_type=SUCCESSFUL_LOGIN,
                source_ip="203.0.113.10",
            )
        ],
    )


# ===========================================================================
# Mocked collaborators
# ===========================================================================

@pytest.fixture
def deps():
    """
    Provide mock repositories and publisher for rules that persist alerts.

    Rule tests can inspect calls to save() and publish() without connecting
    to PostgreSQL or Kafka.
    """
    rules_repository = MagicMock(name="RulesRepository")
    alerts_repository = MagicMock(name="AlertsRepository")
    alert_publisher = MagicMock(name="AlertPublisher")

    # Default persistence behavior: return the alert passed to save().
    alerts_repository.save.side_effect = lambda *args, **kwargs: (
        kwargs if kwargs else (args[0] if args else None)
    )

    # Default configuration is supplied by each test or factory.
    return SimpleNamespace(
        rules_repository=rules_repository,
        alerts_repository=alerts_repository,
        alert_publisher=alert_publisher,
    )


# ===========================================================================
# Rule configurations
# ===========================================================================

@pytest.fixture
def brute_force_config():
    """Default configuration for brute-force detection."""
    return RuleConfig(
        rule_name=RULE_BRUTE_FORCE,
        threshold=5,
        window_minutes=5,
        slide_minutes=1,
        enabled=True,
    )


@pytest.fixture
def port_scan_config():
    """Default configuration for port-scan detection."""
    return RuleConfig(
        rule_name=RULE_PORT_SCAN,
        threshold=20,
        window_minutes=2,
        slide_minutes=2,
        enabled=True,
    )


@pytest.fixture
def impossible_travel_config():
    """Default configuration for impossible-travel detection."""
    return RuleConfig(
        rule_name=RULE_IMPOSSIBLE_TRAVEL,
        threshold=1000,
        window_minutes=60,
        slide_minutes=60,
        enabled=True,
    )


@pytest.fixture
def off_hours_config():
    """Default configuration for off-hours login detection."""
    return RuleConfig(
        rule_name=RULE_OFF_HOURS,
        threshold=1,
        window_minutes=1,
        slide_minutes=1,
        enabled=True,
        off_hours_start=time(22, 0),
        off_hours_end=time(6, 0),
    )


# ===========================================================================
# Rule factory
# ===========================================================================

class RuleFactory:
    """
    Construct the project's existing detection rules with mocked dependencies.

    Detection tests can supply a RuleConfig directly to detect(), as the
    existing rule tests do. This avoids relying on a live rules database.
    """

    def __init__(self, deps):
        self.deps = deps

    def brute_force(self):
        from detection_engine.rules.brute_force import BruteForceRule

        return BruteForceRule(
            rules_repository=self.deps.rules_repository,
            alerts_repository=self.deps.alerts_repository,
            alert_publisher=self.deps.alert_publisher,
        )

    def port_scan(self):
        from detection_engine.rules.port_scan import PortScanRule

        return PortScanRule(
            rules_repository=self.deps.rules_repository,
            alerts_repository=self.deps.alerts_repository,
            alert_publisher=self.deps.alert_publisher,
        )

    def impossible_travel(self):
        from detection_engine.rules.impossible_travel import (
            ImpossibleTravelRule,
        )

        return ImpossibleTravelRule(
            rules_repository=self.deps.rules_repository,
            alerts_repository=self.deps.alerts_repository,
            alert_publisher=self.deps.alert_publisher,
        )

    def off_hours(self):
        from detection_engine.rules.off_hours import OffHoursLoginRule

        return OffHoursLoginRule(
            rules_repository=self.deps.rules_repository,
            alerts_repository=self.deps.alerts_repository,
            alert_publisher=self.deps.alert_publisher,
        )


@pytest.fixture
def rules(deps):
    """Provide a factory for all four detection rules."""
    return RuleFactory(deps)


# ===========================================================================
# Test-suite runtime measurement
# ===========================================================================

_TEST_START_TIME = None


def pytest_sessionstart(session):
    """Record when the detection test session starts."""
    global _TEST_START_TIME
    _TEST_START_TIME = monotonic_time.monotonic()


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """
    Report the elapsed test-suite time.

    The issue requires the suite to finish in under 30 seconds. This hook
    reports the measured duration; it does not falsely mark a slow suite as
    passing or failing.
    """
    if _TEST_START_TIME is None:
        return

    elapsed = monotonic_time.monotonic() - _TEST_START_TIME

    terminalreporter.write_sep(
        "-",
        f"Detection test-suite duration: {elapsed:.2f}s "
        f"(target: under 30s)",
    )

    if elapsed >= 30:
        terminalreporter.write_line(
            "WARNING: Detection tests exceeded the 30-second target. "
            "Use pytest --durations=10 to identify slow tests.",
            red=True,
        )