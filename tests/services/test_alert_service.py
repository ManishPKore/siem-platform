"""
Tests for api/services/alert_service.py.

* Pure unit tests (validation, error wrapping) need no database.
* DB tests run against the real PostgreSQL instance (same approach as
  tests/services/test_storage_service_integration.py): every test runs inside
  a transaction that is rolled back, and the whole group is skipped when
  PostgreSQL is unreachable.

Requires scripts/migrations/003_alert_storage.sql to be applied and SQLAlchemy 2.x.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from api.database import SessionLocal
from api.models.alert import Alert
from api.services.alert_service import (
    AlertEvent,
    AlertFilters,
    AlertNotFoundError,
    AlertStorageError,
    AlertStorageService,
)

UTC = timezone.utc
T0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)

BRUTE = "brute_force"
SCAN = "port_scan"

STATUS_OPEN = "OPEN"
STATUS_ACKNOWLEDGED = "ACKNOWLEDGED"
STATUS_RESOLVED = "RESOLVED"


def make_alert(**overrides) -> AlertEvent:
    base = dict(
        rule_name=BRUTE,
        source_ip="203.0.113.7",
        severity="MEDIUM",
        triggered_at=T0,
        window_start=T0 - timedelta(minutes=5),
        window_end=T0,
        event_count=1,
    )
    base.update(overrides)
    return AlertEvent(**base)


# ===========================================================================
# Pure unit tests (no database)
# ===========================================================================


class TestAlertEvent:
    def test_normalises_values(self):
        alert = AlertEvent(
            "brute_force",
            " 203.0.113.7 ",
            "high",
            datetime(2026, 10, 2, 12, 0),
        )

        assert alert.severity == "HIGH"
        assert alert.source_ip == "203.0.113.7"
        assert alert.triggered_at.tzinfo is not None
        assert alert.window_start == alert.triggered_at
        assert alert.window_end == alert.window_start

    def test_accepts_ipv6(self):
        assert (
            make_alert(source_ip="2001:db8::1").source_ip
            == "2001:db8::1"
        )

    @pytest.mark.parametrize(
        "bad_ip",
        [
            "",
            "not-an-ip",
            "999.1.1.1",
            "1.2.3",
        ],
    )
    def test_rejects_bad_ip(self, bad_ip):
        with pytest.raises(ValueError, match="source_ip"):
            make_alert(source_ip=bad_ip)

    def test_rejects_unknown_severity(self):
        with pytest.raises(ValueError, match="severity"):
            make_alert(severity="URGENT")

    @pytest.mark.parametrize(
        "count",
        [
            0,
            -1,
            True,
            1.5,
        ],
    )
    def test_rejects_bad_event_count(self, count):
        with pytest.raises(ValueError, match="event_count"):
            make_alert(event_count=count)

    def test_rejects_inverted_window(self):
        with pytest.raises(ValueError, match="window_end"):
            make_alert(
                window_start=T0,
                window_end=T0 - timedelta(seconds=1),
            )

    def test_rejects_blank_rule_name(self):
        with pytest.raises(ValueError, match="rule_name"):
            make_alert(rule_name="  ")

    def test_from_dict_roundtrip(self):
        alert = AlertEvent.from_dict(
            {
                "rule_name": BRUTE,
                "source_ip": "198.51.100.4",
                "severity": "critical",
                "triggered_at": "2026-10-02T12:00:00Z",
                "window_start": "2026-10-02T11:55:00+00:00",
                "window_end": "2026-10-02T12:00:00+00:00",
                "event_count": "12",
            }
        )

        assert alert.severity == "CRITICAL"
        assert alert.event_count == 12
        assert alert.triggered_at == T0

    @pytest.mark.parametrize(
        "missing",
        [
            "rule_name",
            "source_ip",
            "severity",
            "triggered_at",
        ],
    )
    def test_from_dict_missing_required_field(self, missing):
        payload = {
            "rule_name": BRUTE,
            "source_ip": "198.51.100.4",
            "severity": "HIGH",
            "triggered_at": "2026-10-02T12:00:00Z",
        }

        del payload[missing]

        with pytest.raises(ValueError, match=missing):
            AlertEvent.from_dict(payload)

    def test_from_dict_bad_timestamp(self):
        with pytest.raises(ValueError, match="triggered_at"):
            AlertEvent.from_dict(
                {
                    "rule_name": BRUTE,
                    "source_ip": "1.2.3.4",
                    "severity": "HIGH",
                    "triggered_at": "yesterday",
                }
            )

    def test_from_dict_rejects_non_object(self):
        with pytest.raises(ValueError):
            AlertEvent.from_dict(
                ["not", "a", "dict"]
            )  # type: ignore[arg-type]


class TestAlertFilters:
    def test_normalises(self):
        filters = AlertFilters(
            severity="high",
            status="OPEN",
        )

        assert filters.severity == "HIGH"
        assert filters.status == STATUS_OPEN

    def test_rejects_inverted_range(self):
        with pytest.raises(ValueError, match="from_time"):
            AlertFilters(
                from_time=T0,
                to_time=T0 - timedelta(hours=1),
            )

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"severity": "x"},
            {"status": "pending"},
            {"limit": 0},
            {"limit": 5000},
            {"offset": -1},
        ],
    )
    def test_rejects_invalid(self, kwargs):
        with pytest.raises(ValueError):
            AlertFilters(**kwargs)


class TestErrorWrapping:
    @pytest.fixture
    def broken_service(self):
        factory = MagicMock(
            side_effect=OperationalError(
                "stmt",
                {},
                Exception("db down"),
            )
        )

        return AlertStorageService(
            session_factory=factory
        )

    def test_save_wraps_db_errors(self, broken_service):
        with pytest.raises(AlertStorageError):
            broken_service.save_alert(
                make_alert()
            )

    def test_get_wraps_db_errors(self, broken_service):
        with pytest.raises(AlertStorageError):
            broken_service.get_alerts(
                severity="HIGH"
            )

    def test_close_wraps_db_errors(self, broken_service):
        with pytest.raises(AlertStorageError):
            broken_service.close_alert(1)

    def test_get_alerts_rejects_filters_and_kwargs_together(self):
        service = AlertStorageService(
            session_factory=MagicMock()
        )

        with pytest.raises(TypeError):
            service.get_alerts(
                AlertFilters(),
                severity="HIGH",
            )


# ===========================================================================
# PostgreSQL-backed tests
# ===========================================================================


@pytest.fixture(scope="module")
def engine():
    bind = SessionLocal.kw.get("bind")

    if bind is None:
        pytest.skip(
            "SessionLocal is not bound to an engine"
        )

    try:
        with bind.connect():
            pass
    except OperationalError:
        pytest.skip(
            "PostgreSQL is not reachable"
        )

    return bind


@pytest.fixture
def session_factory(engine):
    """
    Sessions that share one outer transaction,
    rolled back after the test.
    """

    connection = engine.connect()
    outer = connection.begin()

    def factory() -> Session:
        return Session(
            bind=connection,
            join_transaction_mode="create_savepoint",
            expire_on_commit=True,
        )

    yield factory

    outer.rollback()
    connection.close()


def _seed_rule(
    session_factory,
    rule_name: str,
    dedup_minutes: int = 10,
) -> None:
    """
    Seed a rule row using the current rules schema.

    The rules table requires threshold and window_minutes, so those are
    supplied here instead of relying on missing defaults.
    """

    with session_factory() as session:
        session.execute(
            text(
                """
                INSERT INTO rules (
                    rule_name,
                    description,
                    threshold,
                    window_minutes,
                    enabled,
                    dedup_window_minutes
                )
                VALUES (
                    :rule_name,
                    :description,
                    :threshold,
                    :window_minutes,
                    :enabled,
                    :dedup_window_minutes
                )
                ON CONFLICT (rule_name)
                DO UPDATE SET
                    dedup_window_minutes =
                        EXCLUDED.dedup_window_minutes
                """
            ),
            {
                "rule_name": rule_name,
                "description": (
                    f"Test rule for {rule_name}"
                ),
                "threshold": 5,
                "window_minutes": 5,
                "enabled": True,
                "dedup_window_minutes": dedup_minutes,
            },
        )

        session.commit()


@pytest.fixture
def service(session_factory):
    _seed_rule(
        session_factory,
        BRUTE,
        10,
    )

    _seed_rule(
        session_factory,
        SCAN,
        10,
    )

    return AlertStorageService(
        session_factory=session_factory
    )


def _count(
    session_factory,
    **where,
) -> int:
    with session_factory() as session:
        stmt = (
            select(func.count())
            .select_from(Alert)
        )

        for column, value in where.items():
            stmt = stmt.where(
                getattr(Alert, column) == value
            )

        return session.execute(
            stmt
        ).scalar_one()


class TestSaveAlert:
    def test_persists_new_alert(
        self,
        service,
        session_factory,
    ):
        saved = service.save_alert(
            make_alert(event_count=7)
        )

        assert saved.id is not None
        assert saved.rule_name == BRUTE
        assert (
            str(saved.source_ip)
            == "203.0.113.7"
        )
        assert saved.severity == "MEDIUM"
        assert saved.status == STATUS_OPEN
        assert saved.event_count == 7
        assert saved.resolved_at is None

        assert (
            _count(session_factory)
            == 1
        )

    def test_persisted_within_five_seconds(
        self,
        service,
    ):
        """
        Acceptance: alert persisted within 5s
        of detection (service-side latency).
        """

        detected_at = time.monotonic()

        saved = service.save_alert(
            make_alert(
                triggered_at=datetime.now(UTC)
            )
        )

        assert saved.id is not None

        assert (
            time.monotonic()
            - detected_at
            < 5.0
        )

    def test_duplicate_within_window_updates_event_count(
        self,
        service,
        session_factory,
    ):
        """
        Acceptance: second alert for same
        IP + rule within 10 minutes updates
        event_count instead of creating a row.
        """

        first = service.save_alert(
            make_alert()
        )

        second = service.save_alert(
            make_alert(
                triggered_at=(
                    T0
                    + timedelta(minutes=4)
                ),
                window_start=(
                    T0
                    - timedelta(minutes=1)
                ),
                window_end=(
                    T0
                    + timedelta(minutes=4)
                ),
            )
        )

        assert second.id == first.id
        assert (
            second.event_count
            == first.event_count + 1
        )

        assert (
            _count(session_factory)
            == 1
        )

    def test_many_duplicates_keep_incrementing(
        self,
        service,
        session_factory,
    ):
        for i in range(5):
            last = service.save_alert(
                make_alert(
                    triggered_at=(
                        T0
                        + timedelta(minutes=i)
                    )
                )
            )

        assert last.event_count == 5

        assert (
            _count(session_factory)
            == 1
        )

    def test_duplicate_extends_window_end(
        self,
        service,
    ):
        service.save_alert(
            make_alert()
        )

        later = (
            T0
            + timedelta(minutes=3)
        )

        updated = service.save_alert(
            make_alert(
                triggered_at=later,
                window_end=later,
            )
        )

        assert (
            updated.window_end
            == later
        )

    def test_outside_window_creates_new_row(
        self,
        service,
        session_factory,
    ):
        service.save_alert(
            make_alert()
        )

        service.save_alert(
            make_alert(
                triggered_at=(
                    T0
                    + timedelta(minutes=11)
                ),
                window_start=(
                    T0
                    + timedelta(minutes=6)
                ),
                window_end=(
                    T0
                    + timedelta(minutes=11)
                ),
            )
        )

        assert (
            _count(session_factory)
            == 2
        )

    def test_different_ip_is_not_a_duplicate(
        self,
        service,
        session_factory,
    ):
        service.save_alert(
            make_alert()
        )

        service.save_alert(
            make_alert(
                source_ip="203.0.113.8"
            )
        )

        assert (
            _count(session_factory)
            == 2
        )

    def test_different_rule_is_not_a_duplicate(
        self,
        service,
        session_factory,
    ):
        service.save_alert(
            make_alert()
        )

        service.save_alert(
            make_alert(
                rule_name=SCAN
            )
        )

        assert (
            _count(session_factory)
            == 2
        )

    def test_dedup_window_is_configurable_per_rule(
        self,
        service,
        session_factory,
    ):
        _seed_rule(
            session_factory,
            BRUTE,
            dedup_minutes=2,
        )

        service.save_alert(
            make_alert()
        )

        service.save_alert(
            make_alert(
                triggered_at=(
                    T0
                    + timedelta(minutes=3)
                ),
                window_start=(
                    T0
                    + timedelta(minutes=3)
                ),
                window_end=(
                    T0
                    + timedelta(minutes=3)
                ),
            )
        )

        assert (
            _count(session_factory)
            == 2
        )

    def test_unknown_rule_row_uses_default_window_then_fk_error(
        self,
        service,
    ):
        """
        Rules are required by the alerts FK, so an unknown rule
        should surface as AlertStorageError.
        """

        with pytest.raises(AlertStorageError):
            service.save_alert(
                make_alert(
                    rule_name="no_such_rule"
                )
            )

    def test_severity_escalates_but_never_downgrades(
        self,
        service,
    ):
        service.save_alert(
            make_alert(
                severity="MEDIUM"
            )
        )

        upgraded = service.save_alert(
            make_alert(
                severity="HIGH",
                triggered_at=(
                    T0
                    + timedelta(minutes=1)
                ),
            )
        )

        assert (
            upgraded.severity
            == "HIGH"
        )

        downgraded = service.save_alert(
            make_alert(
                severity="INFO",
                triggered_at=(
                    T0
                    + timedelta(minutes=2)
                ),
            )
        )

        assert (
            downgraded.severity
            == "HIGH"
        )

    def test_closed_alert_is_not_reused_for_dedup(
        self,
        service,
        session_factory,
    ):
        first = service.save_alert(
            make_alert()
        )

        service.close_alert(
            first.id
        )

        again = service.save_alert(
            make_alert(
                triggered_at=(
                    T0
                    + timedelta(minutes=1)
                ),
                window_start=(
                    T0
                    + timedelta(minutes=1)
                ),
                window_end=(
                    T0
                    + timedelta(minutes=1)
                ),
            )
        )

        assert again.id != first.id
        assert again.status == STATUS_OPEN

        assert (
            _count(session_factory)
            == 2
        )


class TestGetAlerts:
    @pytest.fixture
    def seeded(
        self,
        service,
    ):
        rows = [
            make_alert(
                source_ip="10.0.0.1",
                severity="INFO",
                triggered_at=T0,
            ),
            make_alert(
                source_ip="10.0.0.2",
                severity="HIGH",
                triggered_at=(
                    T0
                    + timedelta(hours=1)
                ),
            ),
            make_alert(
                source_ip="10.0.0.3",
                severity="HIGH",
                triggered_at=(
                    T0
                    + timedelta(hours=3)
                ),
            ),
            make_alert(
                source_ip="10.0.0.4",
                severity="CRITICAL",
                rule_name=SCAN,
                triggered_at=(
                    T0
                    + timedelta(hours=2)
                ),
            ),
        ]

        return {
            alert.source_ip: service.save_alert(
                alert
            )
            for alert in rows
        }

    def test_no_filters_returns_newest_first(
        self,
        service,
        seeded,
    ):
        ips = [
            str(alert.source_ip)
            for alert in service.get_alerts()
        ]

        assert ips == [
            "10.0.0.3",
            "10.0.0.4",
            "10.0.0.2",
            "10.0.0.1",
        ]

    def test_severity_and_from_time(
        self,
        service,
        seeded,
    ):
        """
        Acceptance:
        get_alerts(severity="HIGH", from_time=...)
        is correctly filtered.
        """

        result = service.get_alerts(
            severity="HIGH",
            from_time=(
                T0
                + timedelta(hours=2)
            ),
        )

        assert [
            str(alert.source_ip)
            for alert in result
        ] == [
            "10.0.0.3"
        ]

    def test_severity_filter_is_case_insensitive(
        self,
        service,
        seeded,
    ):
        assert (
            len(
                service.get_alerts(
                    severity="high"
                )
            )
            == 2
        )

    def test_rule_name_filter(
        self,
        service,
        seeded,
    ):
        assert [
            str(alert.source_ip)
            for alert in service.get_alerts(
                rule_name=SCAN
            )
        ] == [
            "10.0.0.4"
        ]

    def test_time_range_is_inclusive(
        self,
        service,
        seeded,
    ):
        result = service.get_alerts(
            from_time=(
                T0
                + timedelta(hours=1)
            ),
            to_time=(
                T0
                + timedelta(hours=2)
            ),
        )

        assert {
            str(alert.source_ip)
            for alert in result
        } == {
            "10.0.0.2",
            "10.0.0.4",
        }

    def test_status_filter(
        self,
        service,
        seeded,
    ):
        service.close_alert(
            seeded["10.0.0.1"].id
        )

        assert (
            len(
                service.get_alerts(
                    status=STATUS_RESOLVED
                )
            )
            == 1
        )

        assert (
            len(
                service.get_alerts(
                    status=STATUS_OPEN
                )
            )
            == 3
        )

    def test_combined_filters(
        self,
        service,
        seeded,
    ):
        result = service.get_alerts(
            AlertFilters(
                severity="HIGH",
                rule_name=BRUTE,
                status=STATUS_OPEN,
                to_time=(
                    T0
                    + timedelta(hours=1)
                ),
            )
        )

        assert [
            str(alert.source_ip)
            for alert in result
        ] == [
            "10.0.0.2"
        ]

    def test_pagination(
        self,
        service,
        seeded,
    ):
        page1 = service.get_alerts(
            limit=2
        )

        page2 = service.get_alerts(
            limit=2,
            offset=2,
        )

        assert (
            [alert.id for alert in page1]
            + [alert.id for alert in page2]
            == [
                alert.id
                for alert in service.get_alerts()
            ]
        )

    def test_no_match_returns_empty_list(
        self,
        service,
        seeded,
    ):
        assert (
            service.get_alerts(
                severity="CRITICAL",
                rule_name=BRUTE,
            )
            == []
        )


class TestCloseAlert:
    def test_sets_status_and_resolved_at(
        self,
        service,
    ):
        """
        The existing project lifecycle uses RESOLVED rather than CLOSED.
        """

        alert = service.save_alert(
            make_alert()
        )

        before = datetime.now(UTC)

        resolved = service.close_alert(
            alert.id
        )

        after = datetime.now(UTC)

        assert (
            resolved.status
            == STATUS_RESOLVED
        )

        assert (
            resolved.resolved_at
            is not None
        )

        assert (
            before
            <= resolved.resolved_at
            <= after
        )

    def test_is_idempotent_and_keeps_original_resolved_at(
        self,
        service,
    ):
        alert = service.save_alert(
            make_alert()
        )

        first = service.close_alert(
            alert.id
        )

        second = service.close_alert(
            alert.id
        )

        assert (
            second.status
            == STATUS_RESOLVED
        )

        assert (
            second.resolved_at
            == first.resolved_at
        )

    def test_unknown_id_raises(
        self,
        service,
    ):
        with pytest.raises(
            AlertNotFoundError
        ):
            service.close_alert(
                999_999_999
            )