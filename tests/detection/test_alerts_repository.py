"""Unit tests for the AlertsRepository."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, call

import pytest
from sqlalchemy.exc import IntegrityError

from api.models.alert import Alert
from detection_engine.repositories.alerts_repository import AlertsRepository


@pytest.fixture
def session():
    """Provide a mocked SQLAlchemy session."""
    return MagicMock()


@pytest.fixture
def repository(session):
    """Create a repository using the mocked session factory."""
    return AlertsRepository(session_factory=lambda: session)


@pytest.fixture
def sample_alert():
    """Create an unsaved alert object for repository tests."""
    timestamp = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

    return Alert(
        id=1,
        rule_name="brute_force",
        source_ip="192.0.2.10",
        severity="HIGH",
        triggered_at=timestamp,
        event_count=5,
        window_start=timestamp,
        window_end=timestamp + timedelta(minutes=5),
        status="OPEN",
    )


class TestSave:
    """Tests for AlertsRepository.save()."""

    def test_save_commits_refreshes_and_returns_alert(
        self, repository, session
    ):
        result = repository.save(
            rule_name="brute_force",
            source_ip="192.0.2.10",
            severity="HIGH",
            triggered_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            event_count=5,
            window_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
            window_end=datetime(
                2026, 1, 1, 0, 5, tzinfo=timezone.utc
            ),
        )

        assert isinstance(result, Alert)
        assert result.rule_name == "brute_force"
        assert result.source_ip == "192.0.2.10"
        assert result.severity == "HIGH"
        assert result.event_count == 5
        assert result.status == "open"

        session.add.assert_called_once_with(result)
        session.commit.assert_called_once_with()
        session.refresh.assert_called_once_with(result)
        session.close.assert_called_once_with()

    def test_save_uses_supplied_status(self, repository, session):
        result = repository.save(
            rule_name="port_scan",
            source_ip="192.0.2.20",
            severity="CRITICAL",
            triggered_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            event_count=10,
            window_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
            window_end=datetime(
                2026, 1, 1, 0, 5, tzinfo=timezone.utc
            ),
            status="RESOLVED",
        )

        assert result.status == "RESOLVED"
        session.close.assert_called_once_with()

    def test_save_returns_none_and_rolls_back_on_integrity_error(
        self, repository, session
    ):
        session.commit.side_effect = IntegrityError(
            "INSERT",
            {},
            Exception("duplicate"),
        )

        result = repository.save(
            rule_name="brute_force",
            source_ip="192.0.2.10",
            severity="HIGH",
            triggered_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            event_count=5,
            window_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
            window_end=datetime(
                2026, 1, 1, 0, 5, tzinfo=timezone.utc
            ),
        )

        assert result is None
        session.rollback.assert_called_once_with()
        session.refresh.assert_not_called()
        session.close.assert_called_once_with()

    def test_save_closes_session_when_non_integrity_error_occurs(
        self, repository, session
    ):
        session.commit.side_effect = RuntimeError("database unavailable")

        with pytest.raises(RuntimeError, match="database unavailable"):
            repository.save(
                rule_name="brute_force",
                source_ip="192.0.2.10",
                severity="HIGH",
                triggered_at=datetime(
                    2026, 1, 1, tzinfo=timezone.utc
                ),
                event_count=5,
                window_start=datetime(
                    2026, 1, 1, tzinfo=timezone.utc
                ),
                window_end=datetime(
                    2026, 1, 1, 0, 5, tzinfo=timezone.utc
                ),
            )

        session.close.assert_called_once_with()


class TestGetById:
    """Tests for AlertsRepository.get_by_id()."""

    def test_get_by_id_returns_alert(
        self, repository, session, sample_alert
    ):
        session.get.return_value = sample_alert

        result = repository.get_by_id(1)

        assert result is sample_alert
        session.get.assert_called_once_with(Alert, 1)
        session.close.assert_called_once_with()

    def test_get_by_id_returns_none_when_missing(
        self, repository, session
    ):
        session.get.return_value = None

        result = repository.get_by_id(999)

        assert result is None
        session.get.assert_called_once_with(Alert, 999)
        session.close.assert_called_once_with()

    def test_get_by_id_closes_session_after_error(
        self, repository, session
    ):
        session.get.side_effect = RuntimeError("database unavailable")

        with pytest.raises(RuntimeError, match="database unavailable"):
            repository.get_by_id(1)

        session.close.assert_called_once_with()


class TestListAlerts:
    """Tests for AlertsRepository.list_alerts()."""

    def test_list_alerts_returns_query_results(
        self, repository, session, sample_alert
    ):
        query = session.query.return_value
        query.filter.return_value = query
        query.order_by.return_value = query
        query.offset.return_value = query
        query.limit.return_value = query
        query.all.return_value = [sample_alert]

        result = repository.list_alerts()

        assert result == [sample_alert]
        session.query.assert_called_once_with(Alert)
        query.order_by.assert_called_once()
        query.offset.assert_called_once_with(0)
        query.limit.assert_called_once_with(100)
        query.all.assert_called_once_with()
        session.close.assert_called_once_with()

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("rule_name", "brute_force"),
            ("source_ip", "192.0.2.10"),
            ("severity", "HIGH"),
            ("status", "OPEN"),
        ],
    )
    def test_list_alerts_applies_each_filter(
        self, repository, session, field, value
    ):
        query = session.query.return_value
        query.filter.return_value = query
        query.order_by.return_value = query
        query.offset.return_value = query
        query.limit.return_value = query
        query.all.return_value = []

        repository.list_alerts(**{field: value})

        query.filter.assert_called_once()
        query.all.assert_called_once_with()
        session.close.assert_called_once_with()

    def test_list_alerts_combines_filters_and_pagination(
        self, repository, session
    ):
        query = session.query.return_value
        query.filter.return_value = query
        query.order_by.return_value = query
        query.offset.return_value = query
        query.limit.return_value = query
        query.all.return_value = []

        repository.list_alerts(
            rule_name="brute_force",
            source_ip="192.0.2.10",
            severity="HIGH",
            status="OPEN",
            limit=20,
            offset=10,
        )

        assert query.filter.call_count == 4
        query.offset.assert_called_once_with(10)
        query.limit.assert_called_once_with(20)
        query.all.assert_called_once_with()
        session.close.assert_called_once_with()

    def test_list_alerts_closes_session_after_error(
        self, repository, session
    ):
        session.query.side_effect = RuntimeError("database unavailable")

        with pytest.raises(RuntimeError, match="database unavailable"):
            repository.list_alerts()

        session.close.assert_called_once_with()