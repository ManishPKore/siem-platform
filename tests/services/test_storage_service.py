"""
tests/services/test_storage_service.py

Unit tests for EventStorageService (api/services/storage_service.py),
run with a mocked SQLAlchemy Session so they need no live Postgres
instance. See test_storage_service_integration.py for the real-DB round
trip against actual Postgres.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.exc import IntegrityError, OperationalError

from api.services.storage_service import EventStorageError, EventStorageService
from consumers.schemas import EventType, LogEvent, Severity, SourceType


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #


def _ssh_event(**overrides) -> LogEvent:
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        source_ip="203.0.113.5",
        event_type="failed_login",
        severity="MEDIUM",
        raw_message="Failed password for invalid user admin from 203.0.113.5 port 51234 ssh2",
        source="ssh",
        username="admin",
        auth_method="password",
        success=False,
    )
    defaults.update(overrides)
    return LogEvent(**defaults)


def _web_event(**overrides) -> LogEvent:
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        source_ip="198.51.100.23",
        event_type="web_request",
        severity="INFO",
        raw_message="GET /login HTTP/1.1 200",
        source="web",
        method="GET",
        path="/login",
        status_code=200,
        user_agent="Mozilla/5.0",
        bytes_sent=1024,
    )
    defaults.update(overrides)
    return LogEvent(**defaults)


def _firewall_event(**overrides) -> LogEvent:
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        source_ip="198.51.100.44",
        event_type="firewall_drop",
        severity="MEDIUM",
        raw_message="IPTABLES-DROP SRC=198.51.100.44 DST=10.0.0.5",
        source="firewall",
        action="DROP",
        dest_ip="10.0.0.5",
        dest_port=22,
        protocol="TCP",
    )
    defaults.update(overrides)
    return LogEvent(**defaults)


def _session_factory(session: MagicMock):
    return lambda: session


# --------------------------------------------------------------------------- #
# save_event -> save_events_bulk delegation
# --------------------------------------------------------------------------- #


class TestSaveEvent:
    def test_delegates_to_bulk_with_single_item_list(self):
        service = EventStorageService(session_factory=lambda: MagicMock())
        service.save_events_bulk = MagicMock(return_value=1)
        event = _ssh_event()

        result = service.save_event(event)

        service.save_events_bulk.assert_called_once_with([event])
        assert result == 1


# --------------------------------------------------------------------------- #
# save_events_bulk — statement construction
# --------------------------------------------------------------------------- #


class TestSaveEventsBulk:
    def test_empty_list_short_circuits(self):
        session = MagicMock()
        service = EventStorageService(session_factory=_session_factory(session))

        result = service.save_events_bulk([])

        assert result == 0
        session.execute.assert_not_called()

    def test_batch_of_100_is_a_single_execute_call(self):
        """A batch under chunk_size must be ONE execute() call -- never a
        loop of individual inserts."""
        session = MagicMock()
        session.execute.return_value.rowcount = 100
        service = EventStorageService(session_factory=_session_factory(session))

        events = [_ssh_event(source_ip=f"10.0.{i // 256}.{i % 256}") for i in range(100)]
        result = service.save_events_bulk(events)

        assert session.execute.call_count == 1
        assert session.commit.call_count == 1
        assert result == 100

    def test_uses_on_conflict_do_nothing_on_event_id(self):
        session = MagicMock()
        session.execute.return_value.rowcount = 1
        service = EventStorageService(session_factory=_session_factory(session))

        with patch("api.services.storage_service.pg_insert") as mock_pg_insert:
            values_stmt = mock_pg_insert.return_value.values.return_value
            service.save_events_bulk([_ssh_event()])

        values_stmt.on_conflict_do_nothing.assert_called_once_with(
            index_elements=["event_id"]
        )

    def test_values_contains_all_rows_with_correct_event_ids(self):
        session = MagicMock()
        session.execute.return_value.rowcount = 2
        service = EventStorageService(session_factory=_session_factory(session))
        events = [_ssh_event(), _web_event()]

        with patch("api.services.storage_service.pg_insert") as mock_pg_insert:
            service.save_events_bulk(events)

        rows = mock_pg_insert.return_value.values.call_args[0][0]
        assert len(rows) == 2
        assert {row["event_id"] for row in rows} == {e.event_id for e in events}

    def test_core_fields_mapped_onto_row_columns(self):
        session = MagicMock()
        session.execute.return_value.rowcount = 1
        service = EventStorageService(session_factory=_session_factory(session))
        event = _web_event()

        with patch("api.services.storage_service.pg_insert") as mock_pg_insert:
            service.save_events_bulk([event])

        row = mock_pg_insert.return_value.values.call_args[0][0][0]
        assert row["event_id"] == event.event_id
        assert row["timestamp"] == event.timestamp
        assert row["source_ip"] == "198.51.100.23"
        assert row["event_type"] == "web_request"
        assert row["severity"] == "INFO"
        assert row["source"] == "web"
        assert row["raw_message"] == event.raw_message

    def test_source_specific_fields_go_into_metadata_not_columns(self):
        session = MagicMock()
        session.execute.return_value.rowcount = 1
        service = EventStorageService(session_factory=_session_factory(session))

        with patch("api.services.storage_service.pg_insert") as mock_pg_insert:
            service.save_events_bulk([_ssh_event()])

        row = mock_pg_insert.return_value.values.call_args[0][0][0]
        metadata = row["metadata"]
        assert metadata["username"] == "admin"
        assert metadata["auth_method"] == "password"
        assert metadata["success"] is False
        for core_field in ("event_id", "timestamp", "source_ip", "event_type", "severity", "source", "raw_message"):
            assert core_field not in metadata

    def test_metadata_serializes_ip_address_fields_as_strings(self):
        session = MagicMock()
        session.execute.return_value.rowcount = 1
        service = EventStorageService(session_factory=_session_factory(session))

        with patch("api.services.storage_service.pg_insert") as mock_pg_insert:
            service.save_events_bulk([_firewall_event()])

        row = mock_pg_insert.return_value.values.call_args[0][0][0]
        assert row["metadata"]["dest_ip"] == "10.0.0.5"
        assert isinstance(row["metadata"]["dest_ip"], str)

    def test_duplicate_event_id_does_not_raise(self):
        """A conflicting insert should just report fewer rows inserted
        (DB skipped it via ON CONFLICT DO NOTHING) -- never bubble up as
        an exception from this layer."""
        session = MagicMock()
        session.execute.return_value.rowcount = 0
        service = EventStorageService(session_factory=_session_factory(session))

        result = service.save_events_bulk([_ssh_event()])

        assert result == 0


# --------------------------------------------------------------------------- #
# Chunking
# --------------------------------------------------------------------------- #


class TestChunking:
    def test_batch_larger_than_chunk_size_is_split_into_multiple_transactions(self):
        session = MagicMock()
        session.execute.return_value.rowcount = 10  # per chunk
        service = EventStorageService(
            session_factory=_session_factory(session), chunk_size=10
        )

        events = [_ssh_event(source_ip=f"10.0.{i // 256}.{i % 256}") for i in range(25)]
        result = service.save_events_bulk(events)

        # 25 events / chunk_size 10 -> 3 chunks (10 + 10 + 5)
        assert session.execute.call_count == 3
        assert session.commit.call_count == 3
        assert result == 30  # sum of the (mocked) rowcount per chunk

    def test_each_chunk_never_exceeds_chunk_size_rows(self):
        session = MagicMock()
        session.execute.return_value.rowcount = 1
        service = EventStorageService(
            session_factory=_session_factory(session), chunk_size=10
        )
        events = [_ssh_event(source_ip=f"10.0.{i // 256}.{i % 256}") for i in range(25)]

        with patch("api.services.storage_service.pg_insert") as mock_pg_insert:
            service.save_events_bulk(events)

        chunk_sizes = [
            len(call.args[0]) for call in mock_pg_insert.return_value.values.call_args_list
        ]
        assert chunk_sizes == [10, 10, 5]

    def test_batch_at_exactly_chunk_size_is_one_transaction(self):
        session = MagicMock()
        session.execute.return_value.rowcount = 10
        service = EventStorageService(
            session_factory=_session_factory(session), chunk_size=10
        )
        events = [_ssh_event(source_ip=f"10.0.{i // 256}.{i % 256}") for i in range(10)]

        service.save_events_bulk(events)

        assert session.execute.call_count == 1


# --------------------------------------------------------------------------- #
# Retry / error handling
# --------------------------------------------------------------------------- #


class TestRetryBehavior:
    def test_retries_on_operational_error_then_succeeds(self):
        session = MagicMock()
        ok_result = MagicMock(rowcount=1)
        session.execute.side_effect = [
            OperationalError("stmt", {}, Exception("connection refused")),
            ok_result,
        ]
        service = EventStorageService(
            session_factory=_session_factory(session), max_retries=3
        )

        result = service.save_events_bulk([_ssh_event()])

        assert result == 1
        assert session.execute.call_count == 2
        session.rollback.assert_called_once()
        session.commit.assert_called_once()
        assert service.stats.retry_attempts == 1

    def test_raises_event_storage_error_after_exhausting_retries(self):
        """Connection errors are logged and retried -- never silently
        swallowed. Exhausting the retry budget must raise."""
        session = MagicMock()
        session.execute.side_effect = OperationalError("stmt", {}, Exception("down"))
        service = EventStorageService(
            session_factory=_session_factory(session), max_retries=2
        )

        with pytest.raises(EventStorageError):
            service.save_events_bulk([_ssh_event()])

        assert session.execute.call_count == 3  # initial attempt + 2 retries
        assert session.rollback.call_count == 3
        session.commit.assert_not_called()
        assert service.stats.hard_failures == 1

    def test_non_transient_db_error_is_not_retried(self):
        """A CHECK-constraint violation or similar IntegrityError is not
        a connection problem -- it must fail fast on the first attempt,
        not burn through the retry budget."""
        session = MagicMock()
        integrity_error = IntegrityError("stmt", {}, Exception("check constraint violated"))
        session.execute.side_effect = integrity_error
        service = EventStorageService(
            session_factory=_session_factory(session), max_retries=3
        )

        with pytest.raises(IntegrityError):
            service.save_events_bulk([_ssh_event()])

        assert session.execute.call_count == 1  # no retries
        session.rollback.assert_called_once()
        assert service.stats.hard_failures == 1
        assert service.stats.retry_attempts == 0

    def test_session_is_always_closed_on_success(self):
        session = MagicMock()
        session.execute.return_value.rowcount = 1
        service = EventStorageService(session_factory=_session_factory(session))

        service.save_events_bulk([_ssh_event()])

        session.close.assert_called_once()

    def test_session_is_always_closed_after_exhausted_retries(self):
        session = MagicMock()
        session.execute.side_effect = OperationalError("stmt", {}, Exception("down"))
        service = EventStorageService(
            session_factory=_session_factory(session), max_retries=1
        )

        with pytest.raises(EventStorageError):
            service.save_events_bulk([_ssh_event()])

        assert session.close.call_count == 2  # once per attempt

    def test_session_is_always_closed_after_non_transient_error(self):
        session = MagicMock()
        session.execute.side_effect = IntegrityError("stmt", {}, Exception("bad"))
        service = EventStorageService(session_factory=_session_factory(session))

        with pytest.raises(IntegrityError):
            service.save_events_bulk([_ssh_event()])

        session.close.assert_called_once()


# --------------------------------------------------------------------------- #
# Stats
# --------------------------------------------------------------------------- #


class TestStats:
    def test_stats_track_received_inserted_and_duplicates(self):
        session = MagicMock()
        session.execute.return_value.rowcount = 3  # 3 of 5 actually inserted
        service = EventStorageService(session_factory=_session_factory(session))

        events = [_ssh_event(source_ip=f"10.0.0.{i}") for i in range(5)]
        service.save_events_bulk(events)

        assert service.stats.events_received == 5
        assert service.stats.events_inserted == 3
        assert service.stats.events_duplicate == 2

    def test_stats_accumulate_across_multiple_calls(self):
        session = MagicMock()
        session.execute.return_value.rowcount = 1
        service = EventStorageService(session_factory=_session_factory(session))

        service.save_events_bulk([_ssh_event()])
        service.save_events_bulk([_ssh_event()])

        assert service.stats.events_received == 2
        assert service.stats.events_inserted == 2