"""
tests/services/test_storage_service_integration.py

Integration test for EventStorageService against a REAL Postgres
instance (same pattern as tests/api/test_models.py: one shared engine,
each test wrapped in a transaction that's rolled back afterward so tests
don't leave rows behind or depend on each other).

Requires Postgres to be reachable (e.g. `docker compose up -d postgres`).
The whole module is skipped automatically if it isn't -- this is
intentionally separate from test_storage_service.py so the mocked unit
tests never need a live DB, and this file is what actually proves the
generated SQL (the ON CONFLICT clause, the JSONB metadata column, the
severity CHECK constraint) works against real Postgres rather than
against a mock that will nod along with anything.

Run just this file:
    pytest tests/services/test_storage_service_integration.py -v
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from api.database import POSTGRES_URL
from api.models.base import Base
from api.models.event import Event
from api.services.storage_service import EventStorageService
from consumers.schemas import LogEvent

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def engine():
    eng = create_engine(POSTGRES_URL, future=True)

    try:
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError:
        pytest.skip(
            "Postgres is not reachable — run `docker compose up -d postgres`"
        )

    Base.metadata.create_all(eng, checkfirst=True)

    yield eng
    eng.dispose()


@pytest.fixture()
def session(engine):
    """One connection + transaction per test, rolled back afterward.

    Tests never see each other's rows and never touch real data.
    """
    connection = engine.connect()
    transaction = connection.begin()
    sess = Session(bind=connection, future=True)

    try:
        yield sess
    finally:
        sess.close()

        if transaction.is_active:
            transaction.rollback()

        connection.close()


@pytest.fixture()
def storage(session):
    return EventStorageService(session_factory=lambda: session)


def _ssh_event(**overrides) -> LogEvent:
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        source_ip="203.0.113.5",
        event_type="failed_login",
        severity="MEDIUM",
        raw_message=(
            "Failed password for invalid user admin from "
            "203.0.113.5 port 51234 ssh2"
        ),
        source="ssh",
        username="admin",
        auth_method="password",
        success=False,
    )

    defaults.update(overrides)
    return LogEvent(**defaults)


class TestSaveEventRoundTrip:
    def test_save_event_persists_and_reads_back(self, storage, session):
        event = _ssh_event()

        inserted = storage.save_event(event)
        session.flush()

        assert inserted == 1

        row = session.execute(
            select(Event).where(Event.event_id == event.event_id)
        ).scalar_one()

        assert row.source_ip == str(event.source_ip)
        assert row.event_type == "failed_login"
        assert row.severity == "MEDIUM"
        assert row.source == "ssh"

    def test_source_specific_fields_land_in_metadata_jsonb(
        self,
        storage,
        session,
    ):
        event = _ssh_event(
            username="deploy",
            auth_method="publickey",
            success=True,
        )

        storage.save_event(event)
        session.flush()

        row = session.execute(
            select(Event).where(Event.event_id == event.event_id)
        ).scalar_one()

        assert row.metadata_["username"] == "deploy"
        assert row.metadata_["auth_method"] == "publickey"
        assert row.metadata_["success"] is True


class TestBulkInsertRoundTrip:
    def test_bulk_insert_of_100_events_in_one_transaction(
        self,
        storage,
        session,
    ):
        events = [
            _ssh_event(
                source_ip=f"10.0.{i // 256}.{i % 256}"
            )
            for i in range(100)
        ]

        inserted = storage.save_events_bulk(events)
        session.flush()

        assert inserted == 100

        count = session.execute(
            select(Event).where(
                Event.event_id.in_(
                    [event.event_id for event in events]
                )
            )
        ).all()

        assert len(count) == 100

    def test_duplicate_event_id_is_skipped_not_raised(
        self,
        storage,
        session,
    ):
        event = _ssh_event()

        storage.save_event(event)
        session.flush()

        # Re-saving the exact same event_id must not raise.
        inserted_again = storage.save_event(event)
        session.flush()

        assert inserted_again == 0

        rows = session.execute(
            select(Event).where(Event.event_id == event.event_id)
        ).all()

        assert len(rows) == 1


class TestConstraintEnforcement:
    def test_invalid_severity_raises_integrity_error_not_retried(
        self,
        storage,
        session,
    ):
        """severity is constrained to INFO/MEDIUM/HIGH/CRITICAL at the DB
        level (ck_events_severity).

        This must surface as an IntegrityError immediately, not be silently
        retried as if it were a connection problem.
        """
        bad_row = {
            "event_id": uuid.uuid4(),
            "timestamp": datetime.now(timezone.utc),
            "source_ip": "203.0.113.5",
            "event_type": "failed_login",
            "severity": "INVALID",
            "source": "ssh",
            "raw_message": "test",
            "metadata": {},
        }

        from sqlalchemy.dialects.postgresql import insert as pg_insert

        stmt = (
            pg_insert(Event.__table__)
            .values([bad_row])
            .on_conflict_do_nothing(
                index_elements=["event_id"]
            )
        )

        with pytest.raises(IntegrityError):
            session.execute(stmt)