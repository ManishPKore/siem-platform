"""
Integration tests for api/models against a REAL PostgreSQL instance.

Unlike the producer/consumer tests (which mock Kafka entirely), these
cannot be meaningfully mocked: the whole point is to verify that the
SQLAlchemy models agree with the schema in scripts/init_db.sql, and that
the database's own CHECK constraints, FOREIGN KEYs and JSONB/INET column
types behave as expected. A mocked session would assert nothing about
any of that.

Requires a running Postgres (`docker compose up -d postgres`). Skips the
whole module if one isn't reachable, so a dev without Docker running
doesn't see spurious failures.

Isolation: each test runs inside a transaction that is rolled back on
teardown, so tests never see each other's rows and the developer's local
database is left untouched.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DataError, IntegrityError, OperationalError
from sqlalchemy.orm import Session

from api.models import Alert, Base, Event, Rule, User


# --------------------------------------------------------------------------- #
# Connection / fixtures
# --------------------------------------------------------------------------- #

def _database_url() -> str:
    """Resolve the test DSN the same way api/database.py does.

    Defaults to localhost because tests run on the host, not inside the
    compose network (where the host would be `postgres`).
    """
    url = os.environ.get("POSTGRES_URL")
    if url:
        # SQLAlchemy 2.x needs an explicit driver; .env ships a bare
        # postgresql:// URL for general use.
        return url.replace("postgresql://", "postgresql+psycopg2://", 1)

    user = os.environ.get("POSTGRES_USER", "siem")
    password = os.environ.get("POSTGRES_PASSWORD", "siem_dev_password")
    host = os.environ.get("POSTGRES_TEST_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    db = os.environ.get("POSTGRES_DB", "siem")
    return f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{db}"


@pytest.fixture(scope="module")
def engine():
    eng = create_engine(_database_url(), future=True)
    try:
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable, skipping DB tests: {exc}")
    return eng


@pytest.fixture(scope="module", autouse=True)
def schema_exists(engine):
    """Fail loudly if init_db.sql hasn't been applied.

    A healthy container does NOT imply a populated schema — the health
    check only runs pg_isready. This turns that silent gap into an
    explicit, readable failure.
    """
    expected = {"users", "rules", "events", "alerts"}
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public'"
            )
        ).scalars().all()
    missing = expected - set(rows)
    if missing:
        pytest.fail(
            f"Missing tables {sorted(missing)}. Run scripts/init_db.sql "
            "(or recreate the postgres container so the init script runs)."
        )


@pytest.fixture
def session(engine):
    """A session wrapped in a transaction that is always rolled back."""
    connection = engine.connect()
    transaction = connection.begin()
    sess = Session(bind=connection, future=True)
    try:
        yield sess
    finally:
        sess.close()
        # A test that triggered an IntegrityError may have already aborted
        # the transaction; rolling back again would warn noisily.
        if transaction.is_active:
            transaction.rollback()
        connection.close()


@pytest.fixture
def rule(session) -> Rule:
    """A persisted rule; alerts need one to satisfy the FK."""
    r = Rule(
        rule_name=f"test_rule_{uuid.uuid4().hex[:8]}",
        description="Test rule",
        threshold=5,
        window_minutes=10,
    )
    session.add(r)
    session.flush()
    return r


def make_event(**overrides) -> Event:
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        source_ip="10.0.0.5",
        event_type="failed_login",
        severity="MEDIUM",
        source="ssh",
        raw_message="Failed password for admin from 10.0.0.5 port 22 ssh2",
        metadata_={},
    )
    defaults.update(overrides)
    return Event(**defaults)


def make_alert(rule_name: str, **overrides) -> Alert:
    now = datetime.now(timezone.utc)
    defaults = dict(
        rule_name=rule_name,
        source_ip="10.0.0.5",
        severity="HIGH",
        triggered_at=now,
        event_count=7,
        window_start=now - timedelta(minutes=10),
        window_end=now,
    )
    defaults.update(overrides)
    return Alert(**defaults)


# --------------------------------------------------------------------------- #
# Schema / metadata parity
# --------------------------------------------------------------------------- #

class TestSchemaParity:
    def test_all_models_registered_on_metadata(self):
        assert set(Base.metadata.tables) == {"users", "rules", "events", "alerts"}

    @pytest.mark.parametrize(
        "table,expected",
        [
            (
                "events",
                {
                    "id", "event_id", "timestamp", "source_ip", "event_type",
                    "severity", "source", "raw_message", "metadata",
                    "created_at",
                },
            ),
            (
                "alerts",
                {
                    "id", "rule_name", "source_ip", "severity", "triggered_at",
                    "event_count", "window_start", "window_end", "status",
                    "created_at", "updated_at",
                },
            ),
            (
                "rules",
                {
                    "id", "rule_name", "description", "threshold",
                    "window_minutes", "enabled", "created_at", "updated_at",
                },
            ),
        ],
    )
    def test_model_columns_match_acceptance_criteria(self, table, expected):
        assert set(Base.metadata.tables[table].columns.keys()) == expected

    def test_orm_columns_match_live_database(self, engine):
        """The ORM and init_db.sql must not drift apart."""
        with engine.connect() as conn:
            for table in ("events", "alerts", "rules", "users"):
                db_cols = set(
                    conn.execute(
                        text(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_schema='public' AND table_name=:t"
                        ),
                        {"t": table},
                    ).scalars().all()
                )
                orm_cols = set(Base.metadata.tables[table].columns.keys())
                assert orm_cols == db_cols, (
                    f"{table}: ORM has {orm_cols - db_cols}, "
                    f"DB has {db_cols - orm_cols}"
                )

    @pytest.mark.parametrize(
        "index_name",
        [
            "idx_events_timestamp",
            "idx_events_source_ip",
            "idx_events_event_type",
            "idx_alerts_triggered_at",
        ],
    )
    def test_required_indexes_exist(self, engine, index_name):
        with engine.connect() as conn:
            found = conn.execute(
                text("SELECT 1 FROM pg_indexes WHERE indexname = :n"),
                {"n": index_name},
            ).scalar()
        assert found == 1, f"missing required index {index_name}"


# --------------------------------------------------------------------------- #
# Event
# --------------------------------------------------------------------------- #

class TestEvent:
    def test_round_trips(self, session):
        event = make_event()
        session.add(event)
        session.flush()

        fetched = session.get(Event, event.id)
        assert fetched.event_type == "failed_login"
        assert fetched.severity == "MEDIUM"
        assert fetched.source == "ssh"
        assert str(fetched.source_ip) == "10.0.0.5"

    def test_event_id_autogenerated_and_unique(self, session):
        e1, e2 = make_event(), make_event()
        session.add_all([e1, e2])
        session.flush()

        assert isinstance(e1.event_id, uuid.UUID)
        assert e1.event_id != e2.event_id

    def test_duplicate_event_id_rejected(self, session):
        shared = uuid.uuid4()
        session.add(make_event(event_id=shared))
        session.flush()
        session.add(make_event(event_id=shared))

        with pytest.raises(IntegrityError):
            session.flush()

    def test_jsonb_metadata_round_trips_nested_structure(self, session):
        """Enrichment (GeoIP/ASN) lands here — nested dicts must survive."""
        enrichment = {
            "geoip": {"country": "US", "city": "Ashburn", "lat": 39.0438},
            "asn": 15169,
            "tags": ["bruteforce", "external"],
        }
        event = make_event(metadata_=enrichment)
        session.add(event)
        session.flush()
        session.expire(event)

        assert session.get(Event, event.id).metadata_ == enrichment

    def test_metadata_defaults_to_empty_dict(self, session):
        event = make_event()
        session.add(event)
        session.flush()
        assert event.metadata_ == {}

    @pytest.mark.parametrize("severity", ["INFO", "MEDIUM", "HIGH", "CRITICAL"])
    def test_accepts_canonical_severities(self, session, severity):
        """Must match consumers.schemas.Severity exactly (Issue #6)."""
        session.add(make_event(severity=severity))
        session.flush()

    @pytest.mark.parametrize("severity", ["medium", "low", "LOW", "bogus", ""])
    def test_rejects_non_canonical_severity(self, session, severity):
        session.add(make_event(severity=severity))
        with pytest.raises((IntegrityError, DataError)):
            session.flush()

    def test_rejects_invalid_source_ip(self, session):
        session.add(make_event(source_ip="not-an-ip"))
        with pytest.raises((IntegrityError, DataError)):
            session.flush()

    def test_accepts_ipv6_source_ip(self, session):
        event = make_event(source_ip="2001:db8::1")
        session.add(event)
        session.flush()
        assert "2001:db8::1" in str(event.source_ip)

    def test_accepts_loopback_for_auth_events(self, session):
        """normalize_auth() uses 127.0.0.1 for local sudo (Issue #6)."""
        event = make_event(
            source_ip="127.0.0.1", event_type="sudo_attempt", source="auth"
        )
        session.add(event)
        session.flush()
        assert str(event.source_ip) == "127.0.0.1"

    def test_timestamp_preserved_as_timezone_aware(self, session):
        ts = datetime(2026, 9, 10, 10, 15, 32, tzinfo=timezone.utc)
        event = make_event(timestamp=ts)
        session.add(event)
        session.flush()
        session.expire(event)

        fetched = session.get(Event, event.id)
        assert fetched.timestamp.tzinfo is not None
        assert fetched.timestamp == ts

    @pytest.mark.parametrize("field", ["timestamp", "event_type", "severity", "source"])
    def test_required_fields_rejected_when_null(self, session, field):
        session.add(make_event(**{field: None}))
        with pytest.raises(IntegrityError):
            session.flush()


# --------------------------------------------------------------------------- #
# Rule
# --------------------------------------------------------------------------- #

class TestRule:
    def test_round_trips_with_defaults(self, session, rule):
        fetched = session.get(Rule, rule.id)
        assert fetched.threshold == 5
        assert fetched.window_minutes == 10
        assert fetched.enabled is True

    def test_rule_name_unique(self, session, rule):
        session.add(Rule(rule_name=rule.rule_name, threshold=1, window_minutes=1))
        with pytest.raises(IntegrityError):
            session.flush()

    @pytest.mark.parametrize("threshold", [0, -1])
    def test_non_positive_threshold_rejected(self, session, threshold):
        session.add(
            Rule(rule_name=f"r_{uuid.uuid4().hex[:8]}",
                 threshold=threshold, window_minutes=10)
        )
        with pytest.raises(IntegrityError):
            session.flush()

    @pytest.mark.parametrize("window", [0, -5])
    def test_non_positive_window_rejected(self, session, window):
        session.add(
            Rule(rule_name=f"r_{uuid.uuid4().hex[:8]}",
                 threshold=5, window_minutes=window)
        )
        with pytest.raises(IntegrityError):
            session.flush()

    def test_can_be_disabled(self, session):
        r = Rule(
            rule_name=f"r_{uuid.uuid4().hex[:8]}",
            threshold=5, window_minutes=10, enabled=False,
        )
        session.add(r)
        session.flush()
        assert r.enabled is False


# --------------------------------------------------------------------------- #
# Alert
# --------------------------------------------------------------------------- #

class TestAlert:
    def test_round_trips_with_default_status(self, session, rule):
        alert = make_alert(rule.rule_name)
        session.add(alert)
        session.flush()

        fetched = session.get(Alert, alert.id)
        assert fetched.status == "open"
        assert fetched.event_count == 7

    def test_relationship_to_rule_resolves(self, session, rule):
        alert = make_alert(rule.rule_name)
        session.add(alert)
        session.flush()

        assert alert.rule.rule_name == rule.rule_name
        assert alert in rule.alerts

    def test_unknown_rule_name_rejected_by_fk(self, session):
        session.add(make_alert("rule_that_does_not_exist"))
        with pytest.raises(IntegrityError):
            session.flush()

    @pytest.mark.parametrize("status", ["open", "closed"])
    def test_accepts_valid_statuses(self, session, rule, status):
        session.add(make_alert(rule.rule_name, status=status))
        session.flush()

    @pytest.mark.parametrize("status", ["OPEN", "resolved", "pending", ""])
    def test_rejects_invalid_status(self, session, rule, status):
        session.add(make_alert(rule.rule_name, status=status))
        with pytest.raises((IntegrityError, DataError)):
            session.flush()

    @pytest.mark.parametrize("severity", ["INFO", "MEDIUM", "HIGH", "CRITICAL"])
    def test_accepts_canonical_severities(self, session, rule, severity):
        session.add(make_alert(rule.rule_name, severity=severity))
        session.flush()

    @pytest.mark.parametrize("severity", ["high", "low", "bogus"])
    def test_rejects_non_canonical_severity(self, session, rule, severity):
        session.add(make_alert(rule.rule_name, severity=severity))
        with pytest.raises((IntegrityError, DataError)):
            session.flush()

    @pytest.mark.parametrize("count", [0, -3])
    def test_non_positive_event_count_rejected(self, session, rule, count):
        session.add(make_alert(rule.rule_name, event_count=count))
        with pytest.raises(IntegrityError):
            session.flush()

    def test_window_end_before_start_rejected(self, session, rule):
        now = datetime.now(timezone.utc)
        session.add(
            make_alert(
                rule.rule_name,
                window_start=now,
                window_end=now - timedelta(minutes=5),
            )
        )
        with pytest.raises(IntegrityError):
            session.flush()

    def test_equal_window_bounds_allowed(self, session, rule):
        """A zero-length window is degenerate but not invalid."""
        now = datetime.now(timezone.utc)
        session.add(make_alert(rule.rule_name, window_start=now, window_end=now))
        session.flush()

    def test_deleting_rule_with_alerts_is_restricted(self, session, rule):
        """ON DELETE RESTRICT: alerts must not be silently orphaned."""
        session.add(make_alert(rule.rule_name))
        session.flush()

        # Raw DELETE goes straight to the server, so RESTRICT fires on the
        # execute itself rather than at flush time.
        with pytest.raises(IntegrityError):
            session.execute(
                text("DELETE FROM rules WHERE rule_name = :n"),
                {"n": rule.rule_name},
            )


# --------------------------------------------------------------------------- #
# User
# --------------------------------------------------------------------------- #

class TestUser:
    def _user(self, **overrides) -> User:
        suffix = uuid.uuid4().hex[:8]
        defaults = dict(
            username=f"analyst_{suffix}",
            email=f"analyst_{suffix}@example.com",
            password_hash="$2b$12$fakebcrypthashvalueforunittests",
        )
        defaults.update(overrides)
        return User(**defaults)

    def test_round_trips_with_defaults(self, session):
        user = self._user()
        session.add(user)
        session.flush()

        fetched = session.get(User, user.id)
        assert fetched.role == "analyst"
        assert fetched.is_active is True

    @pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
    def test_accepts_valid_roles(self, session, role):
        session.add(self._user(role=role))
        session.flush()

    @pytest.mark.parametrize("role", ["superuser", "ADMIN", "root", ""])
    def test_rejects_invalid_role(self, session, role):
        session.add(self._user(role=role))
        with pytest.raises((IntegrityError, DataError)):
            session.flush()

    def test_username_unique(self, session):
        user = self._user()
        session.add(user)
        session.flush()
        session.add(self._user(username=user.username))

        with pytest.raises(IntegrityError):
            session.flush()

    def test_email_unique(self, session):
        user = self._user()
        session.add(user)
        session.flush()
        session.add(self._user(email=user.email))

        with pytest.raises(IntegrityError):
            session.flush()


# --------------------------------------------------------------------------- #
# Timestamp behaviour
# --------------------------------------------------------------------------- #

class TestTimestamps:
    def test_created_at_populated_by_server_default(self, session, rule):
        session.refresh(rule)
        assert rule.created_at is not None
        assert rule.created_at.tzinfo is not None

    def test_updated_at_trigger_overwrites_stale_value(self, session, rule):
        """Verifies the set_updated_at() trigger from init_db.sql fires.

        Note: Postgres now() returns the *transaction* start time, so it
        does not advance within a single transaction. Backdating the row
        first makes the trigger's effect observable regardless.
        """
        stale = datetime(2000, 1, 1, tzinfo=timezone.utc)
        session.execute(
            text("UPDATE rules SET updated_at = :s WHERE id = :i"),
            {"s": stale, "i": rule.id},
        )
        session.expire(rule)
        # The trigger fires on that UPDATE too, so it should already be
        # refusing to accept the backdated value.
        assert rule.updated_at > stale

        session.execute(
            text("UPDATE rules SET threshold = 99 WHERE id = :i"), {"i": rule.id}
        )
        session.expire(rule)

        assert rule.threshold == 99
        assert rule.updated_at > stale