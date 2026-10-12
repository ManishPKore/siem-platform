"""
Unit tests for api/database.py.

Unlike tests/api/test_models.py, none of this needs a running Postgres:

DSN resolution is pure string-building from env vars, and the
get_session() commit/rollback/close contract is exercised against an
in-memory SQLite engine — it's generic session-lifecycle behaviour, not
anything Postgres-specific.

api/database.py builds POSTGRES_URL and creates its engine at import
time, from whatever's in os.environ at that moment. That means changing
env vars after import has no effect on an already-imported module — so
every test here forces a fresh import via _import_database() after
setting up its env, rather than relying on module-level state.
"""

from __future__ import annotations

import importlib
import sys

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session as SQLAlchemySession


MODULE_NAME = "api.database"

# Every PostgreSQL variable read by api/database.py.
# These are cleared before each test so developer credentials cannot
# interfere with tests that intentionally use a clean environment.
ENV_KEYS = (
    "POSTGRES_URL",
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
    "POSTGRES_HOST",
    "POSTGRES_PORT",
    "POSTGRES_DB",
)


@pytest.fixture
def clean_env(monkeypatch):
    """
    Provide a clean environment for database configuration tests.

    Disable dotenv loading so a local .env file cannot override the
    environment variables deliberately configured by each test.

    Remove api.database from sys.modules so it is imported afresh
    using the environment configured for the current test.
    """
    for key in ENV_KEYS:
        monkeypatch.delenv(key, raising=False)

    # Critical fix: prevent api.database from loading the local .env.
    monkeypatch.setenv("SIEM_LOAD_DOTENV", "false")

    sys.modules.pop(MODULE_NAME, None)

    yield monkeypatch

    # Avoid leaking the freshly imported module into other tests.
    sys.modules.pop(MODULE_NAME, None)


def _import_database():
    """
    Import api.database afresh using the current environment.

    If the module is already loaded, reload it so module-level
    configuration is evaluated again.
    """
    if MODULE_NAME in sys.modules:
        return importlib.reload(sys.modules[MODULE_NAME])

    return importlib.import_module(MODULE_NAME)


# ---------------------------------------------------------------------------
# DSN resolution: POSTGRES_URL path
# ---------------------------------------------------------------------------


class TestPostgresUrlPath:
    def test_uses_postgres_url_verbatim_when_set(self, clean_env):
        clean_env.setenv(
            "POSTGRES_URL",
            "postgresql://siem:secret@dbhost:5433/siem",
        )

        db = _import_database()

        assert (
            db.POSTGRES_URL
            == "postgresql://siem:secret@dbhost:5433/siem"
        )

    def test_engine_is_built_from_postgres_url(self, clean_env):
        clean_env.setenv(
            "POSTGRES_URL",
            "postgresql://siem:secret@dbhost:5433/siem",
        )

        db = _import_database()

        assert db.engine.url.host == "dbhost"
        assert db.engine.url.port == 5433
        assert db.engine.url.database == "siem"
        assert db.engine.url.username == "siem"

    def test_postgres_url_takes_priority_over_discrete_vars(
        self, clean_env
    ):
        """
        POSTGRES_URL takes priority when both configuration methods
        are provided. Individual variables are only a fallback.
        """
        clean_env.setenv(
            "POSTGRES_URL",
            "postgresql://a:b@url-host:5432/url-db",
        )
        clean_env.setenv("POSTGRES_USER", "discrete-user")
        clean_env.setenv("POSTGRES_PASSWORD", "discrete-pass")
        clean_env.setenv("POSTGRES_DB", "discrete-db")
        clean_env.setenv("POSTGRES_HOST", "discrete-host")

        db = _import_database()

        assert db.engine.url.host == "url-host"
        assert db.engine.url.database == "url-db"


# ---------------------------------------------------------------------------
# DSN resolution: fallback to discrete POSTGRES_* variables
# ---------------------------------------------------------------------------


class TestDiscreteVarsFallback:
    def test_builds_dsn_from_discrete_vars(self, clean_env):
        clean_env.setenv("POSTGRES_USER", "siem")
        clean_env.setenv("POSTGRES_PASSWORD", "siem_dev_password")
        clean_env.setenv("POSTGRES_DB", "siem")
        clean_env.setenv("POSTGRES_HOST", "postgres")
        clean_env.setenv("POSTGRES_PORT", "5432")

        db = _import_database()

        assert db.POSTGRES_URL == (
            "postgresql+psycopg2://"
            "siem:siem_dev_password@postgres:5432/siem"
        )

    def test_defaults_host_to_postgres_when_unset(self, clean_env):
        """
        The default hostname is the Docker Compose service name.
        """
        clean_env.setenv("POSTGRES_USER", "siem")
        clean_env.setenv("POSTGRES_PASSWORD", "pw")
        clean_env.setenv("POSTGRES_DB", "siem")

        db = _import_database()

        assert db.engine.url.host == "postgres"

    def test_defaults_port_to_5432_when_unset(self, clean_env):
        clean_env.setenv("POSTGRES_USER", "siem")
        clean_env.setenv("POSTGRES_PASSWORD", "pw")
        clean_env.setenv("POSTGRES_DB", "siem")

        db = _import_database()

        assert db.engine.url.port == 5432

    def test_custom_host_and_port_respected(self, clean_env):
        clean_env.setenv("POSTGRES_USER", "siem")
        clean_env.setenv("POSTGRES_PASSWORD", "pw")
        clean_env.setenv("POSTGRES_DB", "siem")
        clean_env.setenv("POSTGRES_HOST", "db.internal")
        clean_env.setenv("POSTGRES_PORT", "6543")

        db = _import_database()

        assert db.engine.url.host == "db.internal"
        assert db.engine.url.port == 6543


# ---------------------------------------------------------------------------
# Missing / partial credentials
# ---------------------------------------------------------------------------


class TestMissingCredentials:
    def test_nothing_set_raises_runtime_error(self, clean_env):
        with pytest.raises(RuntimeError, match="not configured"):
            _import_database()

    @pytest.mark.parametrize(
        "present",
        [
            {"POSTGRES_USER": "siem"},
            {"POSTGRES_PASSWORD": "pw"},
            {"POSTGRES_DB": "siem"},
            {
                "POSTGRES_USER": "siem",
                "POSTGRES_PASSWORD": "pw",
            },
            {
                "POSTGRES_USER": "siem",
                "POSTGRES_DB": "siem",
            },
        ],
        ids=[
            "user-only",
            "password-only",
            "db-only",
            "missing-db",
            "missing-password",
        ],
    )
    def test_partial_credentials_still_raise(
        self, clean_env, present
    ):
        for key, value in present.items():
            clean_env.setenv(key, value)

        with pytest.raises(RuntimeError, match="not configured"):
            _import_database()

    def test_error_message_mentions_env_example(self, clean_env):
        """
        Developers using a fresh checkout should be directed to
        the environment configuration example.
        """
        with pytest.raises(
            RuntimeError,
            match=r"\.env\.example",
        ):
            _import_database()


# ---------------------------------------------------------------------------
# get_session(): commit / rollback / close contract
#
# Use an in-memory SQLite database instead of PostgreSQL because
# these tests exercise generic SQLAlchemy session lifecycle behaviour.
# ---------------------------------------------------------------------------


class TestGetSessionLifecycle:
    @pytest.fixture
    def db(self, clean_env):
        clean_env.setenv("POSTGRES_URL", "sqlite:///:memory:")

        module = _import_database()

        with module.engine.begin() as conn:
            conn.execute(text("CREATE TABLE t (id INTEGER)"))

        return module

    def test_commits_on_success(self, db):
        with db.get_session() as session:
            session.execute(text("INSERT INTO t VALUES (1)"))

        with db.get_session() as session:
            count = session.execute(
                text("SELECT COUNT(*) FROM t")
            ).scalar()

        assert count == 1

    def test_rolls_back_on_exception(self, db):
        class Boom(Exception):
            pass

        with pytest.raises(Boom):
            with db.get_session() as session:
                session.execute(text("INSERT INTO t VALUES (1)"))
                raise Boom("something failed mid-transaction")

        with db.get_session() as session:
            count = session.execute(
                text("SELECT COUNT(*) FROM t")
            ).scalar()

        assert count == 0

    def test_exception_propagates_to_caller(self, db):
        """
        get_session() must not swallow the original exception.
        """
        class Boom(Exception):
            pass

        with pytest.raises(Boom, match="specific failure"):
            with db.get_session():
                raise Boom("specific failure")

    def test_session_closed_after_successful_block(
        self, db, monkeypatch
    ):
        closed = []
        original_close = SQLAlchemySession.close

        def spy_close(session):
            closed.append(True)
            return original_close(session)

        monkeypatch.setattr(
            SQLAlchemySession,
            "close",
            spy_close,
        )

        with db.get_session() as session:
            session.execute(text("SELECT 1"))

        assert closed == [True]

    def test_session_closed_even_after_exception(
        self, db, monkeypatch
    ):
        closed = []
        original_close = SQLAlchemySession.close

        def spy_close(session):
            closed.append(True)
            return original_close(session)

        monkeypatch.setattr(
            SQLAlchemySession,
            "close",
            spy_close,
        )

        with pytest.raises(ValueError):
            with db.get_session():
                raise ValueError("boom")

        assert closed == [True]

    def test_yields_a_usable_session(self, db):
        with db.get_session() as session:
            assert isinstance(session, SQLAlchemySession)
            assert session.execute(
                text("SELECT 1")
            ).scalar() == 1