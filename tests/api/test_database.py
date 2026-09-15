"""
Unit tests for api/database.py.

Unlike tests/api/test_models.py, none of this needs a running Postgres:
DSN resolution is pure string-building from env vars, and the
get_session() commit/rollback/close contract is exercised against an
in-memory SQLite engine — it's generic session-lifecycle behaviour, not
anything Postgres-specific.

api/database.py builds POSTGRES_URL and creates its engine at *import*
time, from whatever's in os.environ at that moment. That means changing
env vars after import has no effect on an already-imported module — so
every test here forces a fresh import via _reload_database() after
setting up its env, rather than relying on module-level state.
"""

from __future__ import annotations

import importlib
import sys

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session as SQLAlchemySession

MODULE_NAME = "api.database"

# Every var api/database.py reads. Cleared before each test so no
# developer's real .env (loaded by whatever runs pytest) leaks into a
# test that's deliberately checking the "nothing is set" case.
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
    """A hermetic environment: none of the POSTGRES_* vars are set, and
    api.database is not yet imported for this test."""
    for key in ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    sys.modules.pop(MODULE_NAME, None)
    yield monkeypatch
    # Leave a clean slate for whatever imports api.database next,
    # in this test file or elsewhere in the suite.
    sys.modules.pop(MODULE_NAME, None)


def _import_database():
    """(Re-)import api.database fresh, picking up current os.environ."""
    if MODULE_NAME in sys.modules:
        return importlib.reload(sys.modules[MODULE_NAME])
    return importlib.import_module(MODULE_NAME)


# --------------------------------------------------------------------------- #
# DSN resolution: POSTGRES_URL path
# --------------------------------------------------------------------------- #

class TestPostgresUrlPath:
    def test_uses_postgres_url_verbatim_when_set(self, clean_env):
        clean_env.setenv(
            "POSTGRES_URL", "postgresql://siem:secret@dbhost:5433/siem"
        )
        db = _import_database()

        assert db.POSTGRES_URL == "postgresql://siem:secret@dbhost:5433/siem"

    def test_engine_is_built_from_postgres_url(self, clean_env):
        clean_env.setenv(
            "POSTGRES_URL", "postgresql://siem:secret@dbhost:5433/siem"
        )
        db = _import_database()

        assert db.engine.url.host == "dbhost"
        assert db.engine.url.port == 5433
        assert db.engine.url.database == "siem"
        assert db.engine.url.username == "siem"

    def test_postgres_url_takes_priority_over_discrete_vars(self, clean_env):
        """If both are set, POSTGRES_URL wins — the discrete vars are a
        fallback, not an override."""
        clean_env.setenv("POSTGRES_URL", "postgresql://a:b@url-host:5432/url-db")
        clean_env.setenv("POSTGRES_USER", "discrete-user")
        clean_env.setenv("POSTGRES_PASSWORD", "discrete-pass")
        clean_env.setenv("POSTGRES_DB", "discrete-db")
        clean_env.setenv("POSTGRES_HOST", "discrete-host")

        db = _import_database()

        assert db.engine.url.host == "url-host"
        assert db.engine.url.database == "url-db"


# --------------------------------------------------------------------------- #
# DSN resolution: fallback to discrete POSTGRES_* vars
# --------------------------------------------------------------------------- #

class TestDiscreteVarsFallback:
    def test_builds_dsn_from_discrete_vars(self, clean_env):
        clean_env.setenv("POSTGRES_USER", "siem")
        clean_env.setenv("POSTGRES_PASSWORD", "siem_dev_password")
        clean_env.setenv("POSTGRES_DB", "siem")
        clean_env.setenv("POSTGRES_HOST", "postgres")
        clean_env.setenv("POSTGRES_PORT", "5432")

        db = _import_database()

        assert db.POSTGRES_URL == (
            "postgresql+psycopg2://siem:siem_dev_password@postgres:5432/siem"
        )

    def test_defaults_host_to_postgres_when_unset(self, clean_env):
        """The compose service name, since this fallback exists for the
        in-container case."""
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


# --------------------------------------------------------------------------- #
# Missing / partial credentials
# --------------------------------------------------------------------------- #

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
            {"POSTGRES_USER": "siem", "POSTGRES_PASSWORD": "pw"},
            {"POSTGRES_USER": "siem", "POSTGRES_DB": "siem"},
        ],
        ids=["user-only", "password-only", "db-only", "missing-db",
             "missing-password"],
    )
    def test_partial_credentials_still_raise(self, clean_env, present):
        for key, value in present.items():
            clean_env.setenv(key, value)

        with pytest.raises(RuntimeError, match="not configured"):
            _import_database()

    def test_error_message_mentions_env_example(self, clean_env):
        """A dev hitting this on a fresh checkout should be pointed
        somewhere, not just told "no"."""
        with pytest.raises(RuntimeError, match=r"\.env\.example"):
            _import_database()


# --------------------------------------------------------------------------- #
# get_session(): commit / rollback / close contract
#
# Exercised against SQLite in-memory rather than Postgres — this is
# generic session-lifecycle behaviour with no Postgres-specific SQL in
# it, so a real Postgres instance would add setup cost without covering
# anything more.
# --------------------------------------------------------------------------- #

class TestGetSessionLifecycle:
    @pytest.fixture
    def db(self, clean_env):
        clean_env.setenv("POSTGRES_URL", "sqlite:///:memory:")
        module = _import_database()
        with module.engine.begin() as conn:
            conn.execute(text("CREATE TABLE t (id INTEGER)"))
        return module

    def test_commits_on_success(self, db):
        with db.get_session() as s:
            s.execute(text("INSERT INTO t VALUES (1)"))

        with db.get_session() as s:
            count = s.execute(text("SELECT COUNT(*) FROM t")).scalar()
        assert count == 1

    def test_rolls_back_on_exception(self, db):
        class Boom(Exception):
            pass

        with pytest.raises(Boom):
            with db.get_session() as s:
                s.execute(text("INSERT INTO t VALUES (1)"))
                raise Boom("something failed mid-transaction")

        with db.get_session() as s:
            count = s.execute(text("SELECT COUNT(*) FROM t")).scalar()
        assert count == 0

    def test_exception_propagates_to_caller(self, db):
        """get_session() must not swallow the original error — the
        caller needs to know the operation failed."""
        class Boom(Exception):
            pass

        with pytest.raises(Boom, match="specific failure"):
            with db.get_session() as s:
                raise Boom("specific failure")

    def test_session_closed_after_successful_block(self, db, monkeypatch):
        closed = []
        original_close = SQLAlchemySession.close

        def spy_close(self):
            closed.append(True)
            return original_close(self)

        monkeypatch.setattr(SQLAlchemySession, "close", spy_close)

        with db.get_session() as s:
            s.execute(text("SELECT 1"))

        assert closed == [True]

    def test_session_closed_even_after_exception(self, db, monkeypatch):
        closed = []
        original_close = SQLAlchemySession.close

        def spy_close(self):
            closed.append(True)
            return original_close(self)

        monkeypatch.setattr(SQLAlchemySession, "close", spy_close)

        with pytest.raises(ValueError):
            with db.get_session() as s:
                raise ValueError("boom")

        assert closed == [True]

    def test_yields_a_usable_session(self, db):
        with db.get_session() as s:
            assert isinstance(s, SQLAlchemySession)
            assert s.execute(text("SELECT 1")).scalar() == 1