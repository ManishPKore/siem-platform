"""Database engine and session factory.

Credentials are read from the environment (populated from .env via
docker-compose, or python-dotenv when running locally) — never hardcoded
here.
"""

import os
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

POSTGRES_URL = os.environ.get("POSTGRES_URL")

if not POSTGRES_URL:
    user = os.environ.get("POSTGRES_USER")
    password = os.environ.get("POSTGRES_PASSWORD")
    host = os.environ.get("POSTGRES_HOST", "postgres")
    port = os.environ.get("POSTGRES_PORT", "5432")
    db = os.environ.get("POSTGRES_DB")

    if not all([user, password, db]):
        raise RuntimeError(
            "Database credentials are not configured. Set POSTGRES_URL, or "
            "POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB, in the "
            "environment (see .env.example)."
        )

    POSTGRES_URL = (
        f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{db}"
    )

# Configure the connection pool only for PostgreSQL.
# SQLite (used by the unit tests) uses a different pool implementation
# that does not accept pool_size/max_overflow.
engine_kwargs = {
    "pool_pre_ping": True,
    "future": True,
}

if POSTGRES_URL.startswith("postgresql"):
    engine_kwargs.update(
        {
            "pool_size": 5,
            "max_overflow": 15,
        }
    )

engine = create_engine(
    POSTGRES_URL,
    **engine_kwargs,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    future=True,
)


@contextmanager
def get_session() -> Iterator[Session]:
    """Yield a SQLAlchemy session, committing on success and rolling back on error."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()