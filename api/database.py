"""
Database engine and session factory.

Credentials are read from the environment (populated from .env via
docker-compose, or python-dotenv when running locally) — never hardcoded
here.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker


# Load .env only when explicitly requested for local development.
# Docker Compose supplies environment variables directly.
if os.environ.get("SIEM_LOAD_DOTENV", "").lower() == "true":
    load_dotenv()


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