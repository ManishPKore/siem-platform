"""
api/dependencies.py

Shared FastAPI dependencies. Currently just the DB session dependency,
but this is the place future endpoints' shared dependencies (auth,
pagination defaults, etc.) go rather than each router rolling its own.
"""

from __future__ import annotations

from typing import Iterator

from sqlalchemy.orm import Session

from api.database import SessionLocal


def get_db() -> Iterator[Session]:
    """Yield a request-scoped session, always closed after the request
    -- never committed here. Endpoints that write (none yet) are
    responsible for their own commit."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()