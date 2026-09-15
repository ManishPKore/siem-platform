"""Shared SQLAlchemy declarative base and reusable mixins."""

from datetime import datetime, timezone

from sqlalchemy import DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for all ORM models in api/models/."""
    pass


class TimestampMixin:
    """Adds created_at / updated_at columns backed by DB-side defaults.

    Mirrors the `set_updated_at` trigger defined in scripts/init_db.sql —
    the trigger is the source of truth for updated_at on UPDATE; the
    Python-side `onupdate` is a convenience fallback for code paths that
    bypass raw SQL (e.g. in-memory/sqlite tests without the trigger).
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )