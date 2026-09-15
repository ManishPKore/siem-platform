"""ORM model for the `events` table — normalized log events."""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Index, String, Text, func
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base

# Matches consumers.schemas.Severity exactly (Issue #6 canonical schema).
VALID_SEVERITIES = ("INFO", "MEDIUM", "HIGH", "CRITICAL")


class Event(Base):
    """A single normalized log event ingested into the platform."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), unique=True, nullable=False, default=uuid.uuid4
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    source_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    raw_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Enrichment fields (GeoIP, ASN, ...) live here so the schema stays
    # flexible as new enrichment sources are added.
    metadata_: Mapped[dict] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )
    # Ingestion time, distinct from `timestamp` (when the event actually
    # occurred at the source). Events are immutable once written, so there
    # is no updated_at here — hence no TimestampMixin.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(f"severity IN {VALID_SEVERITIES}", name="ck_events_severity"),
        Index("idx_events_timestamp", "timestamp"),
        Index("idx_events_source_ip", "source_ip"),
        Index("idx_events_event_type", "event_type"),
        Index("idx_events_metadata_gin", "metadata", postgresql_using="gin"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Event id={self.id} event_id={self.event_id} "
            f"type={self.event_type!r} severity={self.severity!r}>"
        )