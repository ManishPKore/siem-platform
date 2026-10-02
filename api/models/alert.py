"""ORM model for persisted detection alerts."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from api.models.base import (
    Base,
    TimestampMixin,
)

if TYPE_CHECKING:
    from api.models.rule import Rule


class Alert(
    TimestampMixin,
    Base,
):
    """A detection alert persisted separately from raw events."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    rule_name: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("rules.rule_name"),
        nullable=False,
    )

    source_ip: Mapped[str] = mapped_column(
        INET,
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )

    triggered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    event_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
    )

    window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    window_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    # Existing SIEM lifecycle:
    #
    # OPEN
    # ACKNOWLEDGED
    # RESOLVED
    #
    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="OPEN",
    )

    resolved_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    rule: Mapped["Rule"] = relationship(
        "Rule",
        back_populates="alerts",
    )

    __table_args__ = (
        CheckConstraint(
            """
            severity IN (
                'INFO',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
            """,
            name="ck_alerts_severity",
        ),

        CheckConstraint(
            """
            status IN (
                'OPEN',
                'ACKNOWLEDGED',
                'RESOLVED'
            )
            """,
            name="ck_alerts_status",
        ),

        CheckConstraint(
            "event_count > 0",
            name="ck_alerts_event_count_positive",
        ),

        CheckConstraint(
            "window_end >= window_start",
            name="ck_alerts_window_order",
        ),

        # Issue #17 deduplication arbiter.
        UniqueConstraint(
            "source_ip",
            "rule_name",
            "window_start",
            name="uq_alerts_ip_rule_window_start",
        ),

        Index(
            "ix_alerts_triggered_at",
            "triggered_at",
        ),

        Index(
            "ix_alerts_source_ip",
            "source_ip",
        ),

        Index(
            "ix_alerts_status",
            "status",
        ),

        Index(
            "ix_alerts_status_severity",
            "status",
            "severity",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<Alert "
            f"id={self.id} "
            f"rule_name={self.rule_name!r} "
            f"source_ip={self.source_ip!r} "
            f"severity={self.severity!r} "
            f"status={self.status!r}>"
        )