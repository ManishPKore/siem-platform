"""ORM model for the `alerts` table — triggered detection results."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.models.base import Base, TimestampMixin
from api.models.event import VALID_SEVERITIES

if TYPE_CHECKING:
    from api.models.rule import Rule

VALID_STATUSES = ("open", "closed")


class Alert(TimestampMixin, Base):
    """A detection result triggered by a rule against a window of events."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    rule_name: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("rules.rule_name", onupdate="CASCADE", ondelete="RESTRICT"),
        nullable=False,
    )
    source_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    triggered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    window_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")

    rule: Mapped["Rule"] = relationship("Rule", back_populates="alerts")

    __table_args__ = (
        CheckConstraint(f"severity IN {VALID_SEVERITIES}", name="ck_alerts_severity"),
        CheckConstraint(f"status IN {VALID_STATUSES}", name="ck_alerts_status"),
        CheckConstraint("event_count > 0", name="ck_alerts_event_count_positive"),
        CheckConstraint("window_end >= window_start", name="ck_alerts_window_order"),
        Index("idx_alerts_triggered_at", "triggered_at"),
        Index("idx_alerts_source_ip", "source_ip"),
        Index("idx_alerts_status", "status"),
        Index("idx_alerts_rule_name", "rule_name"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Alert id={self.id} rule_name={self.rule_name!r} "
            f"status={self.status!r} triggered_at={self.triggered_at}>"
        )