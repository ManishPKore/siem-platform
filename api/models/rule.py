"""ORM model for configurable detection rules."""

from __future__ import annotations

from datetime import time
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, Integer, String, Text, Time
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from api.models.alert import Alert


class Rule(TimestampMixin, Base):
    """Configurable detection rule parameters."""

    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    rule_name: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    threshold: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    window_minutes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    off_hours_start: Mapped[time | None] = mapped_column(
        Time,
        nullable=True,
    )

    off_hours_end: Mapped[time | None] = mapped_column(
        Time,
        nullable=True,
    )

    dedup_window_minutes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=10,
    )

    alerts: Mapped[list["Alert"]] = relationship(
        "Alert",
        back_populates="rule",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        CheckConstraint(
            "threshold > 0",
            name="ck_rules_threshold_positive",
        ),
        CheckConstraint(
            "window_minutes > 0",
            name="ck_rules_window_positive",
        ),
        CheckConstraint(
            "dedup_window_minutes > 0",
            name="ck_rules_dedup_window_positive",
        ),
        CheckConstraint(
            """
            (
                off_hours_start IS NULL
                AND off_hours_end IS NULL
            )
            OR
            (
                off_hours_start IS NOT NULL
                AND off_hours_end IS NOT NULL
            )
            """,
            name="ck_rules_off_hours_pair",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<Rule id={self.id} "
            f"rule_name={self.rule_name!r} "
            f"enabled={self.enabled}>"
        )