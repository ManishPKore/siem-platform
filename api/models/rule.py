"""ORM model for the `rules` table — configurable detection rule parameters."""

from datetime import time
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, Integer, String, Text, Time
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from api.models.alert import Alert


class Rule(TimestampMixin, Base):
    """A configurable detection rule (e.g. brute-force threshold)."""

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

    # Time-based configuration used by rules such as
    # OffHoursLoginRule. These fields remain NULL for rules
    # that do not require an off-hours window.
    off_hours_start: Mapped[time | None] = mapped_column(
        Time,
        nullable=True,
    )

    off_hours_end: Mapped[time | None] = mapped_column(
        Time,
        nullable=True,
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

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Rule id={self.id} rule_name={self.rule_name!r} "
            f"enabled={self.enabled}>"
        )