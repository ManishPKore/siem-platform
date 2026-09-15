"""ORM model for the `rules` table — configurable detection rule parameters."""

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from api.models.alert import Alert


class Rule(TimestampMixin, Base):
    """A configurable detection rule (e.g. brute-force threshold)."""

    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    rule_name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False)
    window_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    alerts: Mapped[list["Alert"]] = relationship(
        "Alert", back_populates="rule", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint("threshold > 0", name="ck_rules_threshold_positive"),
        CheckConstraint("window_minutes > 0", name="ck_rules_window_positive"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Rule id={self.id} rule_name={self.rule_name!r} "
            f"enabled={self.enabled}>"
        )