"""ORM model for the `users` table."""

from sqlalchemy import Boolean, CheckConstraint, String
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin

VALID_ROLES = ("admin", "analyst", "viewer")


class User(TimestampMixin, Base):
    """A platform user (analyst, viewer, or admin)."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    # Never store plaintext passwords — this holds a bcrypt/argon2 hash only.
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        CheckConstraint(f"role IN {VALID_ROLES}", name="ck_users_role"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User id={self.id} username={self.username!r} role={self.role!r}>"