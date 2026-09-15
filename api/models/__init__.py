"""SQLAlchemy models mirroring the schema in scripts/init_db.sql.

Import `Base` here (and from this package) when configuring Alembic or
`Base.metadata.create_all(engine)` in tests, so every model below is
registered on the shared metadata.
"""

from api.models.alert import Alert
from api.models.base import Base
from api.models.event import Event
from api.models.rule import Rule
from api.models.user import User

__all__ = ["Base", "Event", "Alert", "Rule", "User"]