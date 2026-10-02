"""Alert persistence service.

Persists triggered alerts from the ``alerts`` Kafka topic into PostgreSQL's
``alerts`` table, separately from raw events.

The service preserves the existing SIEM alert lifecycle:
    OPEN -> ACKNOWLEDGED -> RESOLVED

Issue #17 adds:
- configurable per-rule deduplication windows
- safe deduplication by source IP + rule
- resolved_at timestamps
- filtered/paginated alert reads
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping, Optional

from sqlalchemy import case, func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.database import SessionLocal
from api.models.alert import Alert

logger = logging.getLogger(__name__)

DEFAULT_DEDUP_WINDOW = timedelta(minutes=10)

# Keep the existing project's alert lifecycle.
STATUS_OPEN = "OPEN"
STATUS_ACKNOWLEDGED = "ACKNOWLEDGED"
STATUS_RESOLVED = "RESOLVED"

VALID_STATUSES = (
    STATUS_OPEN,
    STATUS_ACKNOWLEDGED,
    STATUS_RESOLVED,
)

VALID_SEVERITIES = (
    "INFO",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
)

_SEVERITY_RANK = {
    name: rank
    for rank, name in enumerate(VALID_SEVERITIES, start=1)
}

MAX_PAGE_SIZE = 1000


class AlertStorageError(RuntimeError):
    """Raised when an alert database operation fails."""


class AlertNotFoundError(LookupError):
    """Raised when an alert id does not exist."""


def _to_utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError(
            f"{field_name} must be a datetime, "
            f"got {type(value).__name__}"
        )

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _parse_dt(value: Any, field_name: str) -> datetime:
    if isinstance(value, datetime):
        return _to_utc(value, field_name)

    if isinstance(value, str):
        try:
            return _to_utc(
                datetime.fromisoformat(value),
                field_name,
            )
        except ValueError as exc:
            raise ValueError(
                f"{field_name} is not a valid ISO-8601 "
                f"timestamp: {value!r}"
            ) from exc

    raise ValueError(
        f"{field_name} must be an ISO-8601 string or datetime"
    )


def _normalise_severity(value: str) -> str:
    severity = str(value).strip().upper()

    if severity not in VALID_SEVERITIES:
        raise ValueError(
            f"severity must be one of "
            f"{VALID_SEVERITIES}, got {value!r}"
        )

    return severity


def _normalise_status(value: str) -> str:
    status = str(value).strip().upper()

    if status not in VALID_STATUSES:
        raise ValueError(
            f"status must be one of "
            f"{VALID_STATUSES}, got {value!r}"
        )

    return status


@dataclass(frozen=True)
class AlertEvent:
    """Kafka alert payload accepted by AlertStorageService."""

    rule_name: str
    source_ip: str
    severity: str
    triggered_at: datetime
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    event_count: int = 1

    def __post_init__(self) -> None:
        if not self.rule_name or not str(self.rule_name).strip():
            raise ValueError("rule_name is required")

        try:
            ip = str(
                ipaddress.ip_address(
                    str(self.source_ip).strip()
                )
            )
        except ValueError as exc:
            raise ValueError(
                f"source_ip is not a valid IP address: "
                f"{self.source_ip!r}"
            ) from exc

        triggered_at = _to_utc(
            self.triggered_at,
            "triggered_at",
        )

        window_start = (
            _to_utc(self.window_start, "window_start")
            if self.window_start
            else triggered_at
        )

        window_end = (
            _to_utc(self.window_end, "window_end")
            if self.window_end
            else window_start
        )

        if window_end < window_start:
            raise ValueError(
                "window_end must not be earlier than window_start"
            )

        if (
            not isinstance(self.event_count, int)
            or isinstance(self.event_count, bool)
            or self.event_count < 1
        ):
            raise ValueError(
                "event_count must be an integer >= 1"
            )

        object.__setattr__(
            self,
            "rule_name",
            str(self.rule_name).strip(),
        )
        object.__setattr__(
            self,
            "source_ip",
            ip,
        )
        object.__setattr__(
            self,
            "severity",
            _normalise_severity(self.severity),
        )
        object.__setattr__(
            self,
            "triggered_at",
            triggered_at,
        )
        object.__setattr__(
            self,
            "window_start",
            window_start,
        )
        object.__setattr__(
            self,
            "window_end",
            window_end,
        )

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, Any],
    ) -> "AlertEvent":
        """Build an AlertEvent from decoded Kafka JSON."""

        if not isinstance(payload, Mapping):
            raise ValueError(
                "alert payload must be a JSON object"
            )

        try:
            return cls(
                rule_name=payload["rule_name"],
                source_ip=payload["source_ip"],
                severity=payload["severity"],
                triggered_at=_parse_dt(
                    payload["triggered_at"],
                    "triggered_at",
                ),
                window_start=(
                    _parse_dt(
                        payload["window_start"],
                        "window_start",
                    )
                    if payload.get("window_start")
                    else None
                ),
                window_end=(
                    _parse_dt(
                        payload["window_end"],
                        "window_end",
                    )
                    if payload.get("window_end")
                    else None
                ),
                event_count=int(
                    payload.get("event_count", 1)
                ),
            )

        except KeyError as exc:
            raise ValueError(
                "alert payload missing required field: "
                f"{exc.args[0]}"
            ) from exc

        except (TypeError, ValueError) as exc:
            if isinstance(exc, ValueError):
                raise

            raise ValueError(
                f"alert payload has an invalid field type: {exc}"
            ) from exc


@dataclass(frozen=True)
class AlertFilters:
    """Optional filters for AlertStorageService.get_alerts."""

    severity: Optional[str] = None
    rule_name: Optional[str] = None
    from_time: Optional[datetime] = None
    to_time: Optional[datetime] = None
    status: Optional[str] = None
    limit: int = 100
    offset: int = 0

    def __post_init__(self) -> None:
        if self.severity is not None:
            object.__setattr__(
                self,
                "severity",
                _normalise_severity(self.severity),
            )

        if self.status is not None:
            object.__setattr__(
                self,
                "status",
                _normalise_status(self.status),
            )

        if self.from_time is not None:
            object.__setattr__(
                self,
                "from_time",
                _to_utc(
                    self.from_time,
                    "from_time",
                ),
            )

        if self.to_time is not None:
            object.__setattr__(
                self,
                "to_time",
                _to_utc(
                    self.to_time,
                    "to_time",
                ),
            )

        if (
            self.from_time
            and self.to_time
            and self.from_time > self.to_time
        ):
            raise ValueError(
                "from_time must not be later than to_time"
            )

        if not 1 <= self.limit <= MAX_PAGE_SIZE:
            raise ValueError(
                f"limit must be between 1 and "
                f"{MAX_PAGE_SIZE}"
            )

        if self.offset < 0:
            raise ValueError(
                "offset must be >= 0"
            )


class AlertStorageService:
    """Reads and writes rows of the ``alerts`` table."""

    def __init__(
        self,
        session_factory: Callable[
            [],
            Session,
        ] = SessionLocal,
        default_dedup_window: timedelta = DEFAULT_DEDUP_WINDOW,
    ) -> None:
        self._session_factory = session_factory
        self._default_dedup_window = default_dedup_window

    def save_alert(
        self,
        alert: AlertEvent,
    ) -> Alert:
        """Persist an alert or fold it into an open duplicate.

        Duplicate identity is source IP + rule name.
        The rule's configured deduplication window is read from
        rules.dedup_window_minutes.
        """

        try:
            with self._session_factory() as session:
                self._acquire_dedup_lock(
                    session,
                    alert,
                )

                dedup_window = self._get_dedup_window(
                    session,
                    alert.rule_name,
                )

                existing_window_start = session.execute(
                    select(Alert.window_start)
                    .where(
                        Alert.source_ip == alert.source_ip,
                        Alert.rule_name == alert.rule_name,
                        Alert.status == STATUS_OPEN,
                        Alert.triggered_at
                        >= alert.triggered_at - dedup_window,
                        Alert.triggered_at
                        <= alert.triggered_at + dedup_window,
                    )
                    .order_by(
                        Alert.triggered_at.desc()
                    )
                    .limit(1)
                ).scalar_one_or_none()

                window_start = (
                    existing_window_start
                    or alert.window_start
                )

                table = Alert.__table__

                stmt = pg_insert(table).values(
                    rule_name=alert.rule_name,
                    source_ip=alert.source_ip,
                    severity=alert.severity,
                    triggered_at=alert.triggered_at,
                    event_count=alert.event_count,
                    window_start=window_start,
                    window_end=max(
                        alert.window_end,
                        window_start,
                    ),
                    status=STATUS_OPEN,
                )

                incoming_rank = case(
                    _SEVERITY_RANK,
                    value=stmt.excluded.severity,
                    else_=0,
                )

                current_rank = case(
                    _SEVERITY_RANK,
                    value=table.c.severity,
                    else_=0,
                )

                stmt = stmt.on_conflict_do_update(
                    index_elements=[
                        table.c.source_ip,
                        table.c.rule_name,
                        table.c.window_start,
                    ],
                    set_={
                        "event_count": (
                            table.c.event_count
                            + stmt.excluded.event_count
                        ),
                        "severity": case(
                            (
                                incoming_rank > current_rank,
                                stmt.excluded.severity,
                            ),
                            else_=table.c.severity,
                        ),
                        "window_end": func.greatest(
                            table.c.window_end,
                            stmt.excluded.window_end,
                        ),
                    },
                ).returning(table.c.id)

                alert_id = session.execute(
                    stmt
                ).scalar_one()

                session.commit()

                saved = session.get(
                    Alert,
                    alert_id,
                )

                if saved is None:
                    raise AlertStorageError(
                        f"alert {alert_id} disappeared "
                        "after persistence"
                    )

                logger.info(
                    "alert persisted id=%s rule=%s ip=%s "
                    "severity=%s event_count=%s",
                    alert_id,
                    alert.rule_name,
                    alert.source_ip,
                    saved.severity,
                    saved.event_count,
                )

                return saved

        except SQLAlchemyError as exc:
            logger.exception(
                "failed to save alert rule=%s ip=%s",
                alert.rule_name,
                alert.source_ip,
            )

            raise AlertStorageError(
                f"failed to save alert: {exc}"
            ) from exc

    def get_alerts(
        self,
        filters: Optional[AlertFilters] = None,
        **criteria: Any,
    ) -> list[Alert]:
        """Return alerts, newest first."""

        if filters is not None and criteria:
            raise TypeError(
                "pass either an AlertFilters object "
                "or keyword criteria, not both"
            )

        if filters is None:
            filters = AlertFilters(**criteria)

        stmt = select(Alert)

        if filters.severity:
            stmt = stmt.where(
                Alert.severity == filters.severity
            )

        if filters.rule_name:
            stmt = stmt.where(
                Alert.rule_name == filters.rule_name
            )

        if filters.status:
            stmt = stmt.where(
                Alert.status == filters.status
            )

        if filters.from_time:
            stmt = stmt.where(
                Alert.triggered_at >= filters.from_time
            )

        if filters.to_time:
            stmt = stmt.where(
                Alert.triggered_at <= filters.to_time
            )

        stmt = (
            stmt
            .order_by(
                Alert.triggered_at.desc(),
                Alert.id.desc(),
            )
            .limit(filters.limit)
            .offset(filters.offset)
        )

        try:
            with self._session_factory() as session:
                return list(
                    session.scalars(stmt).all()
                )

        except SQLAlchemyError as exc:
            logger.exception(
                "failed to query alerts"
            )

            raise AlertStorageError(
                f"failed to query alerts: {exc}"
            ) from exc

    def close_alert(
        self,
        alert_id: int,
    ) -> Alert:
        """Mark an alert as RESOLVED."""

        try:
            with self._session_factory() as session:
                alert = session.execute(
                    select(Alert)
                    .where(Alert.id == alert_id)
                    .with_for_update()
                ).scalar_one_or_none()

                if alert is None:
                    raise AlertNotFoundError(
                        f"alert {alert_id} not found"
                    )

                if alert.status != STATUS_RESOLVED:
                    alert.status = STATUS_RESOLVED
                    alert.resolved_at = datetime.now(
                        timezone.utc
                    )

                    session.commit()
                    session.refresh(alert)

                    logger.info(
                        "alert resolved id=%s",
                        alert_id,
                    )

                return alert

        except AlertNotFoundError:
            raise

        except SQLAlchemyError as exc:
            logger.exception(
                "failed to resolve alert id=%s",
                alert_id,
            )

            raise AlertStorageError(
                f"failed to resolve alert "
                f"{alert_id}: {exc}"
            ) from exc

    def _get_dedup_window(
        self,
        session: Session,
        rule_name: str,
    ) -> timedelta:
        """Load the rule's dedup window."""

        minutes = session.execute(
            text(
                """
                SELECT dedup_window_minutes
                FROM rules
                WHERE rule_name = :rule_name
                """
            ),
            {"rule_name": rule_name},
        ).scalar_one_or_none()

        if minutes is None:
            return self._default_dedup_window

        if minutes <= 0:
            logger.warning(
                "rule %s has non-positive "
                "dedup_window_minutes=%s; using default",
                rule_name,
                minutes,
            )

            return self._default_dedup_window

        return timedelta(
            minutes=int(minutes)
        )

    @staticmethod
    def _acquire_dedup_lock(
        session: Session,
        alert: AlertEvent,
    ) -> None:
        """Serialize concurrent writers for same rule/IP."""

        if (
            session.get_bind().dialect.name
            != "postgresql"
        ):
            return

        session.execute(
            text(
                """
                SELECT pg_advisory_xact_lock(
                    hashtextextended(:key, 0)
                )
                """
            ),
            {
                "key": (
                    f"alert:"
                    f"{alert.rule_name}|"
                    f"{alert.source_ip}"
                )
            },
        )