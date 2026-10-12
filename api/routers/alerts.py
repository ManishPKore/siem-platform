"""REST API for persisted security alerts.

Endpoints:
    GET   /api/alerts
    GET   /api/alerts/summary
    GET   /api/alerts/{alert_id}
    PATCH /api/alerts/{alert_id}

The summary endpoint is registered before the dynamic alert ID route.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Query,
    Response,
    status,
)
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.alert_schemas import (
    AlertOut,
    AlertStatusUpdate,
    AlertSummary,
)
from api.dependencies import get_db
from api.models.alert import Alert
from api.models.event import VALID_SEVERITIES


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/alerts",
    tags=["alerts"],
)

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000

VALID_STATUSES = (
    "OPEN",
    "ACKNOWLEDGED",
    "RESOLVED",
)

MAX_ALERT_ID = 2**31 - 1


def _unprocessable(
    field: str,
    message: str,
) -> HTTPException:
    """Create a readable 422 response for invalid query parameters."""
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        detail=[
            {
                "type": "value_error",
                "loc": ["query", field],
                "msg": message,
            }
        ],
    )


def _as_utc(value: datetime) -> datetime:
    """Treat naive datetimes as UTC and normalize aware datetimes."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _key(value: object) -> str:
    """Convert a value, including an enum member, into a string key."""
    return str(getattr(value, "value", value))


class AlertFilters:
    """Validated filters shared by listing and summary endpoints."""

    def __init__(
        self,
        severity: Annotated[
            Optional[str],
            Query(
                description=(
                    "Severity: INFO, MEDIUM, HIGH, or CRITICAL. "
                    "Case-insensitive."
                ),
            ),
        ] = None,
        rule_name: Annotated[
            Optional[str],
            Query(
                min_length=1,
                max_length=128,
                description="Exact detection rule name",
            ),
        ] = None,
        source_ip: Annotated[
            Optional[str],
            Query(description="IPv4 or IPv6 source address"),
        ] = None,
        status_: Annotated[
            Optional[str],
            Query(
                alias="status",
                description=(
                    "Alert status: OPEN, ACKNOWLEDGED, or RESOLVED. "
                    "Case-insensitive."
                ),
            ),
        ] = None,
        from_time: Annotated[
            Optional[datetime],
            Query(
                description=(
                    "Inclusive lower bound for triggered_at, "
                    "as an ISO 8601 timestamp"
                ),
            ),
        ] = None,
        to_time: Annotated[
            Optional[datetime],
            Query(
                description=(
                    "Inclusive upper bound for triggered_at, "
                    "as an ISO 8601 timestamp"
                ),
            ),
        ] = None,
    ) -> None:
        if severity is not None:
            severity = severity.strip().upper()

            if severity not in VALID_SEVERITIES:
                raise _unprocessable(
                    "severity",
                    "Invalid severity. Expected one of: "
                    + ", ".join(VALID_SEVERITIES),
                )

        if status_ is not None:
            status_ = status_.strip().upper()

            if status_ not in VALID_STATUSES:
                raise _unprocessable(
                    "status",
                    "Invalid status. Expected one of: "
                    + ", ".join(VALID_STATUSES),
                )

        if source_ip is not None:
            try:
                source_ip = str(
                    ipaddress.ip_address(source_ip.strip())
                )
            except ValueError:
                raise _unprocessable(
                    "source_ip",
                    "Invalid IPv4 or IPv6 address",
                ) from None

        if from_time is not None:
            from_time = _as_utc(from_time)

        if to_time is not None:
            to_time = _as_utc(to_time)

        if (
            from_time is not None
            and to_time is not None
            and from_time > to_time
        ):
            raise _unprocessable(
                "from_time",
                "from_time must be earlier than or equal to to_time",
            )

        self.severity = severity
        self.rule_name = rule_name
        self.source_ip = source_ip
        self.status = status_
        self.from_time = from_time
        self.to_time = to_time


def _apply_filters(
    stmt,
    filters: AlertFilters,
):
    """Apply shared alert filters to a SQLAlchemy statement."""
    if filters.severity is not None:
        stmt = stmt.where(
            Alert.severity == filters.severity
        )

    if filters.rule_name is not None:
        stmt = stmt.where(
            Alert.rule_name == filters.rule_name
        )

    if filters.source_ip is not None:
        stmt = stmt.where(
            Alert.source_ip == filters.source_ip
        )

    if filters.status is not None:
        stmt = stmt.where(
            Alert.status == filters.status
        )

    if filters.from_time is not None:
        stmt = stmt.where(
            Alert.triggered_at >= filters.from_time
        )

    if filters.to_time is not None:
        stmt = stmt.where(
            Alert.triggered_at <= filters.to_time
        )

    return stmt


DbSession = Annotated[
    Session,
    Depends(get_db),
]

Filters = Annotated[
    AlertFilters,
    Depends(),
]


# ---------------------------------------------------------------------------
# GET /api/alerts
# ---------------------------------------------------------------------------

@router.get(
    "",
    response_model=list[AlertOut],
    summary="List persisted alerts",
)
def list_alerts(
    response: Response,
    db: DbSession,
    filters: Filters,
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=MAX_LIMIT,
            description="Maximum number of alerts to return",
        ),
    ] = DEFAULT_LIMIT,
    offset: Annotated[
        int,
        Query(
            ge=0,
            description="Number of matching alerts to skip",
        ),
    ] = 0,
) -> list[AlertOut]:
    """Return filtered alerts, newest first.

    Pagination headers:
        X-Total-Count: Total number of matching alerts.
        X-Page: One-based page number.
        X-Per-Page: Requested page size.
    """
    count_stmt = _apply_filters(
        select(func.count(Alert.id)),
        filters,
    )

    total = db.execute(count_stmt).scalar_one()

    alerts_stmt = (
        _apply_filters(
            select(Alert),
            filters,
        )
        .order_by(
            Alert.triggered_at.desc(),
            Alert.id.desc(),
        )
        .limit(limit)
        .offset(offset)
    )

    rows = db.execute(alerts_stmt).scalars().all()

    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Page"] = str(offset // limit + 1)
    response.headers["X-Per-Page"] = str(limit)

    return rows


# ---------------------------------------------------------------------------
# GET /api/alerts/summary
# ---------------------------------------------------------------------------

@router.get(
    "/summary",
    response_model=AlertSummary,
    summary="Get alert counts by severity and rule",
)
def alerts_summary(
    db: DbSession,
    filters: Filters,
) -> AlertSummary:
    """Return alert counts grouped by severity and rule."""
    severity_stmt = (
        _apply_filters(
            select(
                Alert.severity,
                func.count(Alert.id),
            ),
            filters,
        )
        .group_by(Alert.severity)
        .order_by(
            func.count(Alert.id).desc(),
            Alert.severity,
        )
    )

    severity_rows = db.execute(
        severity_stmt
    ).all()

    rule_stmt = (
        _apply_filters(
            select(
                Alert.rule_name,
                func.count(Alert.id),
            ),
            filters,
        )
        .group_by(Alert.rule_name)
        .order_by(
            func.count(Alert.id).desc(),
            Alert.rule_name,
        )
    )

    rule_rows = db.execute(
        rule_stmt
    ).all()

    by_severity = {
        _key(severity): int(count)
        for severity, count in severity_rows
    }

    by_rule = {
        _key(rule_name): int(count)
        for rule_name, count in rule_rows
    }

    return AlertSummary(
        by_severity=by_severity,
        by_rule=by_rule,
    )


# ---------------------------------------------------------------------------
# GET /api/alerts/{alert_id}
# ---------------------------------------------------------------------------

@router.get(
    "/{alert_id}",
    response_model=AlertOut,
    summary="Get a single alert",
)
def get_alert(
    db: DbSession,
    alert_id: Annotated[
        int,
        Path(
            ge=1,
            le=MAX_ALERT_ID,
            description="Alert database ID",
        ),
    ],
) -> Alert:
    """Return a persisted alert or 404 if it does not exist."""
    alert = db.get(
        Alert,
        alert_id,
    )

    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )

    return alert


# ---------------------------------------------------------------------------
# PATCH /api/alerts/{alert_id}
# ---------------------------------------------------------------------------

@router.patch(
    "/{alert_id}",
    response_model=AlertOut,
    summary="Update alert status",
)
def update_alert_status(
    db: DbSession,
    payload: AlertStatusUpdate,
    alert_id: Annotated[
        int,
        Path(
            ge=1,
            le=MAX_ALERT_ID,
            description="Alert database ID",
        ),
    ],
) -> Alert:
    """Update an alert's lifecycle status.

    Supported statuses:
        OPEN
        ACKNOWLEDGED
        RESOLVED

    Repeating the current status is idempotent.
    Resolving an alert records resolved_at.
    Reopening a resolved alert clears resolved_at.
    """
    try:
        stmt = (
            select(Alert)
            .where(Alert.id == alert_id)
            .with_for_update()
        )

        alert = db.execute(
            stmt
        ).scalar_one_or_none()

        if alert is None:
            db.rollback()

            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert {alert_id} not found",
            )

        new_status = payload.status
        now = datetime.now(timezone.utc)

        if alert.status != new_status:
            # Set the lifecycle status and its corresponding resolution time
            # together so the two fields cannot drift out of sync.
            alert.status = new_status

            if new_status == "RESOLVED":
                alert.resolved_at = now
            else:
                # OPEN and ACKNOWLEDGED alerts are not resolved.
                alert.resolved_at = None

            db.commit()
            db.refresh(alert)
        else:
            # The request is idempotent. Release the row lock without writing
            # anything, then reload the alert in the current session.
            db.rollback()
            alert = db.get(Alert, alert_id)

            if alert is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Alert {alert_id} not found",
                )

        return alert

    except HTTPException:
        raise

    except SQLAlchemyError:
        db.rollback()

        logger.exception(
            "Failed to update status for alert %s",
            alert_id,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update alert status",
        ) from None