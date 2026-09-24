"""Repository for persisted detection alerts."""

from __future__ import annotations

from datetime import datetime
from typing import Callable

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.models.alert import Alert


class AlertsRepository:
    """Persistence layer for detection alerts."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def save(
        self,
        *,
        rule_name: str,
        source_ip: str | None,
        severity: str,
        triggered_at: datetime,
        event_count: int,
        window_start: datetime,
        window_end: datetime,
        status: str = "open",
    ) -> Alert | None:
        """Persist an alert.

        Returns:
            The newly created Alert when inserted successfully.
            None when the alert is a duplicate.

        Raises:
            IntegrityError: For integrity errors other than a duplicate.
        """
        session = self._session_factory()

        try:
            alert = Alert(
                rule_name=rule_name,
                source_ip=source_ip,
                severity=severity,
                triggered_at=triggered_at,
                event_count=event_count,
                window_start=window_start,
                window_end=window_end,
                status=status,
            )

            session.add(alert)
            session.commit()
            session.refresh(alert)

            return alert

        except IntegrityError:
            session.rollback()

            # Duplicate alerts are intentionally ignored.
            # The unique constraint on:
            # rule_name + source_ip + window_start + window_end
            # makes Spark's at-least-once processing safe.
            return None

        finally:
            session.close()

    def get_by_id(self, alert_id: int) -> Alert | None:
        """Return an alert by primary key."""
        session = self._session_factory()

        try:
            return session.get(Alert, alert_id)
        finally:
            session.close()

    def list_alerts(
        self,
        *,
        rule_name: str | None = None,
        source_ip: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Alert]:
        """Return alerts matching the supplied filters."""
        session = self._session_factory()

        try:
            query = session.query(Alert)

            if rule_name is not None:
                query = query.filter(Alert.rule_name == rule_name)

            if source_ip is not None:
                query = query.filter(Alert.source_ip == source_ip)

            if severity is not None:
                query = query.filter(Alert.severity == severity)

            if status is not None:
                query = query.filter(Alert.status == status)

            return (
                query.order_by(Alert.triggered_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )

        finally:
            session.close()