"""Pydantic schemas for the alerts REST API."""

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)


def _plain(value):
    """Convert enum members and address objects into plain strings."""
    if value is None:
        return None

    if isinstance(value, Enum):
        return value.value

    return str(value)


class AlertOut(BaseModel):
    """Response schema for a persisted alert."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_name: str
    source_ip: str | None = None
    severity: str
    triggered_at: datetime
    event_count: int
    window_start: datetime
    window_end: datetime
    status: str
    resolved_at: datetime | None = None

    @field_validator(
        "source_ip",
        "severity",
        "status",
        mode="before",
    )
    @classmethod
    def coerce_to_string(cls, value):
        """Normalize database values for JSON serialization."""
        return _plain(value)


class AlertStatusUpdate(BaseModel):
    """Request body for PATCH /api/alerts/{alert_id}."""

    model_config = ConfigDict(extra="forbid")

    status: Literal[
        "OPEN",
        "ACKNOWLEDGED",
        "RESOLVED",
    ] = Field(
        ...,
        description=(
            "New alert status: OPEN, ACKNOWLEDGED, or RESOLVED."
        ),
    )


class AlertSummary(BaseModel):
    """Response schema for GET /api/alerts/summary."""

    by_severity: dict[str, int]
    by_rule: dict[str, int]