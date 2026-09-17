"""
api/schemas.py

Pydantic response models for the FastAPI layer. Deliberately separate
from consumers/schemas.py (the canonical LogEvent/AlertEvent pipeline
contract) and from api/models/ (the SQLAlchemy ORM tables) -- this file
is what the HTTP API actually returns, which is allowed to diverge from
both (e.g. `metadata` here is always a plain dict, timestamps are
serialized as ISO 8601 strings by Pydantic automatically).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = Field(..., description="'healthy' or 'degraded'")
    database: str = Field(..., description="'connected' or 'disconnected'")
    timestamp: datetime


class EventOut(BaseModel):
    """A single normalized event, as returned by the API. Built
    explicitly from an api.models.event.Event row (see
    api/routers/events.py::_to_event_out) rather than via Pydantic's
    from_attributes ORM auto-conversion -- the ORM column is named
    `metadata_` (SQLAlchemy reserves the plain name `metadata` on
    declarative models), and explicit mapping avoids relying on alias
    resolution to bridge that mismatch.
    """

    event_id: uuid.UUID
    timestamp: datetime
    source_ip: Optional[str] = None
    event_type: str
    severity: str
    source: str
    raw_message: Optional[str] = None
    metadata: dict = Field(default_factory=dict)
    created_at: datetime


class EventListResponse(BaseModel):
    items: list[EventOut]
    total: int = Field(..., description="Total rows matching the filters, ignoring limit/offset")
    limit: int
    offset: int