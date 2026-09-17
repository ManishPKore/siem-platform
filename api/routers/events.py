"""
api/routers/events.py

GET /api/events            -- filtered, paginated event listing
GET /api/events/{event_id} -- single event lookup, 404 if unknown
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.models.event import Event
from api.schemas import EventListResponse, EventOut

router = APIRouter(prefix="/events", tags=["events"])


def _to_event_out(event: Event) -> EventOut:
    return EventOut(
        event_id=event.event_id,
        timestamp=event.timestamp,
        source_ip=event.source_ip,
        event_type=event.event_type,
        severity=event.severity,
        source=event.source,
        raw_message=event.raw_message,
        metadata=event.metadata_ or {},
        created_at=event.created_at,
    )


@router.get("", response_model=EventListResponse)
def list_events(
    source_ip: Optional[str] = Query(default=None, description="Filter by exact source IP"),
    event_type: Optional[str] = Query(default=None, description="Filter by event type, e.g. 'failed_login'"),
    from_time: Optional[datetime] = Query(
        default=None, description="Inclusive lower bound on timestamp (ISO 8601)"
    ),
    to_time: Optional[datetime] = Query(
        default=None, description="Inclusive upper bound on timestamp (ISO 8601)"
    ),
    limit: int = Query(default=100, ge=1, le=1000, description="Max rows to return"),
    offset: int = Query(default=0, ge=0, description="Rows to skip, for pagination"),
    db: Session = Depends(get_db),
) -> EventListResponse:
    filters = []
    if source_ip:
        filters.append(Event.source_ip == source_ip)
    if event_type:
        filters.append(Event.event_type == event_type)
    if from_time:
        filters.append(Event.timestamp >= from_time)
    if to_time:
        filters.append(Event.timestamp <= to_time)

    total = db.execute(
        select(func.count()).select_from(Event).where(*filters)
    ).scalar_one()

    rows = (
        db.execute(
            select(Event)
            .where(*filters)
            .order_by(Event.timestamp.desc())
            .limit(limit)
            .offset(offset)
        )
        .scalars()
        .all()
    )

    return EventListResponse(
        items=[_to_event_out(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{event_id}", response_model=EventOut)
def get_event(event_id: uuid.UUID, db: Session = Depends(get_db)) -> EventOut:
    event = db.execute(
        select(Event).where(Event.event_id == event_id)
    ).scalar_one_or_none()

    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event {event_id} not found",
        )
    return _to_event_out(event)