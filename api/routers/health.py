"""
api/routers/health.py

GET /health -- 200 + "healthy"/"connected" when the DB is reachable,
503 + "degraded"/"disconnected" when it isn't. Never raises an
unhandled exception for a DB outage -- that's exactly the condition
this endpoint exists to report.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from api.dependencies import get_db
from api.schemas import HealthResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health_check(response: Response, db: Session = Depends(get_db)) -> HealthResponse:
    try:
        db.execute(text("SELECT 1"))
        return HealthResponse(
            status="healthy",
            database="connected",
            timestamp=datetime.now(timezone.utc),
        )
    except OperationalError as exc:
        logger.error("Health check: database unreachable: %s", exc)
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return HealthResponse(
            status="degraded",
            database="disconnected",
            timestamp=datetime.now(timezone.utc),
        )