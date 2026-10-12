"""
api/main.py

FastAPI application factory. `uvicorn api.main:app --reload` picks up
the module-level `app` at the bottom of this file.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import OperationalError


# Load local environment variables before importing the database module.
# Docker/container environments can still provide their own environment
# variables, because load_dotenv() does not override existing variables.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")


from api.database import engine
from api.routers import alerts, events, health


logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SIEM API starting up...")

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))

        logger.info("Database connectivity verified at startup.")

    except OperationalError as exc:
        # Don't crash the app just because the DB isn't reachable.
        # GET /health will report the degraded state.
        logger.warning(
            "Database not reachable at startup: %s",
            exc,
        )

    yield

    logger.info("SIEM API shutting down...")
    engine.dispose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="SIEM Platform API",
        description="Query API for normalized security events and alerts.",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Development-only CORS configuration.
    # Tighten this to explicit origins before production deployment.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Health endpoints.
    app.include_router(health.router)

    # Security event endpoints.
    app.include_router(events.router, prefix="/api")

    # Alert endpoints.
    # The alerts router defines its own prefix.
    app.include_router(alerts.router)

    return app


app = create_app()