"""
tests/api/test_health.py

Mocked-session unit tests for GET /health.
No live PostgreSQL database is required.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from dotenv import load_dotenv
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError


# Load the project's local .env before importing the API/database modules.
# This is intentionally done only in API tests so that the existing
# database configuration tests can still test missing environment variables.
load_dotenv(Path(__file__).resolve().parents[2] / ".env")


from api.dependencies import get_db
from api.main import app


@pytest.fixture()
def client():
    return TestClient(app)


def _override_db(session):
    def _get_db():
        yield session

    return _get_db


class TestHealth:
    def test_healthy_when_db_reachable(self, client):
        session = MagicMock()
        session.execute.return_value = None

        app.dependency_overrides[get_db] = _override_db(session)

        try:
            response = client.get("/health")
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200

        body = response.json()

        assert body["status"] == "healthy"
        assert body["database"] == "connected"
        assert "timestamp" in body

        # Confirm that the health endpoint actually checked the database.
        session.execute.assert_called_once()

    def test_degraded_when_db_unreachable(self, client):
        session = MagicMock()
        session.execute.side_effect = OperationalError(
            "SELECT 1",
            {},
            Exception("database unavailable"),
        )

        app.dependency_overrides[get_db] = _override_db(session)

        try:
            response = client.get("/health")
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 503

        body = response.json()

        assert body["status"] == "degraded"
        assert body["database"] == "disconnected"
        assert "timestamp" in body

        session.execute.assert_called_once()

    def test_health_response_contains_expected_fields(self, client):
        session = MagicMock()
        session.execute.return_value = None

        app.dependency_overrides[get_db] = _override_db(session)

        try:
            response = client.get("/health")
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200

        body = response.json()

        assert set(body.keys()) == {
            "status",
            "database",
            "timestamp",
        }

    def test_health_does_not_require_query_params(self, client):
        session = MagicMock()
        session.execute.return_value = None

        app.dependency_overrides[get_db] = _override_db(session)

        try:
            response = client.get("/health")
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200