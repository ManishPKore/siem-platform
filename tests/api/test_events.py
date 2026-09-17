"""
tests/api/test_events.py

Mocked-session unit tests for the FastAPI event endpoints.

No live PostgreSQL database is required. SQLAlchemy session behavior is
mocked so these tests focus on API routing, filtering parameters,
pagination, response models, validation, and 404 handling.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from dotenv import load_dotenv
from fastapi.testclient import TestClient


# Load the project's local .env before importing the API/database modules.
# This is intentionally limited to these API tests so that the existing
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


def _make_event(
    *,
    event_id: uuid.UUID | None = None,
    source_ip: str = "192.168.1.10",
    event_type: str = "failed_login",
    severity: str = "MEDIUM",
    source: str = "ssh",
    timestamp: datetime | None = None,
    raw_message: str = "Failed password for testuser",
    metadata: dict | None = None,
):
    """
    Create a lightweight mock of api.models.event.Event.

    The API converts Event ORM objects into EventOut using _to_event_out(),
    so a MagicMock containing the expected attributes is sufficient for
    these endpoint tests.
    """
    event = MagicMock()

    event.event_id = event_id or uuid.uuid4()
    event.timestamp = timestamp or datetime.now(timezone.utc)
    event.source_ip = source_ip
    event.event_type = event_type
    event.severity = severity
    event.source = source
    event.raw_message = raw_message
    event.metadata_ = metadata or {}
    event.created_at = datetime.now(timezone.utc)

    return event


class TestListEvents:
    def test_returns_events(self, client):
        event = _make_event()

        session = MagicMock()

        # First database query = COUNT(*)
        count_result = MagicMock()
        count_result.scalar_one.return_value = 1

        # Second database query = SELECT Event
        rows_result = MagicMock()
        rows_result.scalars.return_value.all.return_value = [event]

        session.execute.side_effect = [
            count_result,
            rows_result,
        ]

        app.dependency_overrides[get_db] = _override_db(session)

        try:
            response = client.get("/api/events")
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200

        body = response.json()

        assert body["total"] == 1
        assert body["limit"] == 100
        assert body["offset"] == 0
        assert len(body["items"]) == 1

        returned_event = body["items"][0]

        assert returned_event["event_id"] == str(event.event_id)
        assert returned_event["source_ip"] == "192.168.1.10"
        assert returned_event["event_type"] == "failed_login"
        assert returned_event["severity"] == "MEDIUM"
        assert returned_event["source"] == "ssh"

        assert session.execute.call_count == 2

    def test_filters_by_source_ip(self, client):
        event = _make_event(
            source_ip="192.168.1.10",
        )

        session = MagicMock()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 1

        rows_result = MagicMock()
        rows_result.scalars.return_value.all.return_value = [event]

        session.execute.side_effect = [
            count_result,
            rows_result,
        ]

        app.dependency_overrides[get_db] = _override_db(session)

        try:
            response = client.get(
                "/api/events?source_ip=192.168.1.10"
            )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200

        body = response.json()

        assert body["total"] == 1
        assert body["items"][0]["source_ip"] == "192.168.1.10"
        assert session.execute.call_count == 2

    def test_filters_by_event_type(self, client):
        event = _make_event(
            event_type="successful_login",
        )

        session = MagicMock()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 1

        rows_result = MagicMock()
        rows_result.scalars.return_value.all.return_value = [event]

        session.execute.side_effect = [
            count_result,
            rows_result,
        ]

        app.dependency_overrides[get_db] = _override_db(session)

        try:
            response = client.get(
                "/api/events?event_type=successful_login"
            )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200

        body = response.json()

        assert body["total"] == 1
        assert body["items"][0]["event_type"] == "successful_login"

    def test_filters_by_time_range(self, client):
        event_time = datetime(
            2026,
            9,
            17,
            10,
            0,
            0,
            tzinfo=timezone.utc,
        )

        event = _make_event(
            timestamp=event_time,
        )

        session = MagicMock()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 1

        rows_result = MagicMock()
        rows_result.scalars.return_value.all.return_value = [event]

        session.execute.side_effect = [
            count_result,
            rows_result,
        ]

        app.dependency_overrides[get_db] = _override_db(session)

        try:
            response = client.get(
                "/api/events"
                "?from_time=2026-09-17T09:00:00Z"
                "&to_time=2026-09-17T11:00:00Z"
            )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200

        body = response.json()

        assert body["total"] == 1
        assert body["items"][0]["timestamp"] == (
            "2026-09-17T10:00:00Z"
        )

    def test_pagination_limit_and_offset(self, client):
        events = [
            _make_event(),
            _make_event(),
        ]

        session = MagicMock()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 10

        rows_result = MagicMock()
        rows_result.scalars.return_value.all.return_value = events

        session.execute.side_effect = [
            count_result,
            rows_result,
        ]

        app.dependency_overrides[get_db] = _override_db(session)

        try:
            response = client.get(
                "/api/events?limit=2&offset=4"
            )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200

        body = response.json()

        assert body["total"] == 10
        assert body["limit"] == 2
        assert body["offset"] == 4
        assert len(body["items"]) == 2

    def test_limit_1000_is_allowed(self, client):
        session = MagicMock()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 0

        rows_result = MagicMock()
        rows_result.scalars.return_value.all.return_value = []

        session.execute.side_effect = [
            count_result,
            rows_result,
        ]

        app.dependency_overrides[get_db] = _override_db(session)

        try:
            response = client.get("/api/events?limit=1000")
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200
        assert response.json()["limit"] == 1000

    def test_limit_above_1000_is_rejected(self, client):
        session = MagicMock()

        app.dependency_overrides[get_db] = _override_db(session)

        try:
            response = client.get("/api/events?limit=1001")
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 422

        # Invalid input should be rejected before the database is queried.
        session.execute.assert_not_called()

    def test_negative_offset_is_rejected(self, client):
        session = MagicMock()

        app.dependency_overrides[get_db] = _override_db(session)

        try:
            response = client.get("/api/events?offset=-1")
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 422

        session.execute.assert_not_called()


class TestGetEvent:
    def test_returns_event_by_id(self, client):
        event_id = uuid.uuid4()

        event = _make_event(
            event_id=event_id,
            source_ip="10.0.0.25",
            event_type="firewall_drop",
            severity="HIGH",
            source="firewall",
            raw_message="DROP TCP connection",
            metadata={
                "action": "DROP",
                "dest_ip": "10.0.0.50",
                "dest_port": 22,
            },
        )

        session = MagicMock()

        result = MagicMock()
        result.scalar_one_or_none.return_value = event

        session.execute.return_value = result

        app.dependency_overrides[get_db] = _override_db(session)

        try:
            response = client.get(
                f"/api/events/{event_id}"
            )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200

        body = response.json()

        assert body["event_id"] == str(event_id)
        assert body["source_ip"] == "10.0.0.25"
        assert body["event_type"] == "firewall_drop"
        assert body["severity"] == "HIGH"
        assert body["source"] == "firewall"

        assert body["metadata"]["action"] == "DROP"
        assert body["metadata"]["dest_ip"] == "10.0.0.50"
        assert body["metadata"]["dest_port"] == 22

        session.execute.assert_called_once()

    def test_unknown_event_returns_404(self, client):
        event_id = uuid.uuid4()

        session = MagicMock()

        result = MagicMock()
        result.scalar_one_or_none.return_value = None

        session.execute.return_value = result

        app.dependency_overrides[get_db] = _override_db(session)

        try:
            response = client.get(
                f"/api/events/{event_id}"
            )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 404

        body = response.json()

        assert body["detail"] == f"Event {event_id} not found"

        session.execute.assert_called_once()

    def test_invalid_event_id_returns_422(self, client):
        session = MagicMock()

        app.dependency_overrides[get_db] = _override_db(session)

        try:
            response = client.get(
                "/api/events/not-a-valid-uuid"
            )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 422

        # FastAPI should reject the UUID before touching the database.
        session.execute.assert_not_called()