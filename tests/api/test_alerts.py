"""API tests for /api/alerts.

These tests use PostgreSQL because the alerts.source_ip column is INET.
Each test runs inside an outer transaction that is rolled back.
"""

import itertools
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.database import engine
from api.dependencies import get_db
from api.main import app
from api.models.alert import Alert
from api.models.rule import Rule


BASE = datetime(2001, 1, 1, tzinfo=timezone.utc)

RANGE = {
    "from_time": "2001-01-01T00:00:00Z",
    "to_time": "2001-12-31T23:59:59Z",
}

SUMMARY_IP = "198.51.100.250"

_counter = itertools.count()


# --------------------------------------------------------------------------- #
# Fixtures and factories
# --------------------------------------------------------------------------- #

@pytest.fixture()
def db_session():
    """Provide a session whose changes are rolled back after the test."""
    connection = engine.connect()
    outer_transaction = connection.begin()

    session = Session(
        bind=connection,
        join_transaction_mode="create_savepoint",
    )

    try:
        yield session
    finally:
        session.close()
        outer_transaction.rollback()
        connection.close()


@pytest.fixture()
def client(db_session):
    """Provide a test client using the isolated database session."""

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_db, None)


def ensure_rule(db: Session, name: str) -> None:
    """Create a valid rule if it does not already exist."""
    existing = (
        db.query(Rule)
        .filter(Rule.rule_name == name)
        .first()
    )

    if existing is None:
        db.add(
            Rule(
                rule_name=name,
                description=f"Test rule: {name}",
                threshold=5,
                window_minutes=5,
                enabled=True,
            )
        )
        db.flush()


def make_alert(db: Session, **overrides) -> Alert:
    """Create a persisted test alert."""
    number = next(_counter)

    data = {
        "rule_name": "brute_force",
        "source_ip": "203.0.113.10",
        "severity": "HIGH",
        "triggered_at": BASE + timedelta(minutes=number),
        "event_count": 5,
        "window_start": BASE + timedelta(minutes=number),
        "window_end": BASE + timedelta(minutes=number + 5),
        "status": "OPEN",
    }

    data.update(overrides)

    ensure_rule(db, data["rule_name"])

    alert = Alert(**data)
    db.add(alert)

    # The test session uses a savepoint, leaving the outer transaction active.
    db.commit()
    db.refresh(alert)

    return alert


def summary_params(**overrides):
    """Return time and source-IP filters for isolated summary tests."""
    params = {
        **RANGE,
        "source_ip": SUMMARY_IP,
    }
    params.update(overrides)
    return params


# --------------------------------------------------------------------------- #
# GET /api/alerts
# --------------------------------------------------------------------------- #

class TestListAlerts:
    def test_default_limit_100_and_order_desc(self, client, db_session):
        test_ip = "198.51.100.240"

        for _ in range(105):
            make_alert(db_session, source_ip=test_ip)

        response = client.get(
            "/api/alerts",
            params={"source_ip": test_ip},
        )

        assert response.status_code == 200

        body = response.json()

        assert len(body) == 100
        assert response.headers["X-Per-Page"] == "100"
        assert response.headers["X-Page"] == "1"
        assert response.headers["X-Total-Count"] == "105"

        timestamps = [item["triggered_at"] for item in body]

        assert timestamps == sorted(timestamps, reverse=True)

    def test_response_shape(self, client, db_session):
        alert = make_alert(
            db_session,
            source_ip="203.0.113.50",
        )

        response = client.get(
            "/api/alerts",
            params={"source_ip": "203.0.113.50"},
        )

        assert response.status_code == 200

        item = response.json()[0]

        assert item["id"] == alert.id
        assert item["rule_name"] == "brute_force"
        assert item["source_ip"] == "203.0.113.50"
        assert item["severity"] == "HIGH"
        assert item["status"] == "OPEN"
        assert item["event_count"] == 5

    def test_severity_and_status_returns_only_open_high(
        self,
        client,
        db_session,
    ):
        test_ip = "203.0.113.21"

        keep = make_alert(
            db_session,
            source_ip=test_ip,
            severity="HIGH",
            status="OPEN",
        )

        make_alert(
            db_session,
            source_ip=test_ip,
            severity="HIGH",
            status="RESOLVED",
        )

        make_alert(
            db_session,
            source_ip=test_ip,
            severity="CRITICAL",
            status="OPEN",
        )

        make_alert(
            db_session,
            source_ip=test_ip,
            severity="MEDIUM",
            status="OPEN",
        )

        response = client.get(
            "/api/alerts",
            params={
                "severity": "HIGH",
                "status": "OPEN",
                "source_ip": test_ip,
            },
        )

        assert response.status_code == 200

        body = response.json()

        assert [item["id"] for item in body] == [keep.id]

        assert all(
            item["severity"] == "HIGH"
            and item["status"] == "OPEN"
            for item in body
        )

        assert response.headers["X-Total-Count"] == "1"

    def test_severity_and_status_are_case_insensitive(
        self,
        client,
        db_session,
    ):
        test_ip = "203.0.113.22"

        make_alert(
            db_session,
            source_ip=test_ip,
            severity="HIGH",
            status="OPEN",
        )

        response = client.get(
            "/api/alerts",
            params={
                "severity": "high",
                "status": "OPEN",
                "source_ip": test_ip,
            },
        )

        assert response.status_code == 200
        assert len(response.json()) == 1

    def test_info_is_a_valid_severity(self, client, db_session):
        test_ip = "203.0.113.26"

        alert = make_alert(
            db_session,
            source_ip=test_ip,
            severity="INFO",
        )

        response = client.get(
            "/api/alerts",
            params={
                "severity": "INFO",
                "source_ip": test_ip,
            },
        )

        assert response.status_code == 200
        assert [item["id"] for item in response.json()] == [alert.id]

    def test_filter_by_rule_name(self, client, db_session):
        test_ip = "203.0.113.23"

        make_alert(
            db_session,
            source_ip=test_ip,
            rule_name="brute_force",
        )

        target = make_alert(
            db_session,
            source_ip=test_ip,
            rule_name="port_scan",
        )

        response = client.get(
            "/api/alerts",
            params={
                "rule_name": "port_scan",
                "source_ip": test_ip,
            },
        )

        assert response.status_code == 200
        assert [item["id"] for item in response.json()] == [target.id]

    def test_filter_by_source_ip(self, client, db_session):
        target = make_alert(
            db_session,
            source_ip="203.0.113.24",
        )

        make_alert(
            db_session,
            source_ip="203.0.113.25",
        )

        response = client.get(
            "/api/alerts",
            params={"source_ip": "203.0.113.24"},
        )

        assert response.status_code == 200
        assert [item["id"] for item in response.json()] == [target.id]

    def test_filter_by_ipv6_source_ip(self, client, db_session):
        alert = make_alert(
            db_session,
            source_ip="2001:db8::1",
        )

        response = client.get(
            "/api/alerts",
            params={"source_ip": "2001:db8::1"},
        )

        assert response.status_code == 200
        assert [item["id"] for item in response.json()] == [alert.id]

    def test_time_range_is_inclusive(self, client, db_session):
        test_ip = "203.0.113.26"

        make_alert(
            db_session,
            source_ip=test_ip,
            triggered_at=datetime(
                2001, 4, 30, 23, 59, 59,
                tzinfo=timezone.utc,
            ),
        )

        start = make_alert(
            db_session,
            source_ip=test_ip,
            triggered_at=datetime(
                2001, 5, 1,
                tzinfo=timezone.utc,
            ),
        )

        middle = make_alert(
            db_session,
            source_ip=test_ip,
            triggered_at=datetime(
                2001, 5, 15,
                tzinfo=timezone.utc,
            ),
        )

        end = make_alert(
            db_session,
            source_ip=test_ip,
            triggered_at=datetime(
                2001, 5, 28, 23, 59, 59,
                tzinfo=timezone.utc,
            ),
        )

        make_alert(
            db_session,
            source_ip=test_ip,
            triggered_at=datetime(
                2001, 5, 29,
                tzinfo=timezone.utc,
            ),
        )

        response = client.get(
            "/api/alerts",
            params={
                "from_time": "2001-05-01T00:00:00Z",
                "to_time": "2001-05-28T23:59:59Z",
                "source_ip": test_ip,
            },
        )

        assert response.status_code == 200

        assert [item["id"] for item in response.json()] == [
            end.id,
            middle.id,
            start.id,
        ]

    def test_from_time_only_and_to_time_only(self, client, db_session):
        test_ip = "203.0.113.27"

        old = make_alert(
            db_session,
            source_ip=test_ip,
            triggered_at=datetime(
                2001, 2, 1,
                tzinfo=timezone.utc,
            ),
        )

        new = make_alert(
            db_session,
            source_ip=test_ip,
            triggered_at=datetime(
                2001, 8, 1,
                tzinfo=timezone.utc,
            ),
        )

        response = client.get(
            "/api/alerts",
            params={
                "from_time": "2001-06-01T00:00:00Z",
                "source_ip": test_ip,
            },
        )

        assert [item["id"] for item in response.json()] == [new.id]

        response = client.get(
            "/api/alerts",
            params={
                "to_time": "2001-06-01T00:00:00Z",
                "source_ip": test_ip,
            },
        )

        assert [item["id"] for item in response.json()] == [old.id]

    def test_timezone_offset_is_respected(self, client, db_session):
        test_ip = "203.0.113.28"

        alert = make_alert(
            db_session,
            source_ip=test_ip,
            triggered_at=datetime(
                2001, 5, 1, 12, 0,
                tzinfo=timezone.utc,
            ),
        )

        response = client.get(
            "/api/alerts",
            params={
                "from_time": "2001-05-01T17:30:00+05:30",
                "source_ip": test_ip,
            },
        )

        assert [item["id"] for item in response.json()] == [alert.id]

        response = client.get(
            "/api/alerts",
            params={
                "from_time": "2001-05-01T17:31:00+05:30",
                "source_ip": test_ip,
            },
        )

        assert response.json() == []

    def test_naive_datetime_treated_as_utc(self, client, db_session):
        test_ip = "203.0.113.29"

        alert = make_alert(
            db_session,
            source_ip=test_ip,
            triggered_at=datetime(
                2001, 5, 1, 12, 0,
                tzinfo=timezone.utc,
            ),
        )

        response = client.get(
            "/api/alerts",
            params={
                "from_time": "2001-05-01T12:00:00",
                "source_ip": test_ip,
            },
        )

        assert [item["id"] for item in response.json()] == [alert.id]

    def test_all_filters_combined(self, client, db_session):
        test_ip = "203.0.113.30"

        timestamp = datetime(
            2001, 5, 10,
            tzinfo=timezone.utc,
        )

        target = make_alert(
            db_session,
            source_ip=test_ip,
            rule_name="port_scan",
            severity="CRITICAL",
            status="OPEN",
            triggered_at=timestamp,
        )

        make_alert(
            db_session,
            source_ip=test_ip,
            rule_name="brute_force",
            severity="CRITICAL",
            status="OPEN",
            triggered_at=timestamp,
        )

        make_alert(
            db_session,
            source_ip=test_ip,
            rule_name="port_scan",
            severity="HIGH",
            status="OPEN",
            triggered_at=timestamp,
        )

        make_alert(
            db_session,
            source_ip=test_ip,
            rule_name="port_scan",
            severity="CRITICAL",
            status="RESOLVED",
            triggered_at=timestamp,
        )

        make_alert(
            db_session,
            source_ip=test_ip,
            rule_name="port_scan",
            severity="CRITICAL",
            status="OPEN",
            triggered_at=datetime(
                2001, 6, 10,
                tzinfo=timezone.utc,
            ),
        )

        response = client.get(
            "/api/alerts",
            params={
                "severity": "CRITICAL",
                "rule_name": "port_scan",
                "source_ip": test_ip,
                "status": "OPEN",
                "from_time": "2001-05-01T00:00:00Z",
                "to_time": "2001-05-31T23:59:59Z",
            },
        )

        assert response.status_code == 200
        assert [item["id"] for item in response.json()] == [target.id]

    def test_no_matches_returns_empty_list(self, client):
        response = client.get(
            "/api/alerts",
            params={"source_ip": "198.51.100.200"},
        )

        assert response.status_code == 200
        assert response.json() == []
        assert response.headers["X-Total-Count"] == "0"

    def test_pagination_headers_and_slicing(self, client, db_session):
        test_ip = "203.0.113.31"

        ids = [
            make_alert(
                db_session,
                source_ip=test_ip,
            ).id
            for _ in range(7)
        ]

        newest_first = list(reversed(ids))

        response1 = client.get(
            "/api/alerts",
            params={
                "source_ip": test_ip,
                "limit": 3,
                "offset": 0,
            },
        )

        response2 = client.get(
            "/api/alerts",
            params={
                "source_ip": test_ip,
                "limit": 3,
                "offset": 3,
            },
        )

        response3 = client.get(
            "/api/alerts",
            params={
                "source_ip": test_ip,
                "limit": 3,
                "offset": 6,
            },
        )

        assert [item["id"] for item in response1.json()] == newest_first[:3]
        assert [item["id"] for item in response2.json()] == newest_first[3:6]
        assert [item["id"] for item in response3.json()] == newest_first[6:7]

        for response, page in (
            (response1, "1"),
            (response2, "2"),
            (response3, "3"),
        ):
            assert response.headers["X-Total-Count"] == "7"
            assert response.headers["X-Per-Page"] == "3"
            assert response.headers["X-Page"] == page

    def test_offset_beyond_total_returns_empty_with_total(
        self,
        client,
        db_session,
    ):
        test_ip = "203.0.113.32"

        make_alert(
            db_session,
            source_ip=test_ip,
        )

        response = client.get(
            "/api/alerts",
            params={
                "source_ip": test_ip,
                "offset": 50,
            },
        )

        assert response.status_code == 200
        assert response.json() == []
        assert response.headers["X-Total-Count"] == "1"

    @pytest.mark.parametrize("param", ["from_time", "to_time"])
    @pytest.mark.parametrize(
        "bad",
        [
            "not-a-date",
            "2026-13-45T00:00:00Z",
            "yesterday",
        ],
    )
    def test_invalid_time_returns_422_with_clear_message(
        self,
        client,
        param,
        bad,
    ):
        response = client.get(
            "/api/alerts",
            params={param: bad},
        )

        assert response.status_code == 422

        error = response.json()["detail"][0]

        assert param in error["loc"]
        assert error["msg"]

    def test_from_time_after_to_time_returns_422(self, client):
        response = client.get(
            "/api/alerts",
            params={
                "from_time": "2001-06-01T00:00:00Z",
                "to_time": "2001-05-01T00:00:00Z",
            },
        )

        assert response.status_code == 422
        assert "from_time" in response.json()["detail"][0]["loc"]

    @pytest.mark.parametrize(
        "params",
        [
            {"severity": "SEVERE"},
            {"status": "pending"},
            {"source_ip": "999.1.1.1"},
            {"source_ip": "not-an-ip"},
            {"limit": 0},
            {"limit": 1001},
            {"limit": "abc"},
            {"offset": -1},
            {"rule_name": ""},
        ],
    )
    def test_invalid_params_return_422(self, client, params):
        response = client.get("/api/alerts", params=params)

        assert response.status_code == 422


# --------------------------------------------------------------------------- #
# GET /api/alerts/{alert_id}
# --------------------------------------------------------------------------- #

class TestGetAlert:
    def test_get_existing(self, client, db_session):
        alert = make_alert(
            db_session,
            source_ip="203.0.113.40",
            severity="CRITICAL",
            event_count=42,
        )

        response = client.get(f"/api/alerts/{alert.id}")

        assert response.status_code == 200

        body = response.json()

        assert body["id"] == alert.id
        assert body["severity"] == "CRITICAL"
        assert body["event_count"] == 42
        assert body["source_ip"] == "203.0.113.40"

    def test_not_found(self, client):
        response = client.get("/api/alerts/2147483000")

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    @pytest.mark.parametrize(
        "bad_id",
        [
            "abc",
            "0",
            "-5",
            "99999999999999999999",
        ],
    )
    def test_invalid_id_returns_422(self, client, bad_id):
        response = client.get(f"/api/alerts/{bad_id}")

        assert response.status_code == 422


# --------------------------------------------------------------------------- #
# PATCH /api/alerts/{alert_id}
# --------------------------------------------------------------------------- #

class TestPatchAlert:
    def test_close_alert_updates_record(self, client, db_session):
        alert = make_alert(
            db_session,
            source_ip="203.0.113.60",
            status="OPEN",
        )

        response = client.patch(
            f"/api/alerts/{alert.id}",
            json={"status": "RESOLVED"},
        )

        assert response.status_code == 200
        assert response.json()["status"] == "RESOLVED"

        db_session.expire_all()

        persisted = db_session.get(Alert, alert.id)

        assert persisted.status == "RESOLVED"

        response = client.get(f"/api/alerts/{alert.id}")

        assert response.json()["status"] == "RESOLVED"

    def test_closed_alert_no_longer_matches_open_filter(
        self,
        client,
        db_session,
    ):
        test_ip = "203.0.113.61"

        alert = make_alert(
            db_session,
            source_ip=test_ip,
        )

        client.patch(
            f"/api/alerts/{alert.id}",
            json={"status": "RESOLVED"},
        )

        response = client.get(
            "/api/alerts",
            params={
                "source_ip": test_ip,
                "status": "OPEN",
            },
        )

        assert response.status_code == 200
        assert response.json() == []

    def test_idempotent(self, client, db_session):
        alert = make_alert(
            db_session,
            source_ip="203.0.113.62",
            status="RESOLVED",
        )

        response = client.patch(
            f"/api/alerts/{alert.id}",
            json={"status": "RESOLVED"},
        )

        assert response.status_code == 200
        assert response.json()["status"] == "RESOLVED"

    def test_reopen(self, client, db_session):
        alert = make_alert(
            db_session,
            source_ip="203.0.113.63",
            status="RESOLVED",
        )

        response = client.patch(
            f"/api/alerts/{alert.id}",
            json={"status": "OPEN"},
        )

        assert response.status_code == 200
        assert response.json()["status"] == "OPEN"

    def test_not_found(self, client):
        response = client.patch(
            "/api/alerts/2147483000",
            json={"status": "RESOLVED"},
        )

        assert response.status_code == 404

    @pytest.mark.parametrize(
        "body",
        [
            {"status": "resolved"},
            {"status": ""},
            {},
            {"status": "RESOLVED", "severity": "LOW"},
            {"status": None},
        ],
    )
    def test_invalid_body_returns_422(
        self,
        client,
        db_session,
        body,
    ):
        alert = make_alert(
            db_session,
            source_ip="203.0.113.64",
        )

        response = client.patch(
            f"/api/alerts/{alert.id}",
            json=body,
        )

        assert response.status_code == 422

        db_session.expire_all()

        persisted = db_session.get(Alert, alert.id)

        assert persisted.status == "OPEN"

    def test_other_fields_untouched(self, client, db_session):
        alert = make_alert(
            db_session,
            source_ip="203.0.113.65",
            severity="CRITICAL",
            event_count=9,
        )

        response = client.patch(
            f"/api/alerts/{alert.id}",
            json={"status": "RESOLVED"},
        )

        assert response.status_code == 200

        body = response.json()

        assert body["severity"] == "CRITICAL"
        assert body["event_count"] == 9
        assert body["rule_name"] == "brute_force"


# --------------------------------------------------------------------------- #
# GET /api/alerts/summary
# --------------------------------------------------------------------------- #

class TestSummary:
    def _seed_acceptance_data(self, db):
        """Create 10 HIGH and 3 CRITICAL alerts.

        Counts by rule: 8 brute_force and 5 port_scan.
        All records use the same source IP so the summary can be isolated.
        """
        for index in range(13):
            make_alert(
                db,
                source_ip=SUMMARY_IP,
                rule_name=(
                    "brute_force"
                    if index < 8
                    else "port_scan"
                ),
                severity=(
                    "HIGH"
                    if index < 10
                    else "CRITICAL"
                ),
            )

    def test_summary_matches_acceptance_example(
        self,
        client,
        db_session,
    ):
        self._seed_acceptance_data(db_session)

        response = client.get(
            "/api/alerts/summary",
            params=summary_params(),
        )

        assert response.status_code == 200

        assert response.json() == {
            "by_severity": {
                "HIGH": 10,
                "CRITICAL": 3,
            },
            "by_rule": {
                "brute_force": 8,
                "port_scan": 5,
            },
        }

    def test_summary_respects_status_filter(
        self,
        client,
        db_session,
    ):
        self._seed_acceptance_data(db_session)

        first_alert = (
            db_session.query(Alert)
            .filter(Alert.source_ip == SUMMARY_IP)
            .order_by(Alert.id)
            .first()
        )

        assert first_alert is not None

        response = client.patch(
            f"/api/alerts/{first_alert.id}",
            json={"status": "RESOLVED"},
        )

        assert response.status_code == 200

        response = client.get(
            "/api/alerts/summary",
            params=summary_params(status="OPEN"),
        )

        assert response.status_code == 200

        assert response.json() == {
            "by_severity": {
                "HIGH": 9,
                "CRITICAL": 3,
            },
            "by_rule": {
                "brute_force": 7,
                "port_scan": 5,
            },
        }

    def test_summary_empty(self, client):
        response = client.get(
            "/api/alerts/summary",
            params={
                "from_time": "1990-01-01T00:00:00Z",
                "to_time": "1990-01-02T00:00:00Z",
                "source_ip": "198.51.100.251",
            },
        )

        assert response.status_code == 200

        assert response.json() == {
            "by_severity": {},
            "by_rule": {},
        }

    def test_summary_invalid_time_returns_422(self, client):
        response = client.get(
            "/api/alerts/summary",
            params={"from_time": "garbage"},
        )

        assert response.status_code == 422