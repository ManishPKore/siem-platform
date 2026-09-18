"""
Tests for dashboards/cli_dashboard.py.

Scope: these are unit tests for the pieces of the dashboard that don't
require a live Kafka/PostgreSQL stack --
    - severity -> style mapping
    - table/panel rendering (empty-state and populated)
    - --interval CLI validation
    - fetch_dashboard_data()'s query orchestration and its graceful
      fallback when the `alerts` table/column isn't available yet

fetch_dashboard_data() takes `engine` as an explicit parameter, so it's
tested here against a mocked SQLAlchemy engine/connection rather than a
real database -- no Docker/Postgres required to run this file.

Live-refresh behavior (rich.live.Live, the 2-second loop, real Ctrl+C
handling) is not covered here; that's better verified manually per the
issue's acceptance criteria (`python dashboards/cli_dashboard.py`) or in
an integration test if the project adds one later.
"""

from __future__ import annotations

import argparse
import os
from datetime import datetime
from unittest.mock import MagicMock

import pytest

# api.database resolves POSTGRES_URL (or POSTGRES_USER/PASSWORD/DB) at
# import time -- make sure something is set before cli_dashboard.py (and
# transitively api.database) is imported, same as the rest of the test
# suite relies on a configured environment.
os.environ.setdefault("POSTGRES_URL", "sqlite:///:memory:")

from sqlalchemy.exc import OperationalError, ProgrammingError

from dashboards import cli_dashboard as dash


# --------------------------------------------------------------------------- #
# severity_style
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "severity,expected",
    [
        ("INFO", "white"),
        ("MEDIUM", "yellow"),
        ("HIGH", "red"),
        ("CRITICAL", "bold bright_red"),
        ("high", "red"),  # case-insensitive
        (None, dash.DEFAULT_SEVERITY_STYLE),
        ("", dash.DEFAULT_SEVERITY_STYLE),
        ("NOT_A_REAL_SEVERITY", dash.DEFAULT_SEVERITY_STYLE),
    ],
)
def test_severity_style(severity, expected):
    assert dash.severity_style(severity) == expected


# --------------------------------------------------------------------------- #
# Rendering -- empty state
# --------------------------------------------------------------------------- #

def _render_to_text(renderable) -> str:
    from rich.console import Console

    console = Console(record=True, width=120)
    console.print(renderable)
    return console.export_text()


def test_render_events_table_empty_shows_placeholder():
    data = dash.DashboardData(
        recent_events=[], total_today=0, unique_ips_today=0,
        active_alerts=0, top_ips=[],
    )
    output = _render_to_text(dash.render_events_table(data))
    assert "No events yet" in output


def test_render_top_ips_panel_empty_shows_placeholder():
    data = dash.DashboardData(
        recent_events=[], total_today=0, unique_ips_today=0,
        active_alerts=0, top_ips=[],
    )
    output = _render_to_text(dash.render_top_ips_panel(data))
    assert "No data yet" in output


# --------------------------------------------------------------------------- #
# Rendering -- populated state
# --------------------------------------------------------------------------- #

def test_render_events_table_with_data():
    data = dash.DashboardData(
        recent_events=[
            {
                "event_id": "abc-123",
                "timestamp": datetime(2026, 9, 18, 12, 0, 0),
                "source_ip": "203.0.113.7",
                "event_type": "failed_login",
                "severity": "HIGH",
            },
        ],
        total_today=0, unique_ips_today=0, active_alerts=0, top_ips=[],
    )
    output = _render_to_text(dash.render_events_table(data))
    assert "203.0.113.7" in output
    assert "failed_login" in output
    assert "HIGH" in output
    assert "2026-09-18 12:00:00" in output


def test_render_events_table_handles_missing_fields_gracefully():
    # A row missing optional fields shouldn't blow up rendering.
    data = dash.DashboardData(
        recent_events=[{"timestamp": None, "source_ip": None,
                         "event_type": None, "severity": None}],
        total_today=0, unique_ips_today=0, active_alerts=0, top_ips=[],
    )
    output = _render_to_text(dash.render_events_table(data))
    assert "UNKNOWN" in output  # falls back to "UNKNOWN" severity label


def test_render_top_ips_panel_with_data():
    data = dash.DashboardData(
        recent_events=[], total_today=0, unique_ips_today=0, active_alerts=0,
        top_ips=[
            {"source_ip": "10.0.0.5", "event_count": 42},
            {"source_ip": "10.0.0.9", "event_count": 7},
        ],
    )
    output = _render_to_text(dash.render_top_ips_panel(data))
    assert "10.0.0.5" in output
    assert "42" in output
    assert "10.0.0.9" in output


def test_render_summary_shows_all_three_stats():
    data = dash.DashboardData(
        recent_events=[], total_today=42, unique_ips_today=7,
        active_alerts=3, top_ips=[],
    )
    output = _render_to_text(dash.render_summary(data))
    assert "42" in output
    assert "7" in output
    assert "3" in output


def test_render_dashboard_shows_error_panel_when_data_has_error():
    data = dash.DashboardData(
        recent_events=[], total_today=0, unique_ips_today=0,
        active_alerts=0, top_ips=[], error="connection refused",
    )
    output = _render_to_text(dash.render_dashboard(data))
    assert "connection refused" in output
    assert "Retrying" in output


# --------------------------------------------------------------------------- #
# --interval validation
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw,expected", [("1", 1), ("2", 2), ("30", 30)])
def test_positive_interval_accepts_valid_values(raw, expected):
    assert dash._positive_interval(raw) == expected


@pytest.mark.parametrize("raw", ["0", "-1", "-5"])
def test_positive_interval_rejects_non_positive_values(raw):
    with pytest.raises(argparse.ArgumentTypeError):
        dash._positive_interval(raw)


def test_positive_interval_rejects_non_numeric_values():
    with pytest.raises(argparse.ArgumentTypeError):
        dash._positive_interval("not-a-number")


def test_parse_args_default_interval():
    args = dash.parse_args([])
    assert args.interval == dash.DEFAULT_REFRESH_SECONDS


def test_parse_args_accepts_custom_interval():
    args = dash.parse_args(["--interval", "10"])
    assert args.interval == 10


def test_parse_args_rejects_invalid_interval(capsys):
    with pytest.raises(SystemExit) as exc_info:
        dash.parse_args(["--interval", "-5"])
    assert exc_info.value.code == 2  # argparse's standard usage-error exit code
    captured = capsys.readouterr()
    assert "at least 1 second" in captured.err


# --------------------------------------------------------------------------- #
# fetch_dashboard_data -- mocked engine, no real DB required
# --------------------------------------------------------------------------- #

class _FakeRow:
    """Mimics a SQLAlchemy Row well enough for `dict(row._mapping)`."""

    def __init__(self, mapping: dict):
        self._mapping = mapping


class _FakeScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one(self):
        return self._value


def _make_mock_engine(conn: MagicMock) -> MagicMock:
    context_manager = MagicMock()
    context_manager.__enter__.return_value = conn
    context_manager.__exit__.return_value = False
    engine = MagicMock()
    engine.connect.return_value = context_manager
    return engine


def test_fetch_dashboard_data_happy_path():
    conn = MagicMock()
    conn.execute.side_effect = [
        [_FakeRow({"event_id": "1", "timestamp": datetime(2026, 9, 18),
                    "source_ip": "10.0.0.1", "event_type": "failed_login",
                    "severity": "HIGH"})],           # recent events
        _FakeScalarResult(12),                        # total_today
        _FakeScalarResult(3),                          # unique_ips_today
        [_FakeRow({"source_ip": "10.0.0.1", "event_count": 12})],  # top_ips
        _FakeScalarResult(2),                          # active_alerts
    ]
    engine = _make_mock_engine(conn)

    data = dash.fetch_dashboard_data(engine)

    assert data.total_today == 12
    assert data.unique_ips_today == 3
    assert data.active_alerts == 2
    assert len(data.recent_events) == 1
    assert data.recent_events[0]["source_ip"] == "10.0.0.1"
    assert len(data.top_ips) == 1
    assert conn.rollback.call_count == 0


@pytest.mark.parametrize("db_error_cls", [ProgrammingError, OperationalError])
def test_fetch_dashboard_data_degrades_gracefully_when_alerts_query_fails(db_error_cls):
    """
    If the `alerts` table/column isn't available yet, active_alerts should
    fall back to 0 instead of crashing the whole dashboard refresh.
    """
    conn = MagicMock()
    conn.execute.side_effect = [
        [],                       # recent events
        _FakeScalarResult(0),     # total_today
        _FakeScalarResult(0),     # unique_ips_today
        [],                       # top_ips
        db_error_cls("SELECT ...", {}, Exception("relation alerts does not exist")),
    ]
    # Make the 5th call raise rather than return, since side_effect items
    # that are Exception instances are raised by unittest.mock.
    engine = _make_mock_engine(conn)

    data = dash.fetch_dashboard_data(engine)

    assert data.active_alerts == 0
    conn.rollback.assert_called_once()