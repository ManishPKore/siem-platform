"""
cli_dashboard.py — Live terminal dashboard for the SIEM events pipeline.

MVP visualization tool that proves data is flowing end-to-end (Kafka -> consumer
-> PostgreSQL) before Grafana is wired up in Phase 3. Polls the `events` table
every N seconds and renders a live-updating table + summary stats + top-IPs panel.

Usage:
    python dashboards/cli_dashboard.py
    python dashboards/cli_dashboard.py --interval 5

Configuration:
    Reuses the project's centralized DB config in api/database.py (POSTGRES_URL,
    or POSTGRES_USER/PASSWORD/HOST/PORT/DB), loading .env the same way
    api/main.py does. No separate connection settings live here.

Exit:
    Ctrl+C exits cleanly with no stack trace (SIGINT/SIGTERM both handled).
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import FrameType

# Allow running as `python dashboards/cli_dashboard.py` (repo root isn't on
# sys.path by default in that case) so `api.database` is importable.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    print("python-dotenv is required. Install it with: pip install python-dotenv", file=sys.stderr)
    sys.exit(1)

# Mirrors api/main.py: .env must be loaded before api.database is imported,
# since database.py itself does not call load_dotenv().
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

try:
    from sqlalchemy import text
    from sqlalchemy.engine import Engine
    from sqlalchemy.exc import OperationalError, ProgrammingError, SQLAlchemyError
except ImportError:  # pragma: no cover
    print(
        "SQLAlchemy is required. Install it with: pip install sqlalchemy psycopg2-binary",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    from api.database import engine as db_engine
except Exception as exc:  # noqa: BLE001 - want to report any config error, not just ImportError
    print(
        f"Could not load the project's database configuration from api/database.py: {exc}\n"
        "Make sure POSTGRES_URL (or POSTGRES_USER/PASSWORD/DB) is set in your .env, "
        "and that you're running this from the repo root.",
        file=sys.stderr,
    )
    sys.exit(1)


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

DEFAULT_REFRESH_SECONDS = 2
RECENT_EVENTS_LIMIT = 20
TOP_IPS_LIMIT = 5

SEVERITY_STYLES = {
    "INFO": "white",
    "LOW": "white",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "bold bright_red",
}
DEFAULT_SEVERITY_STYLE = "dim white"

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    filename=None,
)
logger = logging.getLogger("cli_dashboard")


# --------------------------------------------------------------------------- #
# Data access
# --------------------------------------------------------------------------- #

@dataclass
class DashboardData:
    recent_events: list[dict]
    total_today: int
    unique_ips_today: int
    active_alerts: int
    top_ips: list[dict]
    error: str | None = None


def fetch_dashboard_data(engine: Engine) -> DashboardData:
    """
    Runs all dashboard queries in one connection. Any individual query that
    fails because an optional table (e.g. alerts) doesn't exist yet is
    swallowed and defaulted to 0/empty rather than crashing the dashboard.
    """
    with engine.connect() as conn:
        recent_events = [
            dict(row._mapping)
            for row in conn.execute(
                text(
                    """
                    SELECT event_id, timestamp, source_ip, event_type, severity
                    FROM events
                    ORDER BY timestamp DESC
                    LIMIT :limit
                    """
                ),
                {"limit": RECENT_EVENTS_LIMIT},
            )
        ]

        total_today = conn.execute(
            text(
                """
                SELECT COUNT(*) FROM events
                WHERE timestamp >= date_trunc('day', now())
                """
            )
        ).scalar_one()

        unique_ips_today = conn.execute(
            text(
                """
                SELECT COUNT(DISTINCT source_ip) FROM events
                WHERE timestamp >= date_trunc('day', now())
                """
            )
        ).scalar_one()

        top_ips = [
            dict(row._mapping)
            for row in conn.execute(
                text(
                    """
                    SELECT source_ip, COUNT(*) AS event_count
                    FROM events
                    GROUP BY source_ip
                    ORDER BY event_count DESC
                    LIMIT :limit
                    """
                ),
                {"limit": TOP_IPS_LIMIT},
            )
        ]

        # `alerts` table may not exist yet depending on how far the project
        # has progressed — degrade gracefully instead of crashing the dashboard.
        active_alerts = 0
        try:
            active_alerts = conn.execute(
                text("SELECT COUNT(*) FROM alerts WHERE status = 'active'")
            ).scalar_one()
        except (ProgrammingError, OperationalError):
            conn.rollback()

    return DashboardData(
        recent_events=recent_events,
        total_today=total_today,
        unique_ips_today=unique_ips_today,
        active_alerts=active_alerts,
        top_ips=top_ips,
    )


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def severity_style(severity: str | None) -> str:
    return SEVERITY_STYLES.get((severity or "").upper(), DEFAULT_SEVERITY_STYLE)


def render_events_table(data: DashboardData) -> Table:
    table = Table(
        title=f"Recent Events (latest {RECENT_EVENTS_LIMIT})",
        expand=True,
        border_style="grey50",
        header_style="bold cyan",
    )
    table.add_column("Timestamp", style="dim", no_wrap=True)
    table.add_column("Source IP", no_wrap=True)
    table.add_column("Event Type")
    table.add_column("Severity", no_wrap=True)

    if not data.recent_events:
        table.add_row(
            Text("No events yet", style="italic dim"),
            "",
            "",
            "",
        )
        return table

    for event in data.recent_events:
        ts = event.get("timestamp")
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts)
        severity = str(event.get("severity") or "UNKNOWN").upper()
        table.add_row(
            ts_str,
            str(event.get("source_ip") or "-"),
            str(event.get("event_type") or "-"),
            Text(severity, style=severity_style(severity)),
        )
    return table


def render_top_ips_panel(data: DashboardData) -> Panel:
    table = Table(box=None, expand=True, show_header=True, header_style="bold cyan")
    table.add_column("Source IP")
    table.add_column("Events", justify="right")

    if not data.top_ips:
        table.add_row(Text("No data yet", style="italic dim"), "")
    else:
        for row in data.top_ips:
            table.add_row(str(row.get("source_ip") or "-"), str(row.get("event_count", 0)))

    return Panel(table, title="Top 5 Source IPs", border_style="grey50")


def render_summary(data: DashboardData) -> Panel:
    summary = Text()
    summary.append("Total events today: ", style="bold")
    summary.append(f"{data.total_today}   ", style="cyan")
    summary.append("Unique IPs today: ", style="bold")
    summary.append(f"{data.unique_ips_today}   ", style="cyan")
    summary.append("Active alerts: ", style="bold")
    alert_style = "bold bright_red" if data.active_alerts else "green"
    summary.append(f"{data.active_alerts}", style=alert_style)
    return Panel(summary, border_style="grey50")


def render_dashboard(data: DashboardData) -> Group:
    header = Text(
        f"SIEM Live Dashboard  —  last refresh {datetime.now().strftime('%H:%M:%S')}",
        style="bold white on grey15",
        justify="center",
    )

    if data.error:
        error_panel = Panel(
            Text(f"Database error: {data.error}\nRetrying...", style="bold bright_red"),
            title="Connection Problem",
            border_style="bright_red",
        )
        return Group(header, error_panel)

    return Group(
        header,
        render_summary(data),
        render_events_table(data),
        render_top_ips_panel(data),
    )


# --------------------------------------------------------------------------- #
# Main loop
# --------------------------------------------------------------------------- #

_shutdown_requested = False


def _handle_shutdown(signum: int, frame: FrameType | None) -> None:
    global _shutdown_requested
    _shutdown_requested = True


def run_dashboard(interval: int) -> None:
    global _shutdown_requested
    _shutdown_requested = False

    console = Console()
    engine = db_engine

    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)

    last_good_data: DashboardData | None = None

    with Live(console=console, screen=True, auto_refresh=False) as live:
        while not _shutdown_requested:
            try:
                data = fetch_dashboard_data(engine)
                last_good_data = data
            except SQLAlchemyError as exc:
                logger.warning("Database query failed: %s", exc)
                data = last_good_data or DashboardData(
                    recent_events=[], total_today=0, unique_ips_today=0,
                    active_alerts=0, top_ips=[],
                )
                data.error = str(exc.__cause__ or exc)

            live.update(render_dashboard(data), refresh=True)

            # Sleep in small increments so Ctrl+C feels responsive rather than
            # waiting out the full interval.
            slept = 0.0
            step = 0.1
            while slept < interval and not _shutdown_requested:
                time.sleep(step)
                slept += step


def _positive_interval(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid int value: {value!r}") from None
    if parsed < 1:
        raise argparse.ArgumentTypeError(
            f"--interval must be at least 1 second (got {parsed})"
        )
    return parsed


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Live SIEM events dashboard.")
    parser.add_argument(
        "--interval",
        type=_positive_interval,
        default=DEFAULT_REFRESH_SECONDS,
        help=f"Refresh interval in seconds, minimum 1 (default: {DEFAULT_REFRESH_SECONDS}).",
    )
    return parser.parse_args(argv)


def main() -> None:
    args = parse_args(sys.argv[1:])
    try:
        run_dashboard(args.interval)
    except KeyboardInterrupt:
        # Belt-and-suspenders: the signal handler normally exits the loop
        # first, but this guards against a Ctrl+C landing mid-query.
        pass
    finally:
        print("\nDashboard stopped.")


if __name__ == "__main__":
    main()