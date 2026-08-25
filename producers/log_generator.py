#!/usr/bin/env python3
"""
log_generator.py — Fake log event generator for the SIEM producer pipeline.

Generates realistic SSH, Linux auth, Apache/Nginx web access, and firewall
events as newline-delimited JSON (NDJSON). This is the primary data source
for the pipeline during development, since there is no real infrastructure
to monitor yet.

Usage:
    python producers/log_generator.py --rate 10
    python producers/log_generator.py --rate 5 --scenario brute_force
    python producers/log_generator.py --scenario port_scan --output events.log
    python producers/log_generator.py --scenario impossible_travel --count 2
    python producers/log_generator.py --rate 10 --seed 42   # reproducible output

Notes:
    - "normal" streams continuously at --rate until --count is hit, or
      forever until Ctrl+C. brute_force / port_scan / impossible_travel are
      "burst" scenarios with acceptance-criteria timing baked in (e.g. 20+
      failed logins inside 60s) — --rate is ignored for these and a warning
      is logged if you pass it anyway.
    - Every event includes: schema_version, event_id, timestamp, source_ip,
      event_type, raw_message, and username where applicable.
    - Randomly generated IPs exclude private/loopback/link-local/multicast/
      reserved ranges by default, so they look like real internet traffic.
    - Use --seed for deterministic output (handy for test fixtures / CI).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import random
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from faker import Faker

LOG = logging.getLogger("log_generator")
SCHEMA_VERSION = "1.0"
BURST_PACING_SECONDS = 0.02  # small delay between events in burst scenarios

fake = Faker()

# --------------------------------------------------------------------------
# Constants / lookup tables
# --------------------------------------------------------------------------

SSH_PORT = 22
HTTP_METHODS = ["GET", "GET", "GET", "POST", "PUT", "DELETE"]
HTTP_PATHS = [
    "/", "/index.html", "/login", "/api/v1/users", "/api/v1/orders",
    "/admin", "/wp-login.php", "/favicon.ico", "/static/app.js",
    "/api/v1/products", "/checkout", "/robots.txt", "/.env",
    "/phpmyadmin", "/api/v1/auth/token",
]
HTTP_STATUS_WEIGHTS = [
    (200, 60), (301, 5), (302, 5), (401, 8), (403, 8), (404, 10), (500, 4),
]
COMMON_SERVICE_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017, 9200]
FIREWALL_ACTIONS = ["ACCEPT", "ACCEPT", "ACCEPT", "DROP", "DROP"]
PROTOCOLS = ["TCP", "UDP"]
PAM_SERVICES = ["sshd", "sudo", "su", "login", "cron"]

# Illustrative, non-exhaustive prefixes used only to bias generated IPs
# toward a country for the impossible-travel scenario — not real geo-IP data.
INDIAN_IP_PREFIXES = ["49.36.", "103.21.", "117.194.", "182.68.", "223.190."]
US_IP_PREFIXES = ["8.8.", "23.45.", "50.116.", "104.28.", "173.245."]

BURST_SCENARIOS = {"brute_force", "port_scan", "impossible_travel"}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_bogus_ip(addr: ipaddress.IPv4Address) -> bool:
    """True for private/loopback/link-local/multicast/reserved addresses —
    ranges that wouldn't plausibly appear as a real internet source IP."""
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _random_public_ip() -> str:
    """Draw a random IPv4 address, retrying if it lands in a bogus range."""
    for _ in range(20):
        candidate = ipaddress.IPv4Address(random.randint(0x01000000, 0xDFFFFFFF))
        if not _is_bogus_ip(candidate):
            return str(candidate)
    # Astronomically unlikely to be reached, but never fail a build over it.
    return fake.ipv4_public()


def random_ip(prefixes: list[str] | None = None) -> str:
    """Return a valid IPv4 string.

    With `prefixes`, builds an address under one of those dotted prefixes
    (used to bias toward a country/region, e.g. impossible-travel). Without
    it, draws from the public IPv4 space excluding private/reserved ranges.
    """
    if prefixes:
        prefix = random.choice(prefixes)
        parts = prefix.rstrip(".").split(".")
        while len(parts) < 4:
            parts.append(str(random.randint(1, 254)))
        return ".".join(parts)
    return _random_public_ip()


def weighted_choice(weighted_pairs: list[tuple[Any, int]]) -> Any:
    values, weights = zip(*weighted_pairs)
    return random.choices(values, weights=weights, k=1)[0]


def base_event(event_type: str, source_ip: str, timestamp: datetime | None = None, **extra: Any) -> dict[str, Any]:
    event = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "timestamp": iso(timestamp) if timestamp else now_iso(),
        "source_ip": source_ip,
        "event_type": event_type,
    }
    event.update(extra)
    return event


# --------------------------------------------------------------------------
# Event builders — SSH / auth.log
# --------------------------------------------------------------------------

def ssh_failed_login(source_ip: str | None = None, username: str | None = None,
                      timestamp: datetime | None = None, port: int | None = None) -> dict[str, Any]:
    source_ip = source_ip or random_ip()
    username = username or random.choice(
        [fake.user_name(), "root", "admin", "test", "oracle", "postgres"]
    )
    port = port or random.randint(1025, 65000)
    msg = f"Failed password for {username} from {source_ip} port {port} ssh2"
    return base_event(
        "failed_login", source_ip, timestamp,
        username=username, service="sshd", outcome="failure",
        dest_port=SSH_PORT, raw_message=msg,
    )


def ssh_successful_login(source_ip: str | None = None, username: str | None = None,
                          timestamp: datetime | None = None, port: int | None = None) -> dict[str, Any]:
    source_ip = source_ip or random_ip()
    username = username or fake.user_name()
    port = port or random.randint(1025, 65000)
    msg = f"Accepted password for {username} from {source_ip} port {port} ssh2"
    return base_event(
        "successful_login", source_ip, timestamp,
        username=username, service="sshd", outcome="success",
        dest_port=SSH_PORT, raw_message=msg,
    )


def linux_auth_event(source_ip: str | None = None, username: str | None = None,
                      timestamp: datetime | None = None) -> dict[str, Any]:
    """sudo / su / PAM-style auth.log events."""
    source_ip = source_ip or random_ip()
    username = username or fake.user_name()
    service = random.choice(PAM_SERVICES)
    outcome = random.choice(["success", "success", "failure"])

    if service == "sudo":
        target = random.choice(["root", "www-data"])
        if outcome == "success":
            msg = f"{username} : TTY=pts/0 ; PWD=/home/{username} ; USER={target} ; COMMAND=/bin/bash"
            event_type = "sudo_command"
        else:
            msg = f"{username} : 1 incorrect password attempt ; TTY=pts/0 ; USER={target} ; COMMAND=/bin/bash"
            event_type = "sudo_failure"
    elif service == "su":
        if outcome == "success":
            msg = f"(to root) {username} on pts/0"
            event_type = "su_success"
        else:
            msg = f"pam_unix(su:auth): authentication failure; logname={username} uid=0 euid=0 tty=pts/0 ruser={username} rhost="
            event_type = "su_failure"
    else:
        if outcome == "success":
            msg = f"pam_unix({service}:session): session opened for user {username}"
            event_type = "pam_session_opened"
        else:
            msg = f"pam_unix({service}:auth): authentication failure; logname= uid=0 euid=0 tty={service} ruser= rhost= user={username}"
            event_type = "pam_auth_failure"

    return base_event(
        event_type, source_ip, timestamp,
        username=username, service=service, outcome=outcome, raw_message=msg,
    )


# --------------------------------------------------------------------------
# Event builders — Web access log
# --------------------------------------------------------------------------

def web_access_event(source_ip: str | None = None, timestamp: datetime | None = None,
                      status: int | None = None, path: str | None = None) -> dict[str, Any]:
    source_ip = source_ip or random_ip()
    method = random.choice(HTTP_METHODS)
    path = path or random.choice(HTTP_PATHS)
    status = status if status is not None else weighted_choice(HTTP_STATUS_WEIGHTS)
    user_agent = fake.user_agent()
    size = random.randint(150, 45000)
    ts = timestamp or datetime.now(timezone.utc)
    apache_time = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")

    msg = (
        f'{source_ip} - - [{apache_time}] "{method} {path} HTTP/1.1" '
        f'{status} {size} "-" "{user_agent}"'
    )

    return base_event(
        "web_access", source_ip, timestamp,
        method=method, path=path, status_code=status,
        user_agent=user_agent, bytes_sent=size, raw_message=msg,
    )


# --------------------------------------------------------------------------
# Event builders — Firewall
# --------------------------------------------------------------------------

def firewall_event(source_ip: str | None = None, dest_ip: str | None = None,
                    dest_port: int | None = None, timestamp: datetime | None = None,
                    action: str | None = None) -> dict[str, Any]:
    source_ip = source_ip or random_ip()
    dest_ip = dest_ip or random_ip()
    dest_port = dest_port or random.choice(COMMON_SERVICE_PORTS)
    src_port = random.randint(1025, 65000)
    protocol = random.choice(PROTOCOLS)
    action = action or random.choice(FIREWALL_ACTIONS)

    msg = (
        f"{action} IN=eth0 OUT= SRC={source_ip} DST={dest_ip} PROTO={protocol} "
        f"SPT={src_port} DPT={dest_port}"
    )

    # event_type stays generic; `action` is the single source of truth for
    # ACCEPT/DROP so callers don't have to parse it back out of event_type.
    return base_event(
        "firewall_traffic", source_ip, timestamp,
        dest_ip=dest_ip, dest_port=dest_port, src_port=src_port,
        protocol=protocol, action=action, raw_message=msg,
    )


# --------------------------------------------------------------------------
# Scenario generators — each returns a list of events with timestamps set
# --------------------------------------------------------------------------

def scenario_normal(n: int) -> list[dict[str, Any]]:
    """Realistic mix of event types with varied IPs."""
    generators: list[Callable[[], dict[str, Any]]] = [
        ssh_failed_login, ssh_successful_login, linux_auth_event,
        web_access_event, web_access_event, firewall_event,
    ]
    events = []
    now = datetime.now(timezone.utc)
    for i in range(n):
        ts = now + timedelta(milliseconds=i * random.randint(50, 400))
        event = random.choice(generators)()
        event["timestamp"] = iso(ts)
        events.append(event)
    return events


def scenario_brute_force(n: int) -> list[dict[str, Any]]:
    """20+ failed_login events from a single IP within 60 seconds, followed
    by an eventual successful login (classic brute-force-then-breach)."""
    attacker_ip = random_ip()
    usernames = ["root", "admin", "administrator", fake.user_name(), "test"]
    n = max(n, 25)
    start = datetime.now(timezone.utc)
    window_seconds = 55  # comfortably inside the 60s acceptance window

    events = []
    for i in range(n):
        ts = start + timedelta(seconds=(window_seconds * i / max(n - 1, 1)))
        username = random.choice(usernames)
        events.append(ssh_failed_login(source_ip=attacker_ip, username=username, timestamp=ts))

    events.append(
        ssh_successful_login(
            source_ip=attacker_ip,
            username=random.choice(usernames),
            timestamp=start + timedelta(seconds=window_seconds + 2),
        )
    )
    return events


def scenario_port_scan(n: int) -> list[dict[str, Any]]:
    """One IP hitting 30+ different destination ports within 30 seconds."""
    scanner_ip = random_ip()
    target_ip = random_ip()
    n = max(n, 35)
    ports = random.sample(range(1, 65535), n)
    start = datetime.now(timezone.utc)
    window_seconds = 25  # comfortably inside the 30s acceptance window

    events = []
    for i, port in enumerate(ports):
        ts = start + timedelta(seconds=(window_seconds * i / max(n - 1, 1)))
        events.append(
            firewall_event(
                source_ip=scanner_ip, dest_ip=target_ip,
                dest_port=port, timestamp=ts, action="DROP",
            )
        )
    return events


def scenario_impossible_travel(n: int) -> list[dict[str, Any]]:
    """Two successful logins for the same username from an Indian IP and a
    US IP, 3 minutes apart — a classic impossible-travel indicator."""
    username = fake.user_name()
    india_ip = random_ip(INDIAN_IP_PREFIXES)
    us_ip = random_ip(US_IP_PREFIXES)
    start = datetime.now(timezone.utc)

    events = [
        ssh_successful_login(source_ip=india_ip, username=username, timestamp=start),
        ssh_successful_login(
            source_ip=us_ip, username=username, timestamp=start + timedelta(minutes=3)
        ),
    ]

    extra = max(n - 2, 0)
    if extra:
        events.extend(scenario_normal(extra))
        events.sort(key=lambda e: e["timestamp"])
    return events


SCENARIOS: dict[str, Callable[[int], list[dict[str, Any]]]] = {
    "normal": scenario_normal,
    "brute_force": scenario_brute_force,
    "port_scan": scenario_port_scan,
    "impossible_travel": scenario_impossible_travel,
}


# --------------------------------------------------------------------------
# CLI / main loop
# --------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate realistic fake SIEM log events as NDJSON."
    )
    parser.add_argument(
        "--rate", type=float, default=None,
        help="Events per second when streaming continuously (default: 1.0). "
             "Ignored for burst scenarios (brute_force, port_scan, impossible_travel).",
    )
    parser.add_argument(
        "--scenario", choices=sorted(SCENARIOS.keys()), default="normal",
        help="Which event scenario to generate (default: normal).",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="File to write NDJSON events to (default: stdout). Parent dirs are created if missing.",
    )
    parser.add_argument(
        "--count", type=int, default=None,
        help="Total number of events to generate then exit. If omitted, 'normal' "
             "streams until interrupted; burst scenarios always emit their full batch.",
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="Seed the RNG for reproducible output — useful for test fixtures.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging to stderr.",
    )
    args = parser.parse_args(argv)

    if args.rate is not None and args.rate <= 0:
        parser.error("--rate must be a positive number")
    if args.count is not None and args.count <= 0:
        parser.error("--count must be a positive integer")

    return args


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )


def open_output(path: str | None):
    if not path:
        return sys.stdout
    out_path = Path(path)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        return open(out_path, "a", buffering=1, encoding="utf-8")
    except OSError as exc:
        LOG.error("Could not open output file %s: %s", path, exc)
        sys.exit(1)


def emit(event: dict[str, Any], out) -> None:
    out.write(json.dumps(event) + "\n")
    out.flush()


def _suppress_broken_pipe_on_stdout() -> None:
    """Redirect stdout to /dev/null so Python doesn't print a noisy
    traceback when a downstream reader (e.g. `| head`) closes early."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except OSError:
        pass


def run_burst_scenario(scenario_name: str, count: int | None, out) -> int:
    """Pre-builds the full timed batch, then replays it with a small pacing
    delay so downstream consumers see the events arrive roughly in order."""
    n = count or (30 if scenario_name != "impossible_travel" else 2)
    events = SCENARIOS[scenario_name](n)
    generated = 0
    try:
        for event in events:
            emit(event, out)
            generated += 1
            time.sleep(BURST_PACING_SECONDS)
    except KeyboardInterrupt:
        LOG.info("Interrupted by user — exiting after %d events.", generated)
    except BrokenPipeError:
        if out is sys.stdout:
            _suppress_broken_pipe_on_stdout()
    return generated


def run_streaming(scenario_name: str, rate: float, count: int | None, out) -> int:
    interval = 1.0 / rate
    generated = 0
    try:
        while count is None or generated < count:
            for event in SCENARIOS[scenario_name](1):
                emit(event, out)
                generated += 1
                if count is not None and generated >= count:
                    break
            if interval:
                time.sleep(interval)
    except KeyboardInterrupt:
        LOG.info("Interrupted by user — exiting after %d events.", generated)
    except BrokenPipeError:
        if out is sys.stdout:
            _suppress_broken_pipe_on_stdout()
    return generated


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging(args.verbose)

    if args.seed is not None:
        random.seed(args.seed)
        fake.seed_instance(args.seed)
        LOG.debug("RNG seeded with %d", args.seed)

    effective_rate = args.rate if args.rate is not None else 1.0
    if args.rate is not None and args.scenario in BURST_SCENARIOS:
        LOG.warning(
            "--rate is ignored for scenario '%s' (it emits a fixed, pre-timed batch).",
            args.scenario,
        )

    out = open_output(args.output)

    if args.scenario in BURST_SCENARIOS:
        total = run_burst_scenario(args.scenario, args.count, out)
    else:
        total = run_streaming(args.scenario, effective_rate, args.count, out)

    if args.output:
        out.close()
        LOG.info("Wrote %d events to %s", total, args.output)
    else:
        LOG.debug("Streamed %d events to stdout", total)

    return 0


if __name__ == "__main__":
    sys.exit(main())