"""
consumers/schemas.py

Canonical normalized event schema for the SIEM platform.

This module is the single "contract" (CONTRACTS.md equivalent) that every
producer/normalizer/detector in the pipeline must agree on. Raw log lines
from different sources (SSH, web, firewall, auth) are parsed by the
per-source `normalize_*` functions below and turned into a single
`LogEvent` shape, so downstream enrichment and detection code never has to
know or care which log source an event originally came from.

Issue reference: "Define canonical normalized event schema"
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

# --------------------------------------------------------------------------
# Controlled vocabularies
# --------------------------------------------------------------------------

# event_type is a controlled vocabulary (see issue notes).
EventType = Literal[
    "failed_login",
    "successful_login",
    "web_request",
    "firewall_drop",
    "firewall_accept",
    "sudo_attempt",
]

Severity = Literal["INFO", "MEDIUM", "HIGH", "CRITICAL"]

SourceType = Literal["ssh", "web", "firewall", "auth"]

FirewallAction = Literal["ACCEPT", "DROP"]


def _validate_ip(value: str, field_name: str) -> str:
    """Shared IPv4/IPv6 validation used by source_ip and dest_ip."""
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(
            f"{field_name!r} is not a valid IP address: {value!r}"
        ) from exc
    return value


# --------------------------------------------------------------------------
# LogEvent: the canonical normalized event
# --------------------------------------------------------------------------


class LogEvent(BaseModel):
    """
    Canonical normalized log event.

    Every event that leaves the normalization layer -- regardless of which
    raw source it came from -- must conform to this shape. Fields that only
    make sense for a given source (SSH, web, firewall) are optional here,
    but are enforced as required *per-source* by the model_validator below,
    so a "web" event can never be missing `path`/`method`/`status_code`,
    for example.
    """

    # --- Universal required fields (all sources) ---
    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    timestamp: datetime
    source_ip: str
    event_type: EventType
    severity: Severity
    raw_message: str = Field(min_length=1)
    source: SourceType

    # --- SSH-specific optional fields ---
    username: Optional[str] = None
    auth_method: Optional[str] = None
    success: Optional[bool] = None

    # --- Web-specific optional fields ---
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = Field(default=None, ge=100, le=599)
    user_agent: Optional[str] = None
    bytes_sent: Optional[int] = Field(default=None, ge=0)

    # --- Firewall-specific optional fields ---
    action: Optional[FirewallAction] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: Optional[str] = None

    # --- GeoIP enrichment (optional; populated by enrichment/, which runs
    # between normalization and detection. latitude/longitude become the
    # Elasticsearch `location` geo_point in ElasticsearchStorageService) ---
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)

    # --- ASN enrichment (enrichment/asn.py) ---
    asn_number: Optional[int] = Field(default=None, ge=0, le=4_294_967_295)
    asn_org: Optional[str] = None

    # --- IP reputation enrichment (enrichment/ip_reputation.py). A null
    # reputation_score means "not assessed" (private IP, no API key, API
    # unavailable), which is different from 0 ("assessed and clean"). ---
    reputation_score: Optional[int] = Field(default=None, ge=0, le=100)
    is_known_threat: Optional[bool] = None
    threat_categories: Optional[list[str]] = None

    model_config = {"extra": "forbid"}

    # -- validators --------------------------------------------------

    @field_validator("timestamp")
    @classmethod
    def _timestamp_must_be_tz_aware(cls, value: datetime) -> datetime:
        # Require ISO 8601 with an explicit offset so downstream storage
        # (Postgres/Elasticsearch) never has to guess a timezone.
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value

    @field_validator("source_ip")
    @classmethod
    def _source_ip_valid(cls, value: str) -> str:
        return _validate_ip(value, "source_ip")

    @field_validator("dest_ip")
    @classmethod
    def _dest_ip_valid(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        return _validate_ip(value, "dest_ip")

    @model_validator(mode="after")
    def _require_source_specific_fields(self) -> "LogEvent":
        """
        Enforce that source-specific fields are present for their source,
        so a malformed/partial normalization fails loudly with a
        ValidationError instead of silently producing a half-populated
        event.
        """
        if self.source == "ssh":
            missing = [
                f
                for f in ("username", "auth_method", "success")
                if getattr(self, f) is None
            ]
            if missing:
                raise ValueError(f"ssh events require fields: {missing}")

        elif self.source == "web":
            missing = [
                f
                for f in ("method", "path", "status_code")
                if getattr(self, f) is None
            ]
            if missing:
                raise ValueError(f"web events require fields: {missing}")

        elif self.source == "firewall":
            missing = [
                f
                for f in ("action", "dest_ip", "dest_port", "protocol")
                if getattr(self, f) is None
            ]
            if missing:
                raise ValueError(f"firewall events require fields: {missing}")

        # "auth" (e.g. sudo) events reuse the universal fields only; no
        # additional required fields beyond the base contract.

        return self


# --------------------------------------------------------------------------
# AlertEvent: emitted by the detection layer onto the `alerts` topic
# --------------------------------------------------------------------------


class AlertEvent(BaseModel):
    """
    Canonical alert produced by the detection layer. Consumed by the
    alerts Kafka topic / PostgreSQL / API / Grafana.
    """

    alert_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    triggered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    rule_name: str = Field(min_length=1)
    severity: Severity
    description: str = Field(min_length=1)
    source_ip: str
    source_event_ids: list[uuid.UUID] = Field(default_factory=list)
    status: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"] = "OPEN"

    # --- Impossible-travel-specific optional fields ---
    username: Optional[str] = None
    login_1_country: Optional[str] = None
    login_2_country: Optional[str] = None
    time_delta_minutes: Optional[float] = None
    distance_km: Optional[float] = None

    model_config = {"extra": "forbid"}

    @field_validator("triggered_at")
    @classmethod
    def _triggered_at_tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value

    @field_validator("source_ip")
    @classmethod
    def _source_ip_valid(cls, value: str) -> str:
        return _validate_ip(value, "source_ip")


# --------------------------------------------------------------------------
# normalize() functions: one per raw log source
# --------------------------------------------------------------------------

_CURRENT_YEAR = datetime.now(timezone.utc).year


class NormalizationError(ValueError):
    """Raised when a raw log line cannot be parsed at all (not even
    reaching Pydantic validation). Distinct from ValidationError, which
    means the line parsed but produced an invalid LogEvent."""


# --- SSH -------------------------------------------------------------

# e.g.
#   "Sep 06 10:15:32 host sshd[1234]: Failed password for invalid user
#    admin from 10.0.0.5 port 22 ssh2"
#   "Sep 06 10:16:01 host sshd[1234]: Accepted publickey for alice from
#    10.0.0.6 port 22 ssh2"
_SSH_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<result>Failed|Accepted)\s+(?P<auth_method>\S+)\s+for\s+"
    r"(?:invalid user\s+)?(?P<username>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+\d+"
)


def normalize_ssh_log(raw: str) -> LogEvent:
    """Parse a raw sshd auth log line into a canonical LogEvent."""
    match = _SSH_RE.match(raw.strip())
    if not match:
        raise NormalizationError(f"Could not parse SSH log line: {raw!r}")

    ts = _parse_syslog_timestamp(match.group("ts"))
    success = match.group("result") == "Accepted"
    event_type: EventType = "successful_login" if success else "failed_login"
    severity: Severity = "INFO" if success else "MEDIUM"

    return LogEvent(
        timestamp=ts,
        source_ip=match.group("ip"),
        event_type=event_type,
        severity=severity,
        raw_message=raw.strip(),
        source="ssh",
        username=match.group("username"),
        auth_method=match.group("auth_method"),
        success=success,
    )


# --- Web (Apache/Nginx combined log format) --------------------------

# e.g.
#   '10.0.0.5 - - [06/Sep/2026:10:15:32 +0000] "GET /login HTTP/1.1"
#    200 512 "-" "Mozilla/5.0"'
_WEB_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+"(?P<referrer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"'
)

_WEB_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def normalize_web_log(raw: str) -> LogEvent:
    """Parse a raw web-server access log line (combined log format)."""
    match = _WEB_RE.match(raw.strip())
    if not match:
        raise NormalizationError(f"Could not parse web log line: {raw!r}")

    ts = datetime.strptime(match.group("ts"), _WEB_TS_FORMAT)
    status_code = int(match.group("status"))
    bytes_sent_raw = match.group("bytes")
    bytes_sent = 0 if bytes_sent_raw == "-" else int(bytes_sent_raw)
    severity: Severity = "MEDIUM" if status_code >= 400 else "INFO"

    return LogEvent(
        timestamp=ts,
        source_ip=match.group("ip"),
        event_type="web_request",
        severity=severity,
        raw_message=raw.strip(),
        source="web",
        method=match.group("method"),
        path=match.group("path"),
        status_code=status_code,
        user_agent=match.group("user_agent"),
        bytes_sent=bytes_sent,
    )


# --- Firewall ----------------------------------------------------------

# e.g.
#   "2026-09-06T10:15:32Z ACTION=DROP SRC=10.0.0.5 DST=10.0.0.10
#    DPT=443 PROTO=TCP"
_FIREWALL_RE = re.compile(
    r"^(?P<ts>\S+)\s+ACTION=(?P<action>ACCEPT|DROP)\s+SRC=(?P<src>\S+)\s+"
    r"DST=(?P<dst>\S+)\s+DPT=(?P<dport>\d+)\s+PROTO=(?P<proto>\S+)"
)


def normalize_firewall_log(raw: str) -> LogEvent:
    """Parse a raw iptables/netfilter-style firewall log line."""
    match = _FIREWALL_RE.match(raw.strip())
    if not match:
        raise NormalizationError(f"Could not parse firewall log line: {raw!r}")

    ts = datetime.fromisoformat(match.group("ts").replace("Z", "+00:00"))
    action = match.group("action")
    event_type: EventType = (
        "firewall_drop" if action == "DROP" else "firewall_accept"
    )
    severity: Severity = "MEDIUM" if action == "DROP" else "INFO"

    return LogEvent(
        timestamp=ts,
        source_ip=match.group("src"),
        event_type=event_type,
        severity=severity,
        raw_message=raw.strip(),
        source="firewall",
        action=action,
        dest_ip=match.group("dst"),
        dest_port=int(match.group("dport")),
        protocol=match.group("proto"),
    )


# --- Auth (sudo) ---------------------------------------------------------

# e.g.
#   "Sep 06 10:15:32 host sudo: alice : TTY=pts/0 ; PWD=/home/alice ;
#    USER=root ; COMMAND=/bin/bash"
_SUDO_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sudo:\s+"
    r"(?P<username>\S+)\s+:.*COMMAND=(?P<command>\S+)"
)


def normalize_auth_log(raw: str, *, source_ip: str = "127.0.0.1") -> LogEvent:
    """
    Parse a raw sudo/auth log line into a canonical LogEvent.

    sudo log lines are host-local and don't carry a source IP, so callers
    on a real pipeline should pass the host's known management/agent IP;
    it defaults to loopback for standalone/local sudo activity.
    """
    match = _SUDO_RE.match(raw.strip())
    if not match:
        raise NormalizationError(f"Could not parse auth/sudo log line: {raw!r}")

    ts = _parse_syslog_timestamp(match.group("ts"))

    return LogEvent(
        timestamp=ts,
        source_ip=source_ip,
        event_type="sudo_attempt",
        severity="MEDIUM",
        raw_message=raw.strip(),
        source="auth",
        username=match.group("username"),
        auth_method="sudo",
        success=True,
    )


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------


def _parse_syslog_timestamp(ts: str) -> datetime:
    """
    Parse a traditional syslog timestamp ('Sep 06 10:15:32'), which has no
    year, assuming the current year, and attach UTC as the timezone.
    """
    parsed = datetime.strptime(
        f"{_CURRENT_YEAR} {ts}",
        "%Y %b %d %H:%M:%S",
    )
    return parsed.replace(tzinfo=timezone.utc)