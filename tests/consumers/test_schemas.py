"""
tests/consumers/test_schemas.py

Unit tests for consumers/schemas.py:
- LogEvent / AlertEvent Pydantic validation
- normalize_ssh_log / normalize_web_log / normalize_firewall_log /
  normalize_auth_log against raw log string examples
"""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from consumers.schemas import (
    AlertEvent,
    LogEvent,
    NormalizationError,
    normalize_auth_log,
    normalize_firewall_log,
    normalize_ssh_log,
    normalize_web_log,
)

VALID_LOG_EVENT_KWARGS = dict(
    timestamp=datetime(2026, 9, 6, 10, 15, 32, tzinfo=timezone.utc),
    source_ip="10.0.0.5",
    event_type="failed_login",
    severity="MEDIUM",
    raw_message="Failed password for admin from 10.0.0.5 port 22 ssh2",
    source="ssh",
    username="admin",
    auth_method="password",
    success=False,
)


# --------------------------------------------------------------------------
# LogEvent — base contract
# --------------------------------------------------------------------------


class TestLogEventBaseContract:
    def test_valid_event_constructs(self):
        event = LogEvent(**VALID_LOG_EVENT_KWARGS)
        assert event.source_ip == "10.0.0.5"
        assert event.event_type == "failed_login"
        assert event.severity == "MEDIUM"
        assert event.source == "ssh"

    def test_event_id_is_auto_generated_uuid(self):
        event = LogEvent(**VALID_LOG_EVENT_KWARGS)
        assert event.event_id is not None
        # round-trips through str() as a UUID
        assert str(event.event_id).count("-") == 4

    def test_timestamp_iso8601_serializes(self):
        event = LogEvent(**VALID_LOG_EVENT_KWARGS)
        dumped = event.model_dump(mode="json")
        # ISO 8601 parseable
        datetime.fromisoformat(dumped["timestamp"].replace("Z", "+00:00"))

    def test_naive_timestamp_gets_utc_attached(self):
        kwargs = dict(VALID_LOG_EVENT_KWARGS)
        kwargs["timestamp"] = datetime(2026, 9, 6, 10, 15, 32)  # naive
        event = LogEvent(**kwargs)
        assert event.timestamp.tzinfo is not None

    @pytest.mark.parametrize(
        "missing_field",
        ["timestamp", "source_ip", "event_type", "severity", "raw_message", "source"],
    )
    def test_missing_required_field_raises_validation_error(self, missing_field):
        kwargs = dict(VALID_LOG_EVENT_KWARGS)
        del kwargs[missing_field]
        with pytest.raises(ValidationError):
            LogEvent(**kwargs)

    def test_invalid_event_type_rejected(self):
        kwargs = dict(VALID_LOG_EVENT_KWARGS)
        kwargs["event_type"] = "not_a_real_type"
        with pytest.raises(ValidationError):
            LogEvent(**kwargs)

    def test_invalid_severity_rejected(self):
        kwargs = dict(VALID_LOG_EVENT_KWARGS)
        kwargs["severity"] = "SUPER_BAD"
        with pytest.raises(ValidationError):
            LogEvent(**kwargs)

    def test_invalid_source_ip_rejected(self):
        kwargs = dict(VALID_LOG_EVENT_KWARGS)
        kwargs["source_ip"] = "not-an-ip"
        with pytest.raises(ValidationError):
            LogEvent(**kwargs)

    def test_blank_raw_message_rejected(self):
        kwargs = dict(VALID_LOG_EVENT_KWARGS)
        kwargs["raw_message"] = ""
        with pytest.raises(ValidationError):
            LogEvent(**kwargs)

    def test_unknown_extra_field_rejected(self):
        kwargs = dict(VALID_LOG_EVENT_KWARGS)
        kwargs["totally_made_up_field"] = "x"
        with pytest.raises(ValidationError):
            LogEvent(**kwargs)


# --------------------------------------------------------------------------
# LogEvent — source-specific required fields
# --------------------------------------------------------------------------


class TestSourceSpecificFields:
    def test_ssh_missing_username_rejected(self):
        kwargs = dict(VALID_LOG_EVENT_KWARGS)
        kwargs["username"] = None
        with pytest.raises(ValidationError):
            LogEvent(**kwargs)

    def test_web_event_requires_method_path_status(self):
        base = dict(
            timestamp=datetime.now(timezone.utc),
            source_ip="10.0.0.5",
            event_type="web_request",
            severity="INFO",
            raw_message="GET /login 200",
            source="web",
        )
        with pytest.raises(ValidationError):
            LogEvent(**base)  # missing method/path/status_code

        base.update(method="GET", path="/login", status_code=200)
        event = LogEvent(**base)
        assert event.method == "GET"

    def test_firewall_event_requires_action_dest_ip_port_protocol(self):
        base = dict(
            timestamp=datetime.now(timezone.utc),
            source_ip="10.0.0.5",
            event_type="firewall_drop",
            severity="MEDIUM",
            raw_message="ACTION=DROP",
            source="firewall",
        )
        with pytest.raises(ValidationError):
            LogEvent(**base)

        base.update(action="DROP", dest_ip="10.0.0.10", dest_port=443, protocol="TCP")
        event = LogEvent(**base)
        assert event.dest_port == 443

    def test_invalid_dest_ip_rejected(self):
        base = dict(
            timestamp=datetime.now(timezone.utc),
            source_ip="10.0.0.5",
            event_type="firewall_drop",
            severity="MEDIUM",
            raw_message="ACTION=DROP",
            source="firewall",
            action="DROP",
            dest_ip="bad-ip",
            dest_port=443,
            protocol="TCP",
        )
        with pytest.raises(ValidationError):
            LogEvent(**base)

    def test_status_code_out_of_range_rejected(self):
        base = dict(
            timestamp=datetime.now(timezone.utc),
            source_ip="10.0.0.5",
            event_type="web_request",
            severity="INFO",
            raw_message="GET / 999",
            source="web",
            method="GET",
            path="/",
            status_code=999,
        )
        with pytest.raises(ValidationError):
            LogEvent(**base)

    def test_dest_port_out_of_range_rejected(self):
        base = dict(
            timestamp=datetime.now(timezone.utc),
            source_ip="10.0.0.5",
            event_type="firewall_drop",
            severity="MEDIUM",
            raw_message="ACTION=DROP",
            source="firewall",
            action="DROP",
            dest_ip="10.0.0.10",
            dest_port=70000,
            protocol="TCP",
        )
        with pytest.raises(ValidationError):
            LogEvent(**base)

    def test_auth_source_has_no_extra_required_fields(self):
        event = LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="127.0.0.1",
            event_type="sudo_attempt",
            severity="MEDIUM",
            raw_message="sudo attempt",
            source="auth",
        )
        assert event.source == "auth"


# --------------------------------------------------------------------------
# AlertEvent
# --------------------------------------------------------------------------


class TestAlertEvent:
    def test_valid_alert_constructs_with_defaults(self):
        alert = AlertEvent(
            rule_name="brute_force_ssh",
            severity="HIGH",
            description="5 failed SSH logins from 10.0.0.5 in 60s",
            source_ip="10.0.0.5",
        )
        assert alert.status == "OPEN"
        assert alert.alert_id is not None
        assert alert.triggered_at.tzinfo is not None
        assert alert.source_event_ids == []

    def test_alert_missing_required_field_raises(self):
        with pytest.raises(ValidationError):
            AlertEvent(severity="HIGH", description="x", source_ip="10.0.0.5")

    def test_alert_invalid_source_ip_rejected(self):
        with pytest.raises(ValidationError):
            AlertEvent(
                rule_name="brute_force_ssh",
                severity="HIGH",
                description="x",
                source_ip="not-an-ip",
            )

    def test_alert_invalid_status_rejected(self):
        with pytest.raises(ValidationError):
            AlertEvent(
                rule_name="brute_force_ssh",
                severity="HIGH",
                description="x",
                source_ip="10.0.0.5",
                status="MADE_UP_STATUS",
            )

    def test_alert_accepts_source_event_ids(self):
        import uuid

        ids = [uuid.uuid4(), uuid.uuid4()]
        alert = AlertEvent(
            rule_name="brute_force_ssh",
            severity="HIGH",
            description="x",
            source_ip="10.0.0.5",
            source_event_ids=ids,
        )
        assert alert.source_event_ids == ids


# --------------------------------------------------------------------------
# normalize_ssh_log — at least 3 raw examples
# --------------------------------------------------------------------------


class TestNormalizeSshLog:
    def test_failed_password_known_user(self):
        raw = "Sep 06 10:15:32 host sshd[1234]: Failed password for admin from 10.0.0.5 port 22 ssh2"
        event = normalize_ssh_log(raw)
        assert event.source == "ssh"
        assert event.event_type == "failed_login"
        assert event.severity == "MEDIUM"
        assert event.success is False
        assert event.username == "admin"
        assert event.source_ip == "10.0.0.5"
        assert event.raw_message == raw

    def test_failed_password_invalid_user(self):
        raw = "Sep 06 10:15:40 host sshd[1234]: Failed password for invalid user root from 10.0.0.9 port 22 ssh2"
        event = normalize_ssh_log(raw)
        assert event.event_type == "failed_login"
        assert event.username == "root"
        assert event.source_ip == "10.0.0.9"

    def test_accepted_publickey(self):
        raw = "Sep 06 10:16:01 host sshd[1234]: Accepted publickey for alice from 10.0.0.6 port 22 ssh2"
        event = normalize_ssh_log(raw)
        assert event.event_type == "successful_login"
        assert event.severity == "INFO"
        assert event.success is True
        assert event.auth_method == "publickey"
        assert event.username == "alice"

    def test_accepted_password(self):
        raw = "Sep 06 10:17:00 host sshd[1234]: Accepted password for bob from 10.0.0.7 port 22 ssh2"
        event = normalize_ssh_log(raw)
        assert event.success is True
        assert event.username == "bob"

    def test_unparseable_line_raises_normalization_error(self):
        with pytest.raises(NormalizationError):
            normalize_ssh_log("this is not an sshd log line at all")


# --------------------------------------------------------------------------
# normalize_web_log — at least 3 raw examples
# --------------------------------------------------------------------------


class TestNormalizeWebLog:
    def test_successful_get(self):
        raw = '10.0.0.5 - - [06/Sep/2026:10:15:32 +0000] "GET /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        event = normalize_web_log(raw)
        assert event.source == "web"
        assert event.event_type == "web_request"
        assert event.severity == "INFO"
        assert event.method == "GET"
        assert event.path == "/login"
        assert event.status_code == 200
        assert event.bytes_sent == 512
        assert event.user_agent == "Mozilla/5.0"
        assert event.source_ip == "10.0.0.5"

    def test_not_found_post(self):
        raw = '10.0.0.8 - - [06/Sep/2026:10:20:00 +0000] "POST /admin HTTP/1.1" 404 128 "-" "curl/8.0"'
        event = normalize_web_log(raw)
        assert event.status_code == 404
        assert event.severity == "MEDIUM"
        assert event.method == "POST"
        assert event.path == "/admin"

    def test_server_error(self):
        raw = '10.0.0.11 - - [06/Sep/2026:10:25:10 +0000] "GET /api/data HTTP/1.1" 500 0 "-" "python-requests/2.31"'
        event = normalize_web_log(raw)
        assert event.status_code == 500
        assert event.severity == "MEDIUM"
        assert event.bytes_sent == 0

    def test_dash_bytes_sent_normalized_to_zero(self):
        raw = '10.0.0.12 - - [06/Sep/2026:10:30:00 +0000] "GET /health HTTP/1.1" 204 - "-" "kube-probe/1.0"'
        event = normalize_web_log(raw)
        assert event.bytes_sent == 0

    def test_unparseable_line_raises_normalization_error(self):
        with pytest.raises(NormalizationError):
            normalize_web_log("not a combined log format line")


# --------------------------------------------------------------------------
# normalize_firewall_log — at least 3 raw examples
# --------------------------------------------------------------------------


class TestNormalizeFirewallLog:
    def test_drop_event(self):
        raw = "2026-09-06T10:15:32Z ACTION=DROP SRC=10.0.0.5 DST=10.0.0.10 DPT=443 PROTO=TCP"
        event = normalize_firewall_log(raw)
        assert event.source == "firewall"
        assert event.event_type == "firewall_drop"
        assert event.severity == "MEDIUM"
        assert event.action == "DROP"
        assert event.source_ip == "10.0.0.5"
        assert event.dest_ip == "10.0.0.10"
        assert event.dest_port == 443
        assert event.protocol == "TCP"

    def test_accept_event(self):
        raw = "2026-09-06T10:16:00Z ACTION=ACCEPT SRC=10.0.0.6 DST=10.0.0.20 DPT=80 PROTO=TCP"
        event = normalize_firewall_log(raw)
        assert event.event_type == "firewall_accept"
        assert event.severity == "INFO"
        assert event.action == "ACCEPT"

    def test_udp_protocol(self):
        raw = "2026-09-06T10:17:00Z ACTION=DROP SRC=10.0.0.7 DST=10.0.0.30 DPT=53 PROTO=UDP"
        event = normalize_firewall_log(raw)
        assert event.protocol == "UDP"
        assert event.dest_port == 53

    def test_unparseable_line_raises_normalization_error(self):
        with pytest.raises(NormalizationError):
            normalize_firewall_log("garbage firewall line")


# --------------------------------------------------------------------------
# normalize_auth_log (sudo) — at least 3 raw examples
# --------------------------------------------------------------------------


class TestNormalizeAuthLog:
    def test_sudo_bash(self):
        raw = (
            "Sep 06 10:15:32 host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; "
            "USER=root ; COMMAND=/bin/bash"
        )
        event = normalize_auth_log(raw)
        assert event.source == "auth"
        assert event.event_type == "sudo_attempt"
        assert event.severity == "MEDIUM"
        assert event.username == "alice"

    def test_sudo_with_custom_source_ip(self):
        raw = (
            "Sep 06 10:16:00 host sudo: bob : TTY=pts/1 ; PWD=/home/bob ; "
            "USER=root ; COMMAND=/usr/bin/systemctl"
        )
        event = normalize_auth_log(raw, source_ip="10.0.0.50")
        assert event.source_ip == "10.0.0.50"
        assert event.username == "bob"

    def test_sudo_apt_get(self):
        raw = (
            "Sep 06 10:17:00 host sudo: carol : TTY=pts/2 ; PWD=/tmp ; "
            "USER=root ; COMMAND=/usr/bin/apt-get"
        )
        event = normalize_auth_log(raw)
        assert event.username == "carol"

    def test_defaults_to_loopback_source_ip(self):
        raw = (
            "Sep 06 10:18:00 host sudo: dave : TTY=pts/3 ; PWD=/tmp ; "
            "USER=root ; COMMAND=/bin/ls"
        )
        event = normalize_auth_log(raw)
        assert event.source_ip == "127.0.0.1"

    def test_unparseable_line_raises_normalization_error(self):
        with pytest.raises(NormalizationError):
            normalize_auth_log("garbage sudo line")