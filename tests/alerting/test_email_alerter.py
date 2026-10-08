"""Unit tests for EmailAlerter. The SMTP client is mocked; no network is used."""

from __future__ import annotations

import smtplib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from api.services.alerting.email_alerter import (
    EmailAlertConfig,
    EmailAlerter,
    EmailConfigError,
    NotificationResult,
    SourceIpRateLimiter,
)


SMTP_PATH = "api.services.alerting.email_alerter.smtplib.SMTP"
SMTP_SSL_PATH = "api.services.alerting.email_alerter.smtplib.SMTP_SSL"
FIFTEEN_MIN = 15 * 60


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_alert(**overrides):
    data = dict(
        id=42,
        rule_name="brute_force_login",
        source_ip="203.0.113.7",
        severity="CRITICAL",
        triggered_at=datetime(
            2026,
            10,
            8,
            12,
            30,
            15,
            tzinfo=timezone.utc,
        ),
        event_count=23,
        window_start=datetime(
            2026,
            10,
            8,
            12,
            25,
            0,
            tzinfo=timezone.utc,
        ),
        window_end=datetime(
            2026,
            10,
            8,
            12,
            30,
            0,
            tzinfo=timezone.utc,
        ),
        status="open",
    )

    data.update(overrides)
    return SimpleNamespace(**data)


def make_config(**overrides) -> EmailAlertConfig:
    data = dict(
        smtp_host="smtp.test",
        smtp_port=587,
        smtp_user="user",
        smtp_password="secret",
        recipients=("soc@example.com",),
        sender="siem@example.com",
    )

    data.update(overrides)
    return EmailAlertConfig(**data)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def smtp():
    with patch(SMTP_PATH) as smtp_cls:
        server = smtp_cls.return_value.__enter__.return_value
        yield SimpleNamespace(
            cls=smtp_cls,
            server=server,
        )


@pytest.fixture
def alerter(clock) -> EmailAlerter:
    return EmailAlerter(
        make_config(),
        clock=clock,
        sleep=lambda _s: None,
    )


def sent_message(smtp):
    return smtp.server.send_message.call_args.args[0]


# ---------------------------------------------------------------
# Acceptance criteria: sending
# ---------------------------------------------------------------


def test_critical_brute_force_sends_email(alerter, smtp):
    result = alerter.notify(make_alert())

    assert result is NotificationResult.SENT

    smtp.cls.assert_called_once_with(
        "smtp.test",
        587,
        timeout=10.0,
    )

    smtp.server.starttls.assert_called_once()
    smtp.server.login.assert_called_once_with(
        "user",
        "secret",
    )
    smtp.server.send_message.assert_called_once()

    kwargs = smtp.server.send_message.call_args.kwargs

    assert kwargs["from_addr"] == "siem@example.com"
    assert kwargs["to_addrs"] == ["soc@example.com"]


@pytest.mark.parametrize(
    "severity",
    ["HIGH", "CRITICAL", "high", "Critical"],
)
def test_high_and_critical_are_sent_case_insensitive(
    alerter,
    smtp,
    severity,
):
    assert (
        alerter.notify(
            make_alert(severity=severity)
        )
        is NotificationResult.SENT
    )


@pytest.mark.parametrize(
    "severity",
    [
        "MEDIUM",
        "INFO",
        "medium",
        "info",
        "bogus",
        None,
    ],
)
def test_below_threshold_or_unknown_severity_sends_nothing(
    alerter,
    smtp,
    severity,
):
    result = alerter.notify(
        make_alert(severity=severity)
    )

    assert result is NotificationResult.BELOW_THRESHOLD
    smtp.cls.assert_not_called()


def test_threshold_is_configurable(clock, smtp):
    alerter = EmailAlerter(
        make_config(min_severity="CRITICAL"),
        clock=clock,
    )

    assert (
        alerter.notify(
            make_alert(severity="HIGH")
        )
        is NotificationResult.BELOW_THRESHOLD
    )

    assert (
        alerter.notify(
            make_alert(
                severity="CRITICAL",
                source_ip="198.51.100.1",
            )
        )
        is NotificationResult.SENT
    )

    lowered = EmailAlerter(
        make_config(min_severity="MEDIUM"),
        clock=clock,
    )

    assert (
        lowered.notify(
            make_alert(
                severity="MEDIUM",
                source_ip="198.51.100.2",
            )
        )
        is NotificationResult.SENT
    )


def test_enum_severity_is_supported(alerter, smtp):
    from enum import Enum

    class Sev(Enum):
        CRITICAL = "CRITICAL"

    assert (
        alerter.notify(
            make_alert(severity=Sev.CRITICAL)
        )
        is NotificationResult.SENT
    )


# ------------------------------------------------------------
# Acceptance criteria: rate limit
# ------------------------------------------------------------


def test_second_critical_for_same_ip_within_15_min_is_rate_limited(
    alerter,
    smtp,
    clock,
):
    assert (
        alerter.notify(make_alert())
        is NotificationResult.SENT
    )

    clock.advance(FIFTEEN_MIN - 1)

    assert (
        alerter.notify(make_alert())
        is NotificationResult.RATE_LIMITED
    )

    assert smtp.server.send_message.call_count == 1


def test_email_allowed_again_after_window(
    alerter,
    smtp,
    clock,
):
    alerter.notify(make_alert())

    clock.advance(FIFTEEN_MIN)

    assert (
        alerter.notify(make_alert())
        is NotificationResult.SENT
    )

    assert smtp.server.send_message.call_count == 2


def test_rate_limit_is_per_source_ip(alerter, smtp):
    assert (
        alerter.notify(
            make_alert(
                source_ip="203.0.113.7"
            )
        )
        is NotificationResult.SENT
    )

    assert (
        alerter.notify(
            make_alert(
                source_ip="203.0.113.8"
            )
        )
        is NotificationResult.SENT
    )

    assert smtp.server.send_message.call_count == 2


def test_below_threshold_alert_does_not_consume_rate_limit_slot(
    alerter,
    smtp,
):
    alerter.notify(
        make_alert(severity="MEDIUM")
    )

    assert (
        alerter.notify(
            make_alert(severity="CRITICAL")
        )
        is NotificationResult.SENT
    )


def test_rate_limit_disabled_when_zero(clock, smtp):
    alerter = EmailAlerter(
        make_config(rate_limit_seconds=0),
        clock=clock,
    )

    assert (
        alerter.notify(make_alert())
        is NotificationResult.SENT
    )

    assert (
        alerter.notify(make_alert())
        is NotificationResult.SENT
    )


def test_concurrent_alerts_for_same_ip_send_exactly_one_email(
    alerter,
    smtp,
):
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(
            pool.map(
                lambda _i: alerter.notify(make_alert()),
                range(32),
            )
        )

    assert (
        results.count(NotificationResult.SENT)
        == 1
    )

    assert (
        results.count(NotificationResult.RATE_LIMITED)
        == 31
    )

    assert smtp.server.send_message.call_count == 1


def test_limiter_prunes_expired_entries(clock):
    limiter = SourceIpRateLimiter(
        60,
        clock,
    )

    for i in range(100):
        assert limiter.try_acquire(
            f"10.0.0.{i}"
        )

    clock.advance(61)

    assert limiter.try_acquire(
        "10.9.9.9"
    )

    assert len(limiter._last_sent) == 1


# ------------------------------------------------------------
# Acceptance criteria: email content
# ------------------------------------------------------------


def test_subject_contains_severity_and_rule_name(
    alerter,
    smtp,
):
    alerter.notify(make_alert())

    subject = sent_message(smtp)["Subject"]

    assert "CRITICAL" in subject
    assert "brute_force_login" in subject


def test_body_contains_all_alert_fields_in_html_and_text(
    alerter,
    smtp,
):
    alerter.notify(make_alert())

    msg = sent_message(smtp)

    html_body = (
        msg.get_body(("html",))
        .get_content()
    )

    text_body = (
        msg.get_body(("plain",))
        .get_content()
    )

    for body in (
        html_body,
        text_body,
    ):
        assert "CRITICAL" in body
        assert "brute_force_login" in body
        assert "203.0.113.7" in body
        assert (
            "2026-10-08 12:30:15 UTC"
            in body
        )
        assert "23" in body
        assert (
            "2026-10-08 12:25:00 UTC"
            in body
        )
        assert (
            "2026-10-08 12:30:00 UTC"
            in body
        )

    assert "<table" in html_body


def test_naive_timestamps_are_treated_as_utc(
    alerter,
    smtp,
):
    alerter.notify(
        make_alert(
            triggered_at=datetime(
                2026,
                1,
                2,
                3,
                4,
                5,
            )
        )
    )

    assert (
        "2026-01-02 03:04:05 UTC"
        in sent_message(smtp)
        .get_body(("plain",))
        .get_content()
    )


def test_html_is_escaped(alerter, smtp):
    alerter.notify(
        make_alert(
            rule_name="<script>alert(1)</script>"
        )
    )

    html_body = (
        sent_message(smtp)
        .get_body(("html",))
        .get_content()
    )

    assert "<script>" not in html_body
    assert "&lt;script&gt;" in html_body


def test_subject_cannot_inject_headers(
    alerter,
    smtp,
):
    alerter.notify(
        make_alert(
            rule_name="x\r\nBcc: evil@example.com"
        )
    )

    msg = sent_message(smtp)

    assert "\r" not in msg["Subject"]
    assert "\n" not in msg["Subject"]
    assert msg["Bcc"] is None


def test_multiple_recipients(clock, smtp):
    config = make_config(
        recipients=(
            "a@example.com",
            "b@example.com",
        )
    )

    EmailAlerter(
        config,
        clock=clock,
    ).notify(make_alert())

    assert (
        smtp.server.send_message
        .call_args
        .kwargs["to_addrs"]
        == [
            "a@example.com",
            "b@example.com",
        ]
    )

    assert (
        sent_message(smtp)["To"]
        == "a@example.com, b@example.com"
    )


# ------------------------------------------------------------
# Failure handling
# ------------------------------------------------------------


def test_smtp_failure_does_not_raise_and_releases_rate_limit_slot(
    alerter,
    smtp,
):
    smtp.cls.side_effect = ConnectionRefusedError(
        "down"
    )

    assert (
        alerter.notify(make_alert())
        is NotificationResult.FAILED
    )

    smtp.cls.side_effect = None

    assert (
        alerter.notify(make_alert())
        is NotificationResult.SENT
    )


def test_transient_error_is_retried(
    alerter,
    smtp,
):
    smtp.server.send_message.side_effect = [
        smtplib.SMTPServerDisconnected(
            "dropped"
        ),
        None,
    ]

    assert (
        alerter.notify(make_alert())
        is NotificationResult.SENT
    )

    assert (
        smtp.server.send_message.call_count
        == 2
    )


def test_gives_up_after_max_attempts(
    alerter,
    smtp,
):
    smtp.server.send_message.side_effect = (
        TimeoutError("slow")
    )

    assert (
        alerter.notify(make_alert())
        is NotificationResult.FAILED
    )

    assert (
        smtp.server.send_message.call_count
        == 2
    )


def test_authentication_error_is_not_retried(
    alerter,
    smtp,
):
    smtp.server.login.side_effect = (
        smtplib.SMTPAuthenticationError(
            535,
            b"bad credentials",
        )
    )

    assert (
        alerter.notify(make_alert())
        is NotificationResult.FAILED
    )

    assert smtp.server.login.call_count == 1


def test_malformed_alert_does_not_raise(
    alerter,
    smtp,
):
    assert (
        alerter.notify(
            SimpleNamespace(
                severity="CRITICAL"
            )
        )
        is NotificationResult.FAILED
    )


# ------------------------------------------------------------
# Transport
# ------------------------------------------------------------


def test_port_465_uses_implicit_ssl(clock):
    config = make_config(
        smtp_port=465,
        use_ssl=True,
    )

    with (
        patch(SMTP_SSL_PATH) as ssl_cls,
        patch(SMTP_PATH) as plain_cls,
    ):
        server = (
            ssl_cls
            .return_value
            .__enter__
            .return_value
        )

        result = EmailAlerter(
            config,
            clock=clock,
        ).notify(make_alert())

    assert result is NotificationResult.SENT
    plain_cls.assert_not_called()
    server.starttls.assert_not_called()
    server.send_message.assert_called_once()


def test_starttls_can_be_disabled(clock, smtp):
    EmailAlerter(
        make_config(use_starttls=False),
        clock=clock,
    ).notify(make_alert())

    smtp.server.starttls.assert_not_called()


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------


ENV = {
    "SMTP_HOST": "sandbox.smtp.mailtrap.io",
    "SMTP_PORT": "2525",
    "SMTP_USER": "u",
    "SMTP_PASS": "p",
    "ALERT_EMAIL_TO": "a@example.com, b@example.com",
}


def test_from_env_parses_required_values():
    config = EmailAlertConfig.from_env(ENV)

    assert (
        config.smtp_host
        == "sandbox.smtp.mailtrap.io"
    )

    assert config.smtp_port == 2525

    assert config.recipients == (
        "a@example.com",
        "b@example.com",
    )

    assert config.min_severity == "HIGH"
    assert (
        config.rate_limit_seconds
        == FIFTEEN_MIN
    )

    assert (
        config.use_ssl is False
        and config.use_starttls is True
    )


def test_from_env_optional_overrides():
    env = {
        **ENV,
        "ALERT_EMAIL_MIN_SEVERITY": "critical",
        "ALERT_EMAIL_RATE_LIMIT_SECONDS": "60",
        "ALERT_EMAIL_FROM": "ops@example.com",
        "SMTP_PORT": "465",
    }

    config = EmailAlertConfig.from_env(env)

    assert config.min_severity == "CRITICAL"
    assert config.rate_limit_seconds == 60
    assert config.sender == "ops@example.com"
    assert config.use_ssl is True


@pytest.mark.parametrize(
    "missing",
    [
        "SMTP_HOST",
        "SMTP_PORT",
        "SMTP_USER",
        "SMTP_PASS",
        "ALERT_EMAIL_TO",
    ],
)
def test_from_env_reports_missing_variables(
    missing,
):
    env = {
        key: value
        for key, value in ENV.items()
        if key != missing
    }

    with pytest.raises(
        EmailConfigError,
        match=missing,
    ):
        EmailAlertConfig.from_env(env)


@pytest.mark.parametrize(
    "override",
    [
        {"SMTP_PORT": "abc"},
        {"ALERT_EMAIL_MIN_SEVERITY": "URGENT"},
        {"ALERT_EMAIL_RATE_LIMIT_SECONDS": "-5"},
    ],
)
def test_from_env_rejects_invalid_values(
    override,
):
    with pytest.raises(EmailConfigError):
        EmailAlertConfig.from_env(
            {
                **ENV,
                **override,
            }
        )


def test_password_is_not_in_repr():
    assert "secret" not in repr(
        make_config()
    )