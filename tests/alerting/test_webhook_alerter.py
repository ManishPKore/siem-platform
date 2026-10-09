import logging
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests

from api.services.alerting.webhook_alerter import (
    WebhookAlerter,
    WebhookConfig,
)

SLACK_URL = "https://hooks.slack.com/services/T000/B000/SECRETTOKEN"
DISCORD_URL = "https://discord.com/api/webhooks/123456/SECRETTOKEN"
MODULE = "api.services.alerting.webhook_alerter"


class FakeClock:
    """Controllable monotonic clock for rate-limit tests."""

    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def make_response(status=200, headers=None):
    """Create a mock HTTP response."""
    response = MagicMock()
    response.status_code = status
    response.headers = headers or {}
    return response


def make_alert(**overrides):
    """Create a representative SIEM alert."""
    alert = {
        "severity": "CRITICAL",
        "rule_name": "brute_force",
        "source_ip": "203.0.113.7",
        "country": "Germany",
        "event_count": 27,
        "triggered_at": datetime(
            2026,
            10,
            8,
            12,
            30,
            0,
            tzinfo=timezone.utc,
        ),
    }

    alert.update(overrides)
    return alert


@pytest.fixture
def mock_post():
    """Mock HTTP POST calls without contacting a real webhook."""
    with patch(
        f"{MODULE}.requests.post",
        return_value=make_response(200),
    ) as mock:
        yield mock


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def sleep():
    return MagicMock()


@pytest.fixture
def make_alerter(clock, sleep):
    """Build an alerter with deterministic clock and sleep functions."""

    def _make(url=SLACK_URL, **config_overrides):
        return WebhookAlerter(
            WebhookConfig(url=url, **config_overrides),
            sleep=sleep,
            clock=clock,
        )

    return _make


# --------------------------------------------------------------------------- #
# Formatting
# --------------------------------------------------------------------------- #

def test_critical_slack_message_has_emoji_and_all_fields(
    make_alerter,
    mock_post,
):
    assert make_alerter(SLACK_URL).send_alert(make_alert()) is True

    mock_post.assert_called_once()
    assert mock_post.call_args.args[0] == SLACK_URL

    payload = mock_post.call_args.kwargs["json"]

    assert "🚨" in payload["text"]

    attachment = payload["attachments"][0]
    assert attachment["color"] == "#FF0000"

    blocks = attachment["blocks"]
    assert "🚨" in blocks[0]["text"]["text"]

    body = " ".join(
        field["text"]
        for field in blocks[1]["fields"]
    )

    for expected in (
        "CRITICAL",
        "brute_force",
        "203.0.113.7",
        "Germany",
        "27",
        "2026-10-08 12:30:00 UTC",
    ):
        assert expected in body


def test_critical_discord_embed_has_emoji_color_and_all_fields(
    make_alerter,
    mock_post,
):
    assert make_alerter(DISCORD_URL).send_alert(make_alert()) is True

    payload = mock_post.call_args.kwargs["json"]
    embed = payload["embeds"][0]

    assert "🚨" in embed["title"]
    assert "brute_force" in embed["title"]
    assert embed["color"] == 0xFF0000
    assert embed["timestamp"] == "2026-10-08T12:30:00+00:00"

    values = {
        field["name"]: field["value"]
        for field in embed["fields"]
    }

    assert values["Source IP"] == "`203.0.113.7`"
    assert values["Country"] == "Germany"
    assert values["Event Count"] == "27"
    assert "CRITICAL" in values["Severity"]
    assert values["Rule"] == "brute_force"
    assert "content" not in payload


@pytest.mark.parametrize(
    "severity,color",
    [
        ("CRITICAL", 0xFF0000),
        ("HIGH", 0xFF8C00),
        ("MEDIUM", 0xFFD700),
    ],
)
def test_discord_severity_colors(
    make_alerter,
    mock_post,
    severity,
    color,
):
    alerter = make_alerter(
        DISCORD_URL,
        min_severity="MEDIUM",
    )

    assert alerter.send_alert(make_alert(severity=severity))

    embed = mock_post.call_args.kwargs["json"]["embeds"][0]
    assert embed["color"] == color


def test_info_severity_uses_canonical_project_level(
    make_alerter,
    mock_post,
):
    alerter = make_alerter(
        DISCORD_URL,
        min_severity="INFO",
    )

    assert alerter.send_alert(make_alert(severity="INFO"))

    payload = mock_post.call_args.kwargs["json"]
    embed = payload["embeds"][0]

    assert "INFO" in embed["title"]
    assert embed["color"] == 0x808080


def test_country_omitted_when_not_enriched(
    make_alerter,
    mock_post,
):
    make_alerter(DISCORD_URL).send_alert(
        make_alert(country=None)
    )

    fields = mock_post.call_args.kwargs["json"]["embeds"][0]["fields"]
    names = [field["name"] for field in fields]

    assert "Country" not in names


def test_discord_blocks_mentions(make_alerter, mock_post):
    make_alerter(DISCORD_URL).send_alert(
        make_alert(rule_name="@everyone pwn")
    )

    payload = mock_post.call_args.kwargs["json"]

    assert payload["allowed_mentions"] == {"parse": []}


def test_slack_escapes_control_characters(make_alerter, mock_post):
    make_alerter().send_alert(
        make_alert(rule_name="<!channel> & co")
    )

    payload = mock_post.call_args.kwargs["json"]

    assert "<!channel>" not in str(payload)
    assert "&lt;!channel&gt; &amp; co" in payload["text"]


def test_accepts_object_alerts_and_iso_string_timestamps(
    make_alerter,
    mock_post,
):
    alert = SimpleNamespace(
        severity="HIGH",
        rule_name="port_scan",
        source_ip="198.51.100.9",
        event_count=25,
        triggered_at="2026-10-08T12:30:00Z",
    )

    assert make_alerter(DISCORD_URL).send_alert(alert) is True

    embed = mock_post.call_args.kwargs["json"]["embeds"][0]

    assert embed["timestamp"] == "2026-10-08T12:30:00+00:00"


# --------------------------------------------------------------------------- #
# Severity filtering and validation
# --------------------------------------------------------------------------- #

def test_medium_alert_below_default_threshold_is_not_sent(
    make_alerter,
    mock_post,
):
    assert (
        make_alerter().send_alert(
            make_alert(severity="MEDIUM")
        )
        is False
    )

    mock_post.assert_not_called()


@pytest.mark.parametrize(
    "bad",
    [
        {"severity": "BOGUS"},
        {"source_ip": None},
        {"rule_name": ""},
        {"severity": "LOW"},
    ],
)
def test_invalid_alert_is_skipped_not_raised(
    make_alerter,
    mock_post,
    bad,
):
    assert make_alerter().send_alert(make_alert(**bad)) is False

    mock_post.assert_not_called()


# --------------------------------------------------------------------------- #
# Retries
# --------------------------------------------------------------------------- #

def test_failed_webhook_retries_3_times_then_logs_failed(
    make_alerter,
    mock_post,
    sleep,
    caplog,
):
    mock_post.return_value = make_response(500)

    with caplog.at_level(logging.ERROR):
        assert make_alerter().send_alert(make_alert()) is False

    assert mock_post.call_count == 3

    assert [
        call.args[0]
        for call in sleep.call_args_list
    ] == [1.0, 2.0]

    assert "FAILED after 3 attempts" in caplog.text


def test_connection_errors_are_retried(
    make_alerter,
    mock_post,
    sleep,
):
    mock_post.side_effect = requests.ConnectionError("boom")

    assert make_alerter().send_alert(make_alert()) is False

    assert mock_post.call_count == 3
    assert sleep.call_count == 2


def test_succeeds_on_later_attempt(
    make_alerter,
    mock_post,
    sleep,
):
    mock_post.side_effect = [
        requests.Timeout(),
        make_response(503),
        make_response(204),
    ]

    assert make_alerter().send_alert(make_alert()) is True
    assert mock_post.call_count == 3


def test_client_errors_are_not_retried(
    make_alerter,
    mock_post,
    sleep,
):
    mock_post.return_value = make_response(404)

    assert make_alerter().send_alert(make_alert()) is False

    assert mock_post.call_count == 1
    sleep.assert_not_called()


def test_429_honors_retry_after(
    make_alerter,
    mock_post,
    sleep,
):
    mock_post.side_effect = [
        make_response(429, {"Retry-After": "7"}),
        make_response(200),
    ]

    assert make_alerter().send_alert(make_alert()) is True
    sleep.assert_called_once_with(7.0)


def test_webhook_url_never_logged(
    make_alerter,
    mock_post,
    caplog,
):
    mock_post.side_effect = requests.ConnectionError(
        f"failed for {SLACK_URL}"
    )

    with caplog.at_level(logging.DEBUG):
        make_alerter().send_alert(make_alert())

    assert "SECRETTOKEN" not in caplog.text


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #

def test_same_ip_rate_limited_within_15_minutes(
    make_alerter,
    mock_post,
    clock,
):
    alerter = make_alerter()

    assert alerter.send_alert(make_alert()) is True

    clock.advance(14 * 60 + 59)

    assert alerter.send_alert(make_alert()) is False
    assert mock_post.call_count == 1


def test_same_ip_allowed_after_window(
    make_alerter,
    mock_post,
    clock,
):
    alerter = make_alerter()

    assert alerter.send_alert(make_alert()) is True

    clock.advance(15 * 60)

    assert alerter.send_alert(make_alert()) is True
    assert mock_post.call_count == 2


def test_different_ips_are_independent(
    make_alerter,
    mock_post,
):
    alerter = make_alerter()

    assert alerter.send_alert(
        make_alert(source_ip="203.0.113.7")
    )

    assert alerter.send_alert(
        make_alert(source_ip="203.0.113.8")
    )

    assert mock_post.call_count == 2


def test_failed_send_does_not_consume_rate_limit_slot(
    make_alerter,
    mock_post,
):
    alerter = make_alerter()
    mock_post.return_value = make_response(500)

    assert alerter.send_alert(make_alert()) is False

    mock_post.reset_mock()
    mock_post.return_value = make_response(200)

    assert alerter.send_alert(make_alert()) is True


def test_below_threshold_alert_does_not_consume_rate_limit_slot(
    make_alerter,
    mock_post,
):
    alerter = make_alerter()

    assert (
        alerter.send_alert(
            make_alert(severity="MEDIUM")
        )
        is False
    )

    assert alerter.send_alert(
        make_alert(severity="CRITICAL")
    ) is True


# --------------------------------------------------------------------------- #
# Configuration and disabled state
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "value",
    [None, "", "   "],
)
def test_missing_url_warns_and_skips(
    monkeypatch,
    mock_post,
    caplog,
    value,
):
    if value is None:
        monkeypatch.delenv(
            "ALERT_WEBHOOK_URL",
            raising=False,
        )
    else:
        monkeypatch.setenv(
            "ALERT_WEBHOOK_URL",
            value,
        )

    with caplog.at_level(logging.WARNING):
        alerter = WebhookAlerter()

        assert alerter.enabled is False
        assert alerter.send_alert(make_alert()) is False

    assert "ALERT_WEBHOOK_URL" in caplog.text
    mock_post.assert_not_called()


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("ALERT_WEBHOOK_URL", DISCORD_URL)
    monkeypatch.setenv("ALERT_WEBHOOK_MIN_SEVERITY", "critical")
    monkeypatch.setenv("ALERT_WEBHOOK_RATE_LIMIT_SECONDS", "60")

    alerter = WebhookAlerter()

    assert alerter.platform == "discord"
    assert alerter._config.min_severity == "CRITICAL"
    assert alerter._config.rate_limit_seconds == 60.0


def test_invalid_env_values_fall_back_to_defaults(monkeypatch):
    monkeypatch.setenv("ALERT_WEBHOOK_URL", SLACK_URL)
    monkeypatch.setenv("ALERT_WEBHOOK_MIN_SEVERITY", "nonsense")
    monkeypatch.setenv("ALERT_WEBHOOK_RATE_LIMIT_SECONDS", "-5")

    config = WebhookConfig.from_env()

    assert config.min_severity == "HIGH"
    assert config.rate_limit_seconds == 900


@pytest.mark.parametrize(
    "url,expected",
    [
        (SLACK_URL, "slack"),
        (DISCORD_URL, "discord"),
        (
            "https://discordapp.com/api/webhooks/1/x",
            "discord",
        ),
        (
            "https://chat.example.com/hook",
            "slack",
        ),
    ],
)
def test_platform_autodetection(
    make_alerter,
    url,
    expected,
):
    assert make_alerter(url).platform == expected


def test_explicit_platform_overrides_detection(make_alerter):
    assert (
        make_alerter(
            "https://chat.example.com/hook",
            platform="discord",
        ).platform
        == "discord"
    )