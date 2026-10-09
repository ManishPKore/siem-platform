"""Slack / Discord webhook alerter.

Sends a notification to a chat channel when a HIGH/CRITICAL alert fires.

Configuration (environment variables):
    ALERT_WEBHOOK_URL                  Webhook URL. If unset, the alerter is disabled.
    ALERT_WEBHOOK_PLATFORM             "slack" | "discord" | "auto" (default: auto,
                                       detected from the URL host)
    ALERT_WEBHOOK_MIN_SEVERITY         Minimum severity to notify on (default: HIGH)
    ALERT_WEBHOOK_RATE_LIMIT_SECONDS   Per-source-IP suppression window (default: 900)
    ALERT_WEBHOOK_TIMEOUT_SECONDS      HTTP timeout per attempt (default: 5)

Design notes:
    * send_alert() never raises: a broken notification channel must not break
      the detection pipeline. It returns True only if the webhook accepted it.
    * The webhook URL is a secret. It is never logged, and exceptions are logged
      by class name only (requests embeds the URL in some error messages).
    * Rate limiting is 1 notification per source IP per window. It follows the
      same policy as the email alerter, but maintains independent in-process
      state: email and webhook notifications do not share rate-limit slots.
    * The slot is reserved atomically before sending, preventing concurrent
      threads from double-sending. It is released if delivery fails, so a
      failed send does not silence the next alert for that IP.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# Keep severity values consistent with the SIEM project's canonical levels.
SEVERITY_RANK = {
    "INFO": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

SEVERITY_EMOJI = {
    "INFO": "⚪",
    "MEDIUM": "🟡",
    "HIGH": "🟠",
    "CRITICAL": "🚨",
}

SEVERITY_COLOR = {
    "INFO": 0x808080,
    "MEDIUM": 0xFFD700,
    "HIGH": 0xFF8C00,
    "CRITICAL": 0xFF0000,
}

PLATFORM_SLACK = "slack"
PLATFORM_DISCORD = "discord"
PLATFORM_AUTO = "auto"

DEFAULT_MIN_SEVERITY = "HIGH"
DEFAULT_RATE_LIMIT_SECONDS = 15 * 60
DEFAULT_TIMEOUT_SECONDS = 5.0

MAX_ATTEMPTS = 3
BACKOFF_BASE_SECONDS = 1.0
MAX_RETRY_AFTER_SECONDS = 30.0
_PRUNE_THRESHOLD = 1000

_DISCORD_HOSTS = ("discord.com", "discordapp.com")


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

def _env_positive_float(name: str, default: float) -> float:
    """Read a positive floating-point setting from the environment."""
    raw = os.getenv(name)

    if raw is None or not raw.strip():
        return default

    try:
        value = float(raw)
    except ValueError:
        logger.warning(
            "Invalid %s=%r; using default %s",
            name,
            raw,
            default,
        )
        return default

    if value <= 0:
        logger.warning(
            "%s must be > 0 (got %r); using default %s",
            name,
            raw,
            default,
        )
        return default

    return value


@dataclass(frozen=True)
class WebhookConfig:
    """Configuration for Slack or Discord webhook notifications."""

    url: Optional[str] = None
    platform: str = PLATFORM_AUTO
    min_severity: str = DEFAULT_MIN_SEVERITY
    rate_limit_seconds: float = DEFAULT_RATE_LIMIT_SECONDS
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_attempts: int = MAX_ATTEMPTS
    backoff_base_seconds: float = BACKOFF_BASE_SECONDS

    @classmethod
    def from_env(cls) -> "WebhookConfig":
        """Build webhook configuration from environment variables."""
        url = (os.getenv("ALERT_WEBHOOK_URL") or "").strip() or None

        platform = (
            os.getenv("ALERT_WEBHOOK_PLATFORM") or PLATFORM_AUTO
        ).strip().lower()

        if platform not in (
            PLATFORM_SLACK,
            PLATFORM_DISCORD,
            PLATFORM_AUTO,
        ):
            logger.warning(
                "Invalid ALERT_WEBHOOK_PLATFORM=%r; using 'auto'",
                platform,
            )
            platform = PLATFORM_AUTO

        min_severity = (
            os.getenv("ALERT_WEBHOOK_MIN_SEVERITY")
            or DEFAULT_MIN_SEVERITY
        ).strip().upper()

        if min_severity not in SEVERITY_RANK:
            logger.warning(
                "Invalid ALERT_WEBHOOK_MIN_SEVERITY=%r; using %s",
                min_severity,
                DEFAULT_MIN_SEVERITY,
            )
            min_severity = DEFAULT_MIN_SEVERITY

        return cls(
            url=url,
            platform=platform,
            min_severity=min_severity,
            rate_limit_seconds=_env_positive_float(
                "ALERT_WEBHOOK_RATE_LIMIT_SECONDS",
                DEFAULT_RATE_LIMIT_SECONDS,
            ),
            timeout_seconds=_env_positive_float(
                "ALERT_WEBHOOK_TIMEOUT_SECONDS",
                DEFAULT_TIMEOUT_SECONDS,
            ),
        )


@dataclass(frozen=True)
class _AlertData:
    """Normalized alert fields required for notification."""

    severity: str
    rule_name: str
    source_ip: str
    country: Optional[str]
    event_count: Optional[int]
    timestamp: datetime


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _truncate(text: str, limit: int) -> str:
    """Limit text length while preserving a visible truncation marker."""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _slack_escape(text: str) -> str:
    """Escape Slack mrkdwn control characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _field(alert: Any, name: str) -> Any:
    """Read a field from either a mapping or an object."""
    if isinstance(alert, Mapping):
        return alert.get(name)

    return getattr(alert, name, None)


def _parse_timestamp(value: Any) -> datetime:
    """Normalize supported timestamps to timezone-aware UTC."""
    if value is None:
        return datetime.now(timezone.utc)

    if isinstance(value, str):
        value = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

    if not isinstance(value, datetime):
        raise TypeError(
            f"unsupported timestamp type: {type(value).__name__}"
        )

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _detect_platform(url: str) -> Optional[str]:
    """Detect Slack or Discord from the webhook URL hostname."""
    host = (urlparse(url).hostname or "").lower()

    if host == "slack.com" or host.endswith(".slack.com"):
        return PLATFORM_SLACK

    if any(
        host == discord_host
        or host.endswith("." + discord_host)
        for discord_host in _DISCORD_HOSTS
    ):
        return PLATFORM_DISCORD

    return None


# --------------------------------------------------------------------------- #
# Webhook alerter
# --------------------------------------------------------------------------- #

class WebhookAlerter:
    """Send SIEM alerts to Slack or Discord using incoming webhooks."""

    def __init__(
        self,
        config: Optional[WebhookConfig] = None,
        *,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config or WebhookConfig.from_env()
        self._sleep = sleep
        self._clock = clock

        # This limiter is independent of EmailAlerter's limiter.
        self._last_sent: dict[str, float] = {}
        self._lock = threading.Lock()
        self._skip_warned = False

        self._platform = self._resolve_platform()

        if not self.enabled:
            logger.warning(
                "ALERT_WEBHOOK_URL is not set; webhook alerting is disabled"
            )

    @property
    def enabled(self) -> bool:
        """Return whether a webhook URL has been configured."""
        return bool(self._config.url)

    @property
    def platform(self) -> Optional[str]:
        """Return the resolved webhook platform."""
        return self._platform

    def send_alert(self, alert: Any) -> bool:
        """Send an alert notification.

        The alert can be a mapping or an object exposing:
        severity, rule_name, source_ip, event_count, triggered_at
        (or timestamp), and optionally country.

        Returns:
            True if the webhook accepted the notification; otherwise False.
        """
        if not self.enabled:
            if not self._skip_warned:
                logger.warning(
                    "ALERT_WEBHOOK_URL is not set; skipping webhook alert"
                )
                self._skip_warned = True

            return False

        try:
            data = self._normalize(alert)
        except (TypeError, ValueError) as exc:
            logger.error(
                "Webhook alert skipped: invalid alert payload (%s)",
                exc,
            )
            return False

        if (
            SEVERITY_RANK[data.severity]
            < SEVERITY_RANK[self._config.min_severity]
        ):
            logger.debug(
                "Webhook alert below minimum severity (%s < %s); skipped",
                data.severity,
                self._config.min_severity,
            )
            return False

        if not self._reserve(data.source_ip):
            logger.info(
                "Webhook alert for %s rate-limited (1 per %ds)",
                data.source_ip,
                int(self._config.rate_limit_seconds),
            )
            return False

        try:
            if self._platform == PLATFORM_DISCORD:
                payload = self._build_discord_payload(data)
            else:
                payload = self._build_slack_payload(data)

            sent = self._post_with_retry(payload)

        except Exception:  # noqa: BLE001
            # Notification failures must not interrupt alert processing.
            logger.exception(
                "Unexpected error while sending webhook alert"
            )
            sent = False

        if sent:
            logger.info(
                "Webhook alert sent: %s %s from %s",
                data.severity,
                data.rule_name,
                data.source_ip,
            )
        else:
            # Failed delivery should not consume the rate-limit window.
            self._release(data.source_ip)

        return sent

    # -- Setup and validation ----------------------------------------------- #

    def _resolve_platform(self) -> Optional[str]:
        """Resolve an explicit platform or detect it from the URL."""
        if not self._config.url:
            return None

        if self._config.platform != PLATFORM_AUTO:
            return self._config.platform

        detected = _detect_platform(self._config.url)

        if detected is None:
            logger.warning(
                "Could not detect webhook platform from URL host; "
                "assuming Slack format. "
                "Set ALERT_WEBHOOK_PLATFORM=slack or discord to override."
            )
            return PLATFORM_SLACK

        return detected

    @staticmethod
    def _normalize(alert: Any) -> _AlertData:
        """Validate and normalize fields needed for a notification."""
        severity = _field(alert, "severity")
        severity = str(
            getattr(severity, "value", severity) or ""
        ).strip().upper()

        if severity not in SEVERITY_RANK:
            raise ValueError(f"unknown severity {severity!r}")

        rule_name = _field(alert, "rule_name")
        source_ip = _field(alert, "source_ip")

        if not rule_name:
            raise ValueError("rule_name is required")

        if not source_ip:
            raise ValueError("source_ip is required")

        country = _field(alert, "country")
        country = str(country).strip() if country else None

        count = _field(alert, "event_count")
        count = int(count) if count is not None else None

        timestamp = _field(alert, "triggered_at")

        if timestamp is None:
            timestamp = _field(alert, "timestamp")

        return _AlertData(
            severity=severity,
            rule_name=str(rule_name),
            source_ip=str(source_ip),
            country=country or None,
            event_count=count,
            timestamp=_parse_timestamp(timestamp),
        )

    # -- Rate limiting ------------------------------------------------------ #

    def _reserve(self, source_ip: str) -> bool:
        """Atomically reserve the source IP's notification slot."""
        now = self._clock()
        window = self._config.rate_limit_seconds

        with self._lock:
            last = self._last_sent.get(source_ip)

            if last is not None and (now - last) < window:
                return False

            self._last_sent[source_ip] = now

            if len(self._last_sent) > _PRUNE_THRESHOLD:
                self._last_sent = {
                    ip: timestamp
                    for ip, timestamp in self._last_sent.items()
                    if (now - timestamp) < window
                }

            return True

    def _release(self, source_ip: str) -> None:
        """Release the source IP's slot after a failed notification."""
        with self._lock:
            self._last_sent.pop(source_ip, None)

    # -- Payload builders --------------------------------------------------- #

    @staticmethod
    def _display_time(timestamp: datetime) -> str:
        """Format timestamps for human-readable notification fields."""
        return timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

    def _build_slack_payload(self, data: _AlertData) -> dict:
        """Build a Slack incoming-webhook payload."""
        emoji = SEVERITY_EMOJI[data.severity]
        rule = _slack_escape(data.rule_name)
        source_ip = _slack_escape(data.source_ip)

        count = (
            "N/A"
            if data.event_count is None
            else str(data.event_count)
        )

        fields = [
            f"*Severity*\n{emoji} {data.severity}",
            f"*Rule*\n{_truncate(rule, 200)}",
            f"*Source IP*\n`{source_ip}`",
        ]

        if data.country:
            fields.append(
                f"*Country*\n"
                f"{_slack_escape(_truncate(data.country, 100))}"
            )

        fields.append(f"*Event Count*\n{count}")
        fields.append(
            f"*Time*\n{self._display_time(data.timestamp)}"
        )

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    # Use the escaped rule name to avoid raw Slack
                    # control characters such as <!channel> in the header.
                    "text": _truncate(
                        f"{emoji} {data.severity}: {rule}",
                        150,
                    ),
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": field}
                    for field in fields
                ],
            },
        ]

        return {
            # Fallback text for clients that do not render blocks.
            "text": (
                f"{emoji} [{data.severity}] {rule} "
                f"from {source_ip} ({count} events)"
            ),
            # Slack attachment wrapper provides a severity-colored sidebar.
            "attachments": [
                {
                    "color": (
                        f"#{SEVERITY_COLOR[data.severity]:06X}"
                    ),
                    "blocks": blocks,
                }
            ],
        }

    def _build_discord_payload(self, data: _AlertData) -> dict:
        """Build a Discord webhook payload using an embed."""
        emoji = SEVERITY_EMOJI[data.severity]

        count = (
            "N/A"
            if data.event_count is None
            else str(data.event_count)
        )

        fields = [
            {
                "name": "Severity",
                "value": f"{emoji} {data.severity}",
                "inline": True,
            },
            {
                "name": "Rule",
                "value": _truncate(data.rule_name, 1024),
                "inline": True,
            },
            {
                "name": "Source IP",
                "value": f"`{_truncate(data.source_ip, 100)}`",
                "inline": True,
            },
        ]

        if data.country:
            fields.append(
                {
                    "name": "Country",
                    "value": _truncate(data.country, 1024),
                    "inline": True,
                }
            )

        fields.append(
            {
                "name": "Event Count",
                "value": count,
                "inline": True,
            }
        )

        fields.append(
            {
                "name": "Time",
                "value": self._display_time(data.timestamp),
                "inline": True,
            }
        )

        return {
            "username": "SIEM Alerts",
            # Prevent alert content from pinging users or roles.
            "allowed_mentions": {"parse": []},
            "embeds": [
                {
                    "title": _truncate(
                        f"{emoji} {data.severity} — {data.rule_name}",
                        256,
                    ),
                    "color": SEVERITY_COLOR[data.severity],
                    "fields": fields,
                    "timestamp": data.timestamp.isoformat(),
                    "footer": {"text": "SIEM Platform"},
                }
            ],
        }

    # -- Delivery and retries ---------------------------------------------- #

    def _post_with_retry(self, payload: dict) -> bool:
        """POST with up to max_attempts and exponential backoff.

        Retries:
            Network errors, timeouts, HTTP 429, and HTTP 5xx.

        Does not retry:
            Other HTTP 4xx responses because repeating a bad or revoked
            webhook request is unlikely to succeed.
        """
        config = self._config
        delay = config.backoff_base_seconds
        last_reason = "unknown"

        for attempt in range(1, config.max_attempts + 1):
            wait = delay

            try:
                response = requests.post(
                    config.url,
                    json=payload,
                    timeout=config.timeout_seconds,
                )

            except requests.RequestException as exc:
                # Exception text may contain the secret webhook URL.
                last_reason = type(exc).__name__

            else:
                status = response.status_code

                if 200 <= status < 300:
                    return True

                last_reason = f"HTTP {status}"

                if status != 429 and status < 500:
                    logger.error(
                        "Webhook alert failed (%s); not retrying",
                        last_reason,
                    )
                    return False

                if status == 429:
                    wait = self._retry_after(
                        response,
                        default=delay,
                    )

            if attempt < config.max_attempts:
                logger.warning(
                    "Webhook attempt %d/%d failed (%s); "
                    "retrying in %.1fs",
                    attempt,
                    config.max_attempts,
                    last_reason,
                    wait,
                )

                self._sleep(wait)
                delay *= 2

        logger.error(
            "Webhook alert FAILED after %d attempts (last error: %s)",
            config.max_attempts,
            last_reason,
        )

        return False

    @staticmethod
    def _retry_after(response: Any, default: float) -> float:
        """Read and bound the server's Retry-After value."""
        try:
            value = float(response.headers.get("Retry-After"))
        except (TypeError, ValueError, AttributeError):
            return default

        return min(max(value, 0.0), MAX_RETRY_AFTER_SECONDS)