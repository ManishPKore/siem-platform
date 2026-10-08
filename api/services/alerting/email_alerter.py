"""Email notifications for high-severity SIEM alerts.

``EmailAlerter`` sends an HTML (plus plain-text fallback) email when an alert
at or above a configurable severity threshold is raised. A per-source-IP rate
limiter prevents inbox flooding.

Design rules
------------
* ``notify()`` NEVER raises. Alerting is a side effect of detection; an SMTP
  outage must not stop alerts from being persisted. Call it *after* the alert
  has been saved to the database.
* Rate-limit state is in-process (thread-safe dict). It is lost on restart and
  is not shared between processes. Swap ``SourceIpRateLimiter`` for a Redis
  implementation (same ``try_acquire`` / ``release`` interface) in Phase 4.
* Credentials are read from the environment and never logged.
"""

from __future__ import annotations

import html
import logging
import os
import re
import smtplib
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from enum import Enum
from typing import Any, Callable, Mapping, Optional, Protocol

logger = logging.getLogger(__name__)


# Keep this aligned with the SIEM project's canonical severity model.
SEVERITY_RANK: dict[str, int] = {
    "INFO": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

_SEVERITY_COLORS: dict[str, str] = {
    "INFO": "#455a64",
    "MEDIUM": "#f9a825",
    "HIGH": "#ef6c00",
    "CRITICAL": "#c62828",
}

_REQUIRED_ENV = (
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USER",
    "SMTP_PASS",
    "ALERT_EMAIL_TO",
)


# Errors that will not be fixed by retrying.
_PERMANENT_SMTP_ERRORS = (
    smtplib.SMTPAuthenticationError,
    smtplib.SMTPRecipientsRefused,
    smtplib.SMTPSenderRefused,
    smtplib.SMTPNotSupportedError,
)


# smtplib.SMTPException subclasses OSError, so OSError covers timeouts,
# refused connections, TLS errors and SMTP errors alike. Permanent errors are
# filtered out first.
_TRANSIENT_ERRORS = (OSError,)


class EmailConfigError(ValueError):
    """Raised when the email alerting configuration is missing or invalid."""


class NotificationResult(str, Enum):
    """Result of attempting to notify about an alert."""

    SENT = "sent"
    BELOW_THRESHOLD = "below_threshold"
    RATE_LIMITED = "rate_limited"
    FAILED = "failed"


class AlertLike(Protocol):
    """Anything with the attributes required to build an alert email."""

    rule_name: str
    source_ip: Any
    severity: Any
    triggered_at: Any
    event_count: int


def _normalize_severity(value: Any) -> Optional[str]:
    """Return the upper-case severity name, or None if it is not recognised."""
    raw = getattr(value, "value", value)
    name = str(raw).strip().upper()
    return name if name in SEVERITY_RANK else None


def _env_bool(
    env: Mapping[str, str],
    key: str,
    default: bool,
) -> bool:
    """Read a boolean environment variable."""
    raw = env.get(key)

    if raw is None or raw.strip() == "":
        return default

    value = raw.strip().lower()

    if value in {"1", "true", "yes", "on"}:
        return True

    if value in {"0", "false", "no", "off"}:
        return False

    raise EmailConfigError(
        f"{key} must be a boolean, got {raw!r}"
    )


def _env_number(
    env: Mapping[str, str],
    key: str,
    default: float,
    cast: Callable,
) -> Any:
    """Read and cast a numeric environment variable."""
    raw = env.get(key)

    if raw is None or raw.strip() == "":
        return default

    try:
        return cast(raw)
    except ValueError as exc:
        raise EmailConfigError(
            f"{key} must be a number, got {raw!r}"
        ) from exc


@dataclass(frozen=True)
class EmailAlertConfig:
    """Configuration for SIEM email alert notifications."""

    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str = field(repr=False)
    recipients: tuple[str, ...]
    sender: str = "siem-alerts@siem.local"
    min_severity: str = "HIGH"
    rate_limit_seconds: int = 15 * 60
    timeout_seconds: float = 10.0
    use_ssl: bool = False
    use_starttls: bool = True
    max_attempts: int = 2
    retry_delay_seconds: float = 1.0

    def __post_init__(self) -> None:
        """Validate email alert configuration."""
        if not self.smtp_host:
            raise EmailConfigError("smtp_host is required")

        if not (0 < self.smtp_port < 65536):
            raise EmailConfigError(
                f"invalid smtp_port: {self.smtp_port}"
            )

        if not self.recipients:
            raise EmailConfigError(
                "at least one recipient is required"
            )

        if _normalize_severity(self.min_severity) is None:
            raise EmailConfigError(
                "min_severity must be one of "
                f"{sorted(SEVERITY_RANK)}, got {self.min_severity!r}"
            )

        if self.rate_limit_seconds < 0:
            raise EmailConfigError(
                "rate_limit_seconds must be >= 0"
            )

        if self.timeout_seconds <= 0:
            raise EmailConfigError(
                "timeout_seconds must be > 0"
            )

        if self.max_attempts < 1:
            raise EmailConfigError(
                "max_attempts must be >= 1"
            )

    @classmethod
    def from_env(
        cls,
        env: Optional[Mapping[str, str]] = None,
    ) -> "EmailAlertConfig":
        """Build configuration from environment variables.

        Required:
            SMTP_HOST
            SMTP_PORT
            SMTP_USER
            SMTP_PASS
            ALERT_EMAIL_TO

        Optional:
            ALERT_EMAIL_FROM
            ALERT_EMAIL_MIN_SEVERITY
            ALERT_EMAIL_RATE_LIMIT_SECONDS
            SMTP_TIMEOUT_SECONDS
            SMTP_USE_SSL
            SMTP_USE_STARTTLS
        """
        env = os.environ if env is None else env

        missing = [
            key
            for key in _REQUIRED_ENV
            if not (env.get(key) or "").strip()
        ]

        if missing:
            raise EmailConfigError(
                "missing required environment variables: "
                + ", ".join(missing)
            )

        try:
            port = int(env["SMTP_PORT"])
        except ValueError as exc:
            raise EmailConfigError(
                f"SMTP_PORT must be an integer, got {env['SMTP_PORT']!r}"
            ) from exc

        recipients = tuple(
            recipient.strip()
            for recipient in env["ALERT_EMAIL_TO"].split(",")
            if recipient.strip()
        )

        use_ssl = _env_bool(
            env,
            "SMTP_USE_SSL",
            default=(port == 465),
        )

        return cls(
            smtp_host=env["SMTP_HOST"].strip(),
            smtp_port=port,
            smtp_user=env["SMTP_USER"],
            smtp_password=env["SMTP_PASS"],
            recipients=recipients,
            sender=(
                env.get("ALERT_EMAIL_FROM")
                or "siem-alerts@siem.local"
            ).strip(),
            min_severity=(
                env.get("ALERT_EMAIL_MIN_SEVERITY")
                or "HIGH"
            ).strip().upper(),
            rate_limit_seconds=_env_number(
                env,
                "ALERT_EMAIL_RATE_LIMIT_SECONDS",
                15 * 60,
                int,
            ),
            timeout_seconds=_env_number(
                env,
                "SMTP_TIMEOUT_SECONDS",
                10.0,
                float,
            ),
            use_ssl=use_ssl,
            use_starttls=_env_bool(
                env,
                "SMTP_USE_STARTTLS",
                default=True,
            ),
        )


class SourceIpRateLimiter:
    """Allow at most one notification per source IP per time window.

    The limiter is thread-safe and atomically reserves a notification slot.
    ``release()`` frees a reserved slot when sending fails so that a failed
    email does not suppress the next notification attempt.
    """

    def __init__(
        self,
        window_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._window = window_seconds
        self._clock = clock
        self._last_sent: dict[str, float] = {}
        self._lock = threading.Lock()
        self._last_prune = clock()

    def try_acquire(self, key: str) -> bool:
        """Reserve a notification slot for a source IP."""
        now = self._clock()

        with self._lock:
            self._prune(now)

            last = self._last_sent.get(key)

            if last is not None and (now - last) < self._window:
                return False

            self._last_sent[key] = now
            return True

    def release(self, key: str) -> None:
        """Release a previously reserved notification slot."""
        with self._lock:
            self._last_sent.pop(key, None)

    def _prune(self, now: float) -> None:
        """Remove expired entries to keep memory bounded."""
        if (now - self._last_prune) < self._window:
            return

        expired = [
            key
            for key, timestamp in self._last_sent.items()
            if (now - timestamp) >= self._window
        ]

        for key in expired:
            del self._last_sent[key]

        self._last_prune = now


def _clean_header(
    value: str,
    max_len: int = 200,
) -> str:
    """Strip CR/LF characters and cap header length."""
    return re.sub(r"[\r\n]+", " ", value).strip()[:max_len]


def _format_timestamp(value: Any) -> str:
    """Format timestamps consistently in UTC."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        return value.astimezone(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )

    return str(value)


class EmailAlerter:
    """Send email notifications for alerts at or above the threshold."""

    def __init__(
        self,
        config: EmailAlertConfig,
        *,
        rate_limiter: Optional[SourceIpRateLimiter] = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._config = config

        self._limiter = (
            rate_limiter
            or SourceIpRateLimiter(
                config.rate_limit_seconds,
                clock,
            )
        )

        self._sleep = sleep

        normalized_threshold = _normalize_severity(
            config.min_severity
        )

        if normalized_threshold is None:
            raise EmailConfigError(
                f"invalid minimum severity: {config.min_severity!r}"
            )

        self._threshold = SEVERITY_RANK[normalized_threshold]

    @classmethod
    def from_env(
        cls,
        env: Optional[Mapping[str, str]] = None,
        **kwargs: Any,
    ) -> "EmailAlerter":
        """Create an EmailAlerter from environment configuration."""
        return cls(
            EmailAlertConfig.from_env(env),
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def should_notify(self, alert: AlertLike) -> bool:
        """Return True when an alert meets the configured threshold."""
        severity = _normalize_severity(alert.severity)

        return (
            severity is not None
            and SEVERITY_RANK[severity] >= self._threshold
        )

    def notify(self, alert: AlertLike) -> NotificationResult:
        """Send an email for an alert if it qualifies.

        This method never raises. Email alerting is intentionally treated as
        a side effect so an SMTP failure cannot break alert persistence.
        """
        source_ip: Optional[str] = None
        slot_reserved = False

        try:
            severity = _normalize_severity(alert.severity)

            if severity is None:
                logger.warning(
                    "Email skipped: unrecognised severity %r",
                    alert.severity,
                )
                return NotificationResult.BELOW_THRESHOLD

            if SEVERITY_RANK[severity] < self._threshold:
                return NotificationResult.BELOW_THRESHOLD

            source_ip = str(alert.source_ip)

            if not self._limiter.try_acquire(source_ip):
                logger.info(
                    "Email rate-limited for source_ip=%s rule=%s "
                    "(alert is still stored)",
                    source_ip,
                    alert.rule_name,
                )
                return NotificationResult.RATE_LIMITED

            slot_reserved = True

            message = self.build_message(alert)

            self._send_with_retry(message)

            logger.info(
                "Alert email sent: severity=%s rule=%s source_ip=%s",
                severity,
                alert.rule_name,
                source_ip,
            )

            return NotificationResult.SENT

        except Exception:  # noqa: BLE001
            if slot_reserved and source_ip is not None:
                self._limiter.release(source_ip)

            logger.exception("Failed to send alert email")

            return NotificationResult.FAILED

    def build_message(
        self,
        alert: AlertLike,
    ) -> EmailMessage:
        """Build the email message for an alert."""
        severity = (
            _normalize_severity(alert.severity)
            or str(alert.severity).upper()
        )

        rows = self._rows(alert, severity)

        subject = _clean_header(
            f"[{severity}] SIEM Alert: "
            f"{alert.rule_name} from {alert.source_ip}"
        )

        message = EmailMessage()

        message["Subject"] = subject
        message["From"] = self._config.sender
        message["To"] = ", ".join(self._config.recipients)

        message.set_content(
            self._render_text(rows)
        )

        message.add_alternative(
            self._render_html(rows, severity),
            subtype="html",
        )

        return message

    # ------------------------------------------------------------------
    # Message formatting
    # ------------------------------------------------------------------

    @staticmethod
    def _rows(
        alert: AlertLike,
        severity: str,
    ) -> list[tuple[str, str]]:
        """Build alert fields for email rendering."""
        rows = [
            ("Severity", severity),
            ("Rule", str(alert.rule_name)),
            ("Source IP", str(alert.source_ip)),
            ("Triggered at", _format_timestamp(alert.triggered_at)),
            ("Event count", str(alert.event_count)),
        ]

        optional_fields = (
            ("Window start", "window_start"),
            ("Window end", "window_end"),
            ("Status", "status"),
            ("Alert ID", "id"),
        )

        for label, attribute in optional_fields:
            value = getattr(alert, attribute, None)

            if value is not None:
                rows.append(
                    (
                        label,
                        _format_timestamp(value),
                    )
                )

        return rows

    @staticmethod
    def _render_text(
        rows: list[tuple[str, str]],
    ) -> str:
        """Render a plain-text version of the alert email."""
        width = max(
            len(label)
            for label, _ in rows
        )

        lines = [
            "SIEM security alert",
            "",
        ]

        lines += [
            f"{label.ljust(width)} : {value}"
            for label, value in rows
        ]

        return "\n".join(lines) + "\n"

    @staticmethod
    def _render_html(
        rows: list[tuple[str, str]],
        severity: str,
    ) -> str:
        """Render an HTML version of the alert email."""
        color = _SEVERITY_COLORS.get(
            severity,
            "#455a64",
        )

        body_rows = "".join(
            "<tr>"
            '<td style="padding:6px 12px;'
            'font-weight:bold;'
            'border-bottom:1px solid #eee;">'
            f"{html.escape(label)}</td>"
            '<td style="padding:6px 12px;'
            'border-bottom:1px solid #eee;">'
            f"{html.escape(value)}</td>"
            "</tr>"
            for label, value in rows
        )

        return (
            '<html><body '
            'style="font-family:Arial,Helvetica,sans-serif;'
            'color:#222;">'
            f'<div style="background:{color};'
            'color:#fff;padding:12px 16px;'
            'font-size:18px;">'
            f"{html.escape(severity)} severity alert"
            "</div>"
            f'<table style="border-collapse:collapse;'
            f'margin-top:8px;">{body_rows}</table>'
            '<p style="color:#888;font-size:12px;">'
            "Sent by SIEM Platform alerting."
            "</p>"
            "</body></html>"
        )

    # ------------------------------------------------------------------
    # SMTP transport
    # ------------------------------------------------------------------

    def _send_with_retry(
        self,
        message: EmailMessage,
    ) -> None:
        """Send an email with limited retry handling."""
        last_error: Optional[BaseException] = None

        for attempt in range(
            1,
            self._config.max_attempts + 1,
        ):
            try:
                self._send_once(message)
                return

            except _PERMANENT_SMTP_ERRORS:
                raise

            except _TRANSIENT_ERRORS as exc:
                last_error = exc

                logger.warning(
                    "SMTP attempt %d/%d failed: %s",
                    attempt,
                    self._config.max_attempts,
                    exc,
                )

                if attempt < self._config.max_attempts:
                    self._sleep(
                        self._config.retry_delay_seconds
                    )

        assert last_error is not None
        raise last_error

    def _send_once(
        self,
        message: EmailMessage,
    ) -> None:
        """Send one email through the configured SMTP server."""
        config = self._config

        factory = (
            smtplib.SMTP_SSL
            if config.use_ssl
            else smtplib.SMTP
        )

        kwargs: dict[str, Any] = {
            "timeout": config.timeout_seconds,
        }

        if config.use_ssl:
            kwargs["context"] = ssl.create_default_context()

        with factory(
            config.smtp_host,
            config.smtp_port,
            **kwargs,
        ) as server:

            if not config.use_ssl and config.use_starttls:
                server.ehlo()

                server.starttls(
                    context=ssl.create_default_context()
                )

                server.ehlo()

            server.login(
                config.smtp_user,
                config.smtp_password,
            )

            server.send_message(
                message,
                from_addr=config.sender,
                to_addrs=list(config.recipients),
            )