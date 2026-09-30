"""Repository for configurable detection rules."""

from __future__ import annotations

from typing import Callable

from sqlalchemy.orm import Session

from api.models.rule import Rule
from detection_engine.rules.base import RuleConfig


class RuleNotConfiguredError(RuntimeError):
    """Raised when a requested rule has no database configuration."""


class RulesRepository:
    """Persistence layer for detection rule configuration."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def get_config(
        self,
        rule_name: str,
        *,
        default: RuleConfig | None = None,
    ) -> RuleConfig:
        """Load a rule configuration from the database.

        Args:
            rule_name: Name of the detection rule.
            default: Optional fallback configuration when no DB row exists.

        Returns:
            RuleConfig populated from the database.

        Raises:
            RuleNotConfiguredError:
                If no database configuration exists and no default was supplied.
        """
        session = self._session_factory()

        try:
            rule = (
                session.query(Rule)
                .filter(Rule.rule_name == rule_name)
                .one_or_none()
            )

            if rule is None:
                if default is not None:
                    return default

                raise RuleNotConfiguredError(
                    f"No configuration found for rule '{rule_name}'"
                )

            return RuleConfig(
                rule_name=rule.rule_name,
                threshold=rule.threshold,
                window_minutes=rule.window_minutes,
                slide_minutes=rule.window_minutes,
                enabled=rule.enabled,
                off_hours_start=rule.off_hours_start,
                off_hours_end=rule.off_hours_end,
            )

        finally:
            session.close()

    def get_rule(self, rule_name: str) -> Rule | None:
        """Return the persisted Rule model, if it exists."""
        session = self._session_factory()

        try:
            return (
                session.query(Rule)
                .filter(Rule.rule_name == rule_name)
                .one_or_none()
            )
        finally:
            session.close()

    def list_enabled(self) -> list[Rule]:
        """Return all enabled detection rules."""
        session = self._session_factory()

        try:
            return (
                session.query(Rule)
                .filter(Rule.enabled.is_(True))
                .order_by(Rule.rule_name)
                .all()
            )
        finally:
            session.close()