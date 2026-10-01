"""
detection_engine/base_rule.py

The contract every detection rule implements to plug into the
`RulesEngine`.

Adding a new rule takes three steps and no engine changes:

    1. Create a class that inherits `BaseRule`, sets `rule_name`, and
       implements `evaluate()`.
    2. Make sure its module lives under `detection_engine/rules/` (the
       engine imports that package at startup so the class registers
       itself).
    3. INSERT a row into the `rules` table with the same `rule_name`.

Example::

    class SudoAbuseRule(BaseRule):
        rule_name = "sudo_abuse"

        def evaluate(self, stream: DataFrame) -> DataFrame:
            return (
                stream.where(F.col("event_type") == "sudo_attempt")
                .select(
                    "source_ip",
                    "username",
                    F.lit("MEDIUM").alias("severity"),
                    F.lit("Suspicious sudo attempt").alias("description"),
                    F.array("event_id").alias("source_event_ids"),
                )
            )

Output contract for `evaluate()`
--------------------------------
`evaluate()` is a pure transformation: normalized events in, alert rows
out. It must not persist, publish, or otherwise cause side effects --
the engine is the single place where alerts leave Spark.

Required output columns:
    source_ip, severity, description

Optional output columns (engine fills sensible defaults):
    source_event_ids (array<string>)   default: []
    triggered_at     (timestamp)       default: current_timestamp()
    status           (string)          default: 'OPEN'
    alert_id         (string)          default: deterministic UUID-shaped
                                       hash of stable alert identity
    username, login_1_country, login_2_country,
    time_delta_minutes, distance_km    default: NULL

The engine always stamps `rule_name` itself, so a rule cannot emit
alerts under another rule's name.

Extra columns are dropped.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import ClassVar

from pyspark.sql import DataFrame

from detection_engine.rules.base import RuleConfig

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Unified alert stream schema
#
# These columns mirror `consumers.schemas.AlertEvent` exactly.
# AlertEvent forbids extra fields, so the RulesEngine projects every
# rule's output onto this schema before validation/publication.
# --------------------------------------------------------------------------

ALERT_SPARK_TYPES: dict[str, str] = {
    "alert_id": "string",
    "triggered_at": "timestamp",
    "rule_name": "string",
    "severity": "string",
    "description": "string",
    "source_ip": "string",
    "source_event_ids": "array<string>",
    "status": "string",
    "username": "string",
    "login_1_country": "string",
    "login_2_country": "string",
    "time_delta_minutes": "double",
    "distance_km": "double",
}

ALERT_COLUMNS: tuple[str, ...] = tuple(ALERT_SPARK_TYPES)


# What a rule MUST return from evaluate().
REQUIRED_ALERT_COLUMNS: tuple[str, ...] = (
    "source_ip",
    "severity",
    "description",
)


class BaseRule(ABC):
    """
    Abstract base class for all detection rules.

    Subclasses that define ``rule_name`` in their class body are
    registered automatically so the RulesEngine can find them by the
    name stored in the `rules` table.

    Intermediate abstract classes can omit ``rule_name`` and will not
    be registered.

    Test doubles can opt out using ``register=False``::

        class FakeRule(BaseRule, register=False):
            ...
    """

    rule_name: ClassVar[str]

    _registry: ClassVar[dict[str, type["BaseRule"]]] = {}

    def __init_subclass__(
        cls,
        register: bool = True,
        **kwargs,
    ) -> None:
        """
        Automatically register concrete rule classes.

        Duplicate rule names are rejected so two implementations cannot
        accidentally claim the same database rule.
        """

        super().__init_subclass__(**kwargs)

        if not register:
            return

        name = cls.__dict__.get("rule_name")

        if name is None:
            # Intermediate abstract class.
            return

        if not isinstance(name, str) or not name.strip():
            raise ValueError(
                f"{cls.__module__}.{cls.__qualname__}.rule_name must be "
                "a non-empty string"
            )

        existing = BaseRule._registry.get(name)

        if existing is not None and (
            existing.__module__,
            existing.__qualname__,
        ) != (
            cls.__module__,
            cls.__qualname__,
        ):
            raise ValueError(
                f"Duplicate rule_name {name!r}: already registered by "
                f"{existing.__module__}.{existing.__qualname__}, cannot "
                f"register {cls.__module__}.{cls.__qualname__}"
            )

        # Re-importing the same class/module replaces the old class
        # reference safely.
        BaseRule._registry[name] = cls

        logger.debug(
            "Registered detection rule: name=%s class=%s.%s",
            name,
            cls.__module__,
            cls.__qualname__,
        )

    # ------------------------------------------------------------------
    # Registry helpers
    # ------------------------------------------------------------------

    @classmethod
    def registered_rules(
        cls,
    ) -> dict[str, type["BaseRule"]]:
        """
        Return a copy of the registered rule mapping.

        The returned dictionary can be safely modified by the caller
        without modifying the global registry.
        """

        return dict(BaseRule._registry)

    @classmethod
    def unregister(cls, rule_name: str) -> None:
        """
        Remove a rule from the registry.

        Primarily intended for tests.
        """

        BaseRule._registry.pop(rule_name, None)

    # ------------------------------------------------------------------
    # Instance contract
    # ------------------------------------------------------------------

    def __init__(
        self,
        config: RuleConfig,
    ) -> None:
        """
        Initialize the rule with its database-backed configuration.
        """

        if config.rule_name != self.rule_name:
            raise ValueError(
                f"Invalid rule configuration: expected "
                f"{self.rule_name!r}, got {config.rule_name!r}"
            )

        self.config = config

    @abstractmethod
    def evaluate(
        self,
        stream: DataFrame,
    ) -> DataFrame:
        """
        Transform the normalized event stream into an alert stream.

        This method MUST be side-effect free.

        Rules must not:
            - write to PostgreSQL
            - publish to Kafka
            - start a streaming query
            - call collect() on the streaming DataFrame
            - perform external side effects

        The RulesEngine owns alert normalization and publication.
        """

        raise NotImplementedError

    def __repr__(self) -> str:
        return (
            f"<{type(self).__name__} "
            f"rule_name={self.rule_name!r}>"
        )