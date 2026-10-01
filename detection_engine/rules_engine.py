"""
detection_engine/rules_engine.py

RulesEngine orchestrates every detection rule.

    normalized event stream
            |
            v
    +-----------------+      rules table (enabled=true)
    |   RulesEngine   |<---------------------------------- PostgreSQL
    +-----------------+
      | rule A.evaluate()  \
      | rule B.evaluate()   >-- normalize -> unionByName
      | rule C.evaluate()  /
            |
            v
      unified `alerts` stream
            |
            v
       foreachBatch
            |
            v
      AlertEvent validation
            |
            v
       AlertPublisher
            |
            v
       Kafka `alerts`

The engine is the single point where alerts leave Spark.

Rules themselves are pure Spark transformations. They must not write
directly to Kafka or PostgreSQL.

Reloading
---------
`reload_rules()` re-queries the `rules` table and rebuilds the active
rule set without restarting the SparkSession.

If the engine owns a running Structured Streaming query, a changed rule
set causes that query to be stopped and restarted using the same
checkpoint. Stateful rule changes may require a fresh checkpoint because
Spark streaming state is tied to the logical query plan.
"""

from __future__ import annotations

import importlib
import logging
import os
import pkgutil
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import reduce
from typing import Any, Callable, Mapping, Protocol, Sequence

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from consumers.schemas import AlertEvent
from detection_engine.base_rule import (
    ALERT_COLUMNS,
    ALERT_SPARK_TYPES,
    REQUIRED_ALERT_COLUMNS,
    BaseRule,
)
from detection_engine.publishers.alert_publisher import AlertPublisher
from detection_engine.rules.base import RuleConfig

logger = logging.getLogger(__name__)


DEFAULT_RULES_PACKAGE = "detection_engine.rules"
DEFAULT_QUERY_NAME = "siem-rules-engine"
DEFAULT_ALERTS_TOPIC = "alerts"


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


class RulesEngineError(RuntimeError):
    """Base class for RulesEngine errors."""


class RuleLoadError(RulesEngineError):
    """Raised when rules cannot be loaded from the database or built."""


class RuleEvaluationError(RulesEngineError):
    """Raised when a rule fails evaluation in strict mode."""


# --------------------------------------------------------------------------
# Small types
# --------------------------------------------------------------------------


class RulesSource(Protocol):
    """
    Interface required from the rules repository.

    The existing RulesRepository satisfies this contract.
    """

    def list_enabled(self) -> Sequence[Any]:
        ...


RuleFactory = Callable[
    [type[BaseRule], RuleConfig],
    BaseRule,
]


@dataclass(frozen=True)
class LoadedRule:
    """An instantiated detection rule and its configuration."""

    rule: BaseRule
    config: RuleConfig


@dataclass(frozen=True)
class ReloadResult:
    """Result of loading or reloading detection rules."""

    loaded: tuple[str, ...]
    added: tuple[str, ...]
    removed: tuple[str, ...]
    updated: tuple[str, ...]
    skipped_unregistered: tuple[str, ...]
    failed: tuple[str, ...]

    @property
    def changed(self) -> bool:
        """Whether the active rule set changed."""

        return bool(
            self.added
            or self.removed
            or self.updated
        )


@dataclass(frozen=True)
class _QuerySpec:
    """Specification required to recreate the streaming query."""

    stream: DataFrame
    checkpoint_location: str
    trigger_interval: str | None
    query_name: str


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def config_from_row(row: Any) -> RuleConfig:
    """
    Build RuleConfig from a `rules` table row.

    The current rules table does not contain a separate slide interval,
    so slide_minutes follows window_minutes, matching the existing
    RulesRepository behavior.
    """

    return RuleConfig(
        rule_name=row.rule_name,
        threshold=row.threshold,
        window_minutes=row.window_minutes,
        slide_minutes=row.window_minutes,
        enabled=bool(row.enabled),
        off_hours_start=getattr(
            row,
            "off_hours_start",
            None,
        ),
        off_hours_end=getattr(
            row,
            "off_hours_end",
            None,
        ),
    )


def discover_rules(
    package: str = DEFAULT_RULES_PACKAGE,
    *,
    strict: bool = False,
) -> list[str]:
    """
    Import every module below `package`.

    Importing the modules causes BaseRule subclasses to register
    themselves through BaseRule.__init_subclass__().

    Returns:
        Names of modules that failed to import.

    In non-strict mode an import failure is logged and discovery
    continues. In strict mode the original exception is raised.
    """

    root = importlib.import_module(package)

    if not hasattr(root, "__path__"):
        raise RuleLoadError(
            f"Rule package {package!r} is not a package"
        )

    failures: list[str] = []

    def _on_walk_error(name: str) -> None:
        failures.append(name)

        logger.error(
            "Failed to scan rule package %s",
            name,
            exc_info=True,
        )

    for module_info in pkgutil.walk_packages(
        root.__path__,
        prefix=f"{package}.",
        onerror=_on_walk_error,
    ):
        try:
            importlib.import_module(
                module_info.name,
            )
        except Exception:
            failures.append(
                module_info.name,
            )

            if strict:
                raise

            logger.exception(
                "Failed to import rule module %s; rules defined in "
                "that module will not be available",
                module_info.name,
            )

    if failures:
        logger.warning(
            "Rule discovery completed with %d module failure(s)",
            len(failures),
        )

    return failures


def _as_utc(value: float | int | None) -> datetime:
    """
    Convert epoch seconds to an aware UTC datetime.
    """

    if value is None:
        raise ValueError(
            "triggered_at cannot be None"
        )

    return datetime.fromtimestamp(
        float(value),
        tz=timezone.utc,
    )


# --------------------------------------------------------------------------
# RulesEngine
# --------------------------------------------------------------------------


class RulesEngine:
    """
    Load enabled rules, evaluate them against a Spark stream, merge
    their outputs, validate alerts, and publish them downstream.

    The engine is responsible for:

        PostgreSQL rules
              ↓
        active rule set
              ↓
        rule evaluation
              ↓
        alert normalization
              ↓
        alert validation
              ↓
        Kafka publication

    Individual rules are responsible only for Spark transformations.
    """

    def __init__(
        self,
        rules_repository: RulesSource,
        *,
        alert_publisher: AlertPublisher | None = None,
        rule_registry: Mapping[
            str,
            type[BaseRule],
        ] | None = None,
        rule_factory: RuleFactory | None = None,
        discover_package: str | None = DEFAULT_RULES_PACKAGE,
        strict: bool = False,
        load_on_init: bool = True,
    ) -> None:
        """
        Args:
            rules_repository:
                Source of enabled rules from PostgreSQL.

            alert_publisher:
                Publisher used by process_batch/start_query.

            rule_registry:
                Optional explicit rule mapping. If omitted, the
                BaseRule self-registration registry is used.

            rule_factory:
                Factory receiving (rule_class, RuleConfig).
                Defaults to rule_class(config).

            discover_package:
                Package containing detection rules.

            strict:
                If True, rule loading/evaluation errors raise.
                If False, broken individual rules are skipped while
                healthy rules continue running.

            load_on_init:
                Load enabled rules immediately during startup.
        """

        self._repository = rules_repository
        self._publisher = alert_publisher
        self._rule_registry = rule_registry

        self._rule_factory: RuleFactory = (
            rule_factory
            or (
                lambda rule_cls, config: rule_cls(config)
            )
        )

        self._strict = strict

        self._lock = threading.RLock()

        self._active: dict[
            str,
            LoadedRule,
        ] = {}

        self._version = 0

        self._query: Any = None
        self._query_spec: _QuerySpec | None = None

        self._stats: dict[str, int] = {
            "batches": 0,
            "alerts_published": 0,
            "alerts_invalid": 0,
        }

        # Import rule modules so BaseRule subclasses register.
        if discover_package is not None:
            discover_rules(
                discover_package,
                strict=strict,
            )

        # Acceptance criterion:
        # rules are loaded from PostgreSQL on startup.
        if load_on_init:
            self._apply(initial=True)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def active_rule_names(self) -> tuple[str, ...]:
        """Return names of currently active rules."""

        with self._lock:
            return tuple(
                sorted(self._active)
            )

    @property
    def version(self) -> int:
        """
        Return the active rule-set version.

        Incremented whenever the active configuration changes.
        """

        with self._lock:
            return self._version

    @property
    def stats(self) -> dict[str, int]:
        """Return a snapshot of engine statistics."""

        with self._lock:
            return dict(self._stats)

    @property
    def is_running(self) -> bool:
        """Return whether the engine owns an active Spark query."""

        query = self._query

        return (
            query is not None
            and bool(query.isActive)
        )

    # ------------------------------------------------------------------
    # Loading / reloading
    # ------------------------------------------------------------------

    def reload_rules(
        self,
        *,
        restart_query: bool = True,
    ) -> ReloadResult:
        """
        Re-query PostgreSQL and rebuild the active rule set.

        Behavior:

        - Disabled rules stop being applied.
        - Newly enabled rules become active.
        - Changed rule configuration is reloaded.
        - The SparkSession is not restarted.

        If the database cannot be queried, the existing active rule set
        remains unchanged and RuleLoadError is raised.

        If a running engine query is owned by this object and the active
        rule set changed, the query is restarted.

        Stateful rules may require a new checkpoint when the logical
        streaming plan changes.
        """

        with self._lock:
            result = self._apply(
                initial=False,
            )

            if (
                result.changed
                and restart_query
                and self._query_spec is not None
            ):
                self._restart_query()

            return result

    def _apply(
        self,
        *,
        initial: bool,
    ) -> ReloadResult:
        """
        Build a new active rule set and atomically replace the old one.
        """

        (
            active,
            unregistered,
            failed,
        ) = self._build_active_rules()

        with self._lock:
            previous = self._active

            previous_names = set(
                previous
            )

            active_names = set(
                active
            )

            added = sorted(
                active_names - previous_names
            )

            removed = sorted(
                previous_names - active_names
            )

            updated = sorted(
                name
                for name in (
                    active_names & previous_names
                )
                if (
                    active[name].config
                    != previous[name].config
                    or type(active[name].rule)
                    is not type(previous[name].rule)
                )
            )

            result = ReloadResult(
                loaded=tuple(
                    sorted(active)
                ),
                added=tuple(added),
                removed=tuple(removed),
                updated=tuple(updated),
                skipped_unregistered=tuple(
                    sorted(unregistered)
                ),
                failed=tuple(
                    sorted(failed)
                ),
            )

            self._active = active

            if result.changed:
                self._version += 1

        self._log_result(
            result,
            active,
            initial=initial,
        )

        return result

    def _build_active_rules(
        self,
    ) -> tuple[
        dict[str, LoadedRule],
        list[str],
        list[str],
    ]:
        """
        Query enabled rules and instantiate their implementations.
        """

        try:
            rows = list(
                self._repository.list_enabled()
            )
        except Exception as exc:
            raise RuleLoadError(
                "Failed to query enabled rules from "
                "the rules table"
            ) from exc

        registry = (
            dict(self._rule_registry)
            if self._rule_registry is not None
            else BaseRule.registered_rules()
        )

        active: dict[
            str,
            LoadedRule,
        ] = {}

        unregistered: list[str] = []
        failed: list[str] = []

        for row in sorted(
            rows,
            key=lambda item: item.rule_name,
        ):
            name = row.rule_name

            # Do not rely exclusively on the repository filtering.
            if not bool(
                getattr(
                    row,
                    "enabled",
                    True,
                )
            ):
                continue

            rule_cls = registry.get(
                name
            )

            if rule_cls is None:
                message = (
                    f"Rule {name!r} is enabled in the rules "
                    "table but no BaseRule subclass with that "
                    "rule_name is registered"
                )

                if self._strict:
                    raise RuleLoadError(
                        message
                    )

                logger.warning(
                    "%s; skipping it",
                    message,
                )

                unregistered.append(
                    name
                )

                continue

            try:
                config = config_from_row(
                    row
                )

                rule = self._rule_factory(
                    rule_cls,
                    config,
                )

                if not isinstance(
                    rule,
                    BaseRule,
                ):
                    raise TypeError(
                        f"Rule factory returned "
                        f"{type(rule).__name__}, expected "
                        "a BaseRule"
                    )

                if rule.rule_name != name:
                    raise ValueError(
                        f"Rule implementation name mismatch: "
                        f"DB has {name!r}, implementation has "
                        f"{rule.rule_name!r}"
                    )

            except Exception as exc:
                if self._strict:
                    raise RuleLoadError(
                        f"Failed to build rule {name!r}"
                    ) from exc

                logger.exception(
                    "Failed to build rule %r; skipping it",
                    name,
                )

                failed.append(
                    name
                )

                continue

            active[name] = LoadedRule(
                rule=rule,
                config=config,
            )

        return (
            active,
            unregistered,
            failed,
        )

    def _log_result(
        self,
        result: ReloadResult,
        active: Mapping[
            str,
            LoadedRule,
        ],
        *,
        initial: bool,
    ) -> None:
        """
        Log startup/reload information.

        This directly satisfies the requirement that the engine logs
        which rules are loaded.
        """

        if initial:
            if result.loaded:
                logger.info(
                    "Rules engine loaded %d detection rule(s): %s",
                    len(result.loaded),
                    ", ".join(result.loaded),
                )
            else:
                logger.warning(
                    "Rules engine loaded 0 detection rules; "
                    "the alert stream will be empty until rules "
                    "are enabled and reload_rules() is called"
                )

        elif result.changed:
            logger.info(
                "Rules reloaded: added=%s removed=%s "
                "updated=%s active=%s",
                list(result.added),
                list(result.removed),
                list(result.updated),
                list(result.loaded),
            )

        else:
            logger.info(
                "Rules reloaded: no changes (%d active)",
                len(result.loaded),
            )

        for name in result.loaded:
            config = active[name].config

            logger.info(
                "  rule=%s class=%s threshold=%s "
                "window_minutes=%s enabled=%s",
                name,
                type(
                    active[name].rule
                ).__name__,
                config.threshold,
                config.window_minutes,
                config.enabled,
            )

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        stream: DataFrame,
    ) -> DataFrame:
        """
        Apply all currently active rules to a Spark DataFrame.

        Each rule receives the same normalized event stream.

        Rule outputs are normalized to the unified alert schema and then
        merged using unionByName.

        The active rule set is snapshotted at the start of evaluation,
        so a concurrent reload cannot partially change one evaluation.
        """

        with self._lock:
            snapshot = tuple(
                self._active.values()
            )

        outputs: list[DataFrame] = []

        for loaded in snapshot:
            alerts = self._evaluate_rule(
                loaded,
                stream,
            )

            if alerts is not None:
                outputs.append(
                    alerts
                )

        if not outputs:
            logger.warning(
                "No active rule produced an alert stream; "
                "returning an empty alert stream"
            )

            return self._empty_alerts(
                stream
            )

        return reduce(
            lambda left, right: left.unionByName(
                right
            ),
            outputs,
        )

    def _evaluate_rule(
        self,
        loaded: LoadedRule,
        stream: DataFrame,
    ) -> DataFrame | None:
        """
        Evaluate one rule and normalize its output.
        """

        rule = loaded.rule
        name = rule.rule_name

        try:
            result = rule.evaluate(
                stream
            )

            if not isinstance(
                result,
                DataFrame,
            ):
                raise TypeError(
                    f"evaluate() returned "
                    f"{type(result).__name__}, expected "
                    "a Spark DataFrame"
                )

            # A rule must preserve the streaming nature of its input.
            if result.isStreaming != stream.isStreaming:
                raise ValueError(
                    "evaluate() must preserve the streaming nature "
                    f"of the input: input isStreaming="
                    f"{stream.isStreaming}, output isStreaming="
                    f"{result.isStreaming}"
                )

            return self._normalize_alerts(
                name,
                result,
            )

        except Exception as exc:
            if self._strict:
                raise RuleEvaluationError(
                    f"Rule {name!r} failed to evaluate"
                ) from exc

            logger.exception(
                "Rule %r failed to evaluate and is excluded "
                "from this alert stream; other rules are unaffected",
                name,
            )

            return None

    @staticmethod
    def _normalize_alerts(
        rule_name: str,
        df: DataFrame,
    ) -> DataFrame:
        """
        Normalize a rule output to the canonical AlertEvent schema.

        Required fields must exist.

        Optional fields receive defaults.

        `rule_name` is always generated by the engine rather than
        trusting the rule.

        Extra columns are discarded.
        """

        present = set(
            df.columns
        )

        missing = [
            column
            for column in REQUIRED_ALERT_COLUMNS
            if column not in present
        ]

        if missing:
            raise ValueError(
                "evaluate() output is missing required "
                f"alert column(s): {missing}"
            )

        def typed(
            column: str,
        ):
            return F.col(
                column
            ).cast(
                ALERT_SPARK_TYPES[column]
            )

        def optional(
            column: str,
        ):
            if column in present:
                return typed(
                    column
                )

            return F.lit(
                None
            ).cast(
                ALERT_SPARK_TYPES[column]
            )

        source_ip = typed(
            "source_ip"
        )

        severity = F.upper(
            typed("severity")
        )

        description = typed(
            "description"
        )

        username = optional(
            "username"
        )

        # Optional source event IDs.
        if "source_event_ids" in present:
            event_ids = F.coalesce(
                typed(
                    "source_event_ids"
                ),
                F.array().cast(
                    "array<string>"
                ),
            )
        else:
            event_ids = F.array().cast(
                "array<string>"
            )

        # Optional triggered timestamp.
        if "triggered_at" in present:
            triggered_at = F.coalesce(
                typed(
                    "triggered_at"
                ),
                F.current_timestamp(),
            )
        else:
            triggered_at = F.current_timestamp()

        # Optional status.
        if "status" in present:
            status = F.coalesce(
                typed("status"),
                F.lit("OPEN"),
            )
        else:
            status = F.lit(
                "OPEN"
            )

        # --------------------------------------------------------------
        # Deterministic alert ID
        #
        # Do NOT include description because description is human-readable
        # and may change without changing the underlying detection event.
        #
        # The identity is based on:
        #   rule + source IP + source event IDs + username
        #
        # This allows an at-least-once replay of the same detection
        # events to produce the same generated ID.
        # --------------------------------------------------------------

        digest = F.md5(
            F.concat_ws(
                "|",
                F.lit(rule_name),
                F.coalesce(
                    source_ip,
                    F.lit(""),
                ),
                F.array_join(
                    F.sort_array(
                        event_ids
                    ),
                    ",",
                ),
                F.coalesce(
                    username,
                    F.lit(""),
                ),
            )
        )

        generated_id = F.concat_ws(
            "-",
            F.substring(
                digest,
                1,
                8,
            ),
            F.substring(
                digest,
                9,
                4,
            ),
            F.substring(
                digest,
                13,
                4,
            ),
            F.substring(
                digest,
                17,
                4,
            ),
            F.substring(
                digest,
                21,
                12,
            ),
        )

        if "alert_id" in present:
            alert_id = F.coalesce(
                typed("alert_id"),
                generated_id,
            )
        else:
            alert_id = generated_id

        # --------------------------------------------------------------
        # Canonical output
        # --------------------------------------------------------------

        columns = {
            "alert_id": alert_id,

            "triggered_at": triggered_at,

            # IMPORTANT:
            # The engine owns rule_name.
            "rule_name": F.lit(
                rule_name
            ),

            "severity": severity,

            "description": description,

            "source_ip": source_ip,

            "source_event_ids": event_ids,

            "status": status,

            "username": username,

            "login_1_country": optional(
                "login_1_country"
            ),

            "login_2_country": optional(
                "login_2_country"
            ),

            "time_delta_minutes": optional(
                "time_delta_minutes"
            ),

            "distance_km": optional(
                "distance_km"
            ),
        }

        return df.select(
            *[
                columns[column].alias(
                    column
                )
                for column in ALERT_COLUMNS
            ]
        )

    @staticmethod
    def _empty_alerts(
        stream: DataFrame,
    ) -> DataFrame:
        """
        Return an empty DataFrame with the canonical alert schema.

        The returned DataFrame preserves the streaming nature of the
        input.
        """

        return stream.select(
            *[
                F.lit(None)
                .cast(
                    ALERT_SPARK_TYPES[column]
                )
                .alias(column)
                for column in ALERT_COLUMNS
            ]
        ).where(
            F.lit(False)
        )

    # ------------------------------------------------------------------
    # Kafka sink
    # ------------------------------------------------------------------

    def process_batch(
        self,
        batch_df: DataFrame,
        batch_id: int,
    ) -> None:
        """
        Validate and publish one alert micro-batch.

        This is the single downstream point where alerts leave Spark.

        AlertEvent validation prevents malformed alerts from being
        published.

        Publisher failures propagate so Structured Streaming can retry
        the batch.

        The deterministic alert_id makes replayed batches
        de-duplicatable downstream.
        """

        if self._publisher is None:
            raise RulesEngineError(
                "An alert_publisher is required "
                "to publish alerts"
            )

        # foreachBatch receives a finite DataFrame, so collecting the
        # alert batch here is intentional: AlertEvent validation and the
        # existing AlertPublisher operate in Python.
        #
        # Triggered timestamp is converted to epoch seconds first so
        # Python timezone handling is independent of the local machine.
        rows = (
            batch_df
            .withColumn(
                "triggered_at",
                F.col(
                    "triggered_at"
                ).cast("double"),
            )
            .collect()
        )

        published = 0
        invalid = 0

        for row in rows:
            data = row.asDict(
                recursive=True
            )

            try:
                data["triggered_at"] = _as_utc(
                    data.get(
                        "triggered_at"
                    )
                )

                payload = AlertEvent(
                    **data
                ).model_dump(
                    mode="json"
                )

            except Exception:
                invalid += 1

                logger.exception(
                    "Dropping invalid alert "
                    "rule=%s source_ip=%s batch_id=%s",
                    data.get(
                        "rule_name"
                    ),
                    data.get(
                        "source_ip"
                    ),
                    batch_id,
                )

                continue

            # Publisher exceptions intentionally propagate.
            self._publisher.publish(
                payload
            )

            published += 1

        flush = getattr(
            self._publisher,
            "flush",
            None,
        )

        if callable(flush):
            flush()

        # Stats are protected because the engine may be inspected or
        # interacted with from another thread while the query is running.
        with self._lock:
            self._stats[
                "batches"
            ] += 1

            self._stats[
                "alerts_published"
            ] += published

            self._stats[
                "alerts_invalid"
            ] += invalid

        logger.info(
            "Alert batch processed "
            "batch_id=%s published=%d invalid=%d",
            batch_id,
            published,
            invalid,
        )

    # ------------------------------------------------------------------
    # Query lifecycle
    # ------------------------------------------------------------------

    def start_query(
        self,
        stream: DataFrame,
        checkpoint_location: str,
        *,
        trigger_interval: str | None = None,
        query_name: str = DEFAULT_QUERY_NAME,
    ):
        """
        Evaluate the normalized stream and start the alert query.

        Returns:
            Spark StreamingQuery.

        Call `awaitTermination()` on the returned query.
        """

        if self._publisher is None:
            raise RulesEngineError(
                "An alert_publisher is required "
                "to start the query"
            )

        with self._lock:
            if (
                self._query is not None
                and self._query.isActive
            ):
                raise RulesEngineError(
                    "The rules engine query is already running"
                )

            spec = _QuerySpec(
                stream=stream,
                checkpoint_location=checkpoint_location,
                trigger_interval=trigger_interval,
                query_name=query_name,
            )

            self._query = self._launch(
                spec
            )

            self._query_spec = spec

            return self._query

    def stop(self) -> None:
        """Stop the engine-owned streaming query, if active."""

        with self._lock:
            query = self._query

            self._query = None
            self._query_spec = None

        if (
            query is not None
            and query.isActive
        ):
            logger.info(
                "Stopping rules engine query"
            )

            query.stop()

    def _launch(
        self,
        spec: _QuerySpec,
    ):
        """
        Create and start the Structured Streaming query.
        """

        alerts = self.evaluate(
            spec.stream
        )

        writer = (
            alerts.writeStream
            .foreachBatch(
                self.process_batch
            )
            .option(
                "checkpointLocation",
                spec.checkpoint_location,
            )
            .outputMode(
                "append"
            )
            .queryName(
                spec.query_name
            )
        )

        if spec.trigger_interval:
            writer = writer.trigger(
                processingTime=spec.trigger_interval
            )

        query = writer.start()

        logger.info(
            "Rules engine query started "
            "name=%s rules=%s checkpoint=%s",
            spec.query_name,
            list(
                self.active_rule_names
            ),
            spec.checkpoint_location,
        )

        return query

    def _restart_query(self) -> None:
        """
        Restart the engine-owned query after a rule-set change.

        Spark itself is not restarted.

        Stateful rule changes may require a fresh checkpoint.
        """

        spec = self._query_spec
        old_query = self._query

        if spec is None:
            return

        logger.info(
            "Rule set changed; restarting the "
            "rules engine query"
        )

        if (
            old_query is not None
            and old_query.isActive
        ):
            old_query.stop()

        self._query = None

        try:
            self._query = self._launch(
                spec
            )

        except Exception:
            logger.exception(
                "Failed to restart the rules engine query "
                "after reload; alerting is DOWN until "
                "start_query() succeeds"
            )

            self._query_spec = None

            raise


# --------------------------------------------------------------------------
# Production factory
# --------------------------------------------------------------------------


def build_default_engine() -> RulesEngine:
    """
    Construct the production RulesEngine.

    Uses:

        PostgreSQL -> RulesRepository
        Kafka      -> KafkaAlertPublisher
    """

    from api.database import SessionLocal

    from detection_engine.publishers.kafka_alert_publisher import (
        KafkaAlertPublisher,
    )

    from detection_engine.repositories.rules_repository import (
        RulesRepository,
    )

    bootstrap_servers = os.environ.get(
        "KAFKA_BOOTSTRAP_SERVERS"
    )

    if not bootstrap_servers:
        raise RuntimeError(
            "KAFKA_BOOTSTRAP_SERVERS environment variable "
            "is required"
        )

    return RulesEngine(
        rules_repository=RulesRepository(
            session_factory=SessionLocal,
        ),
        alert_publisher=KafkaAlertPublisher(
            bootstrap_servers=bootstrap_servers,
        ),
    )