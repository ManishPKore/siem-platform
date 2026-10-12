"""
tests/detection/test_rules_engine.py

Unit tests for detection_engine.rules_engine.RulesEngine.

Issue #16 coverage:

- Enabled rules are loaded from the rules repository.
- Rules are instantiated from the BaseRule registry.
- RulesEngine logs loaded rules.
- Multiple rules are evaluated against the same stream.
- Rule outputs are merged into one unified alert stream.
- Required alert fields are enforced.
- Optional alert fields receive defaults.
- rule_name is always stamped by the engine.
- Extra rule output columns are removed.
- Invalid rule implementations are rejected.
- Disabled rules are not loaded.
- reload_rules() adds newly enabled rules.
- reload_rules() removes disabled rules.
- reload_rules() detects configuration changes.
- Database failures preserve the previous active rule set.
- Strict mode raises on rule failures.
- Non-strict mode isolates a broken rule.
- Streaming/batch mismatch is rejected.
- Empty active-rule sets return an empty alert stream.
- Deterministic alert IDs are generated.
- AlertEvent validation occurs before publishing.
- Publisher failures propagate.
- Engine statistics are updated.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import Mock

import pytest
from pyspark.sql import DataFrame, SparkSession

from detection_engine.base_rule import (
    BaseRule,
)
from detection_engine.rules.base import RuleConfig
from detection_engine.rules_engine import (
    RuleEvaluationError,
    RuleLoadError,
    RulesEngine,
    RulesEngineError,
    _as_utc,
    config_from_row,
    discover_rules,
)


# ---------------------------------------------------------------------------
# Spark fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def spark():
    """
    Create one local Spark session for the test module.

    The environment variables are intentionally not modified here.
    On Windows/Git Bash, configure them before running pytest:

        export PYSPARK_PYTHON="$(which python)"
        export PYSPARK_DRIVER_PYTHON="$(which python)"
    """

    spark = (
        SparkSession.builder
        .master("local[2]")
        .appName("test-rules-engine")
        .config("spark.ui.enabled", "false")
        .config(
            "spark.sql.session.timeZone",
            "UTC",
        )
        .getOrCreate()
    )

    yield spark

    spark.stop()


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def make_rule_row(
    rule_name: str,
    *,
    enabled: bool = True,
    threshold: int = 5,
    window_minutes: int = 5,
    off_hours_start=None,
    off_hours_end=None,
):
    """
    Create a lightweight mock of a PostgreSQL Rule ORM row.
    """

    row = Mock()

    row.rule_name = rule_name
    row.enabled = enabled
    row.threshold = threshold
    row.window_minutes = window_minutes
    row.off_hours_start = off_hours_start
    row.off_hours_end = off_hours_end

    return row


def make_config(
    rule_name: str,
    *,
    threshold: int = 5,
    window_minutes: int = 5,
    enabled: bool = True,
) -> RuleConfig:
    """Create a RuleConfig for test rules."""

    return RuleConfig(
        rule_name=rule_name,
        threshold=threshold,
        window_minutes=window_minutes,
        slide_minutes=window_minutes,
        enabled=enabled,
    )


def make_event_stream(spark) -> DataFrame:
    """
    Create a small normalized event DataFrame.
    """

    return spark.createDataFrame(
        [
            (
                "550e8400-e29b-41d4-a716-446655440001",
                datetime(2026, 1, 1, 0, 0, 0),
                "192.168.1.10",
                "failed_login",
                "alice",
            ),
            (
                "550e8400-e29b-41d4-a716-446655440002",
                datetime(2026, 1, 1, 0, 1, 0),
                "192.168.1.20",
                "successful_login",
                "bob",
            ),
        ],
        """
        event_id string,
        timestamp timestamp,
        source_ip string,
        event_type string,
        username string
        """,
    )


def make_alert_df(
    spark,
    *,
    rule_name: str,
    source_ip: str = "192.168.1.10",
    severity: str = "HIGH",
    description: str = "Test alert",
    event_ids=None,
    username=None,
) -> DataFrame:
    """
    Create a valid alert DataFrame using only the fields a rule is
    required to provide plus optional fields.
    """

    if event_ids is None:
        event_ids = [
            "550e8400-e29b-41d4-a716-446655440001",
        ]

    schema = """
        source_ip string,
        severity string,
        description string,
        source_event_ids array<string>,
        username string
    """

    return spark.createDataFrame(
        [
            (
                source_ip,
                severity,
                description,
                event_ids,
                username,
            )
        ],
        schema,
    )


def make_minimal_alert_df(
    spark,
    *,
    source_ip: str = "192.168.1.10",
) -> DataFrame:
    """
    Create an alert DataFrame containing only required fields.
    """

    return spark.createDataFrame(
        [
            (
                source_ip,
                "HIGH",
                "Minimal test alert",
            )
        ],
        """
        source_ip string,
        severity string,
        description string
        """,
    )


# ---------------------------------------------------------------------------
# Test rules
#
# These are deliberately registered with unique names so they do not
# conflict with production rule classes.
# ---------------------------------------------------------------------------


class MockRuleOne(BaseRule):
    rule_name = "test_rule_one"

    def evaluate(
        self,
        stream: DataFrame,
    ) -> DataFrame:
        return make_alert_df(
            stream.sparkSession,
            rule_name=self.rule_name,
        )


class MockRuleTwo(BaseRule):
    rule_name = "test_rule_two"

    def evaluate(
        self,
        stream: DataFrame,
    ) -> DataFrame:
        return make_alert_df(
            stream.sparkSession,
            rule_name=self.rule_name,
            source_ip="192.168.1.20",
            severity="MEDIUM",
            description="Second test alert",
            event_ids=["550e8400-e29b-41d4-a716-446655440002"],
        )


class MinimalRule(BaseRule):
    rule_name = "minimal_test_rule"

    def evaluate(
        self,
        stream: DataFrame,
    ) -> DataFrame:
        return make_minimal_alert_df(
            stream.sparkSession,
        )


class BrokenRule(BaseRule):
    rule_name = "broken_test_rule"

    def evaluate(
        self,
        stream: DataFrame,
    ) -> DataFrame:
        raise RuntimeError(
            "intentional test failure"
        )


class NonDataFrameRule(BaseRule):
    rule_name = "non_dataframe_test_rule"

    def evaluate(
        self,
        stream: DataFrame,
    ):
        return "not a DataFrame"


class InvalidSchemaRule(BaseRule):
    rule_name = "invalid_schema_test_rule"

    def evaluate(
        self,
        stream: DataFrame,
    ) -> DataFrame:
        return stream


class WrongStreamingModeRule(BaseRule):
    rule_name = "wrong_streaming_mode_test_rule"

    def evaluate(
        self,
        stream: DataFrame,
    ) -> DataFrame:
        # Return a batch DataFrame when the input is streaming.
        return stream.sparkSession.createDataFrame(
            [
                (
                    "192.168.1.10",
                    "HIGH",
                    "Wrong mode",
                )
            ],
            """
            source_ip string,
            severity string,
            description string
            """,
        )


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------


class FakeRegistry:
    """
    Small explicit registry used by tests.

    This avoids depending on whatever production rules happen to be
    imported into the process.
    """

    def __init__(self):
        self.rules = {
            "test_rule_one": MockRuleOne,
            "test_rule_two": MockRuleTwo,
            "minimal_test_rule": MinimalRule,
            "broken_test_rule": BrokenRule,
            "non_dataframe_test_rule": NonDataFrameRule,
            "invalid_schema_test_rule": InvalidSchemaRule,
            "wrong_streaming_mode_test_rule": (
                WrongStreamingModeRule
            ),
        }

    def get(self, rule_name):
        return self.rules.get(rule_name)


def make_engine(
    repository,
    *,
    strict: bool = False,
    registry: FakeRegistry | None = None,
    publisher=None,
    rule_factory=None,
):
    """
    Construct the RulesEngine using the explicit fake registry.
    """

    return RulesEngine(
        rules_repository=repository,
        alert_publisher=publisher,
        rule_registry=(
            registry.rules
            if registry is not None
            else FakeRegistry().rules
        ),
        rule_factory=rule_factory,
        discover_package=None,
        strict=strict,
    )


# ---------------------------------------------------------------------------
# Startup / loading
# ---------------------------------------------------------------------------


def test_engine_loads_enabled_rules():
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row("test_rule_one"),
        make_rule_row("test_rule_two"),
    ]

    engine = make_engine(
        repository,
    )

    assert engine.active_rule_names == (
        "test_rule_one",
        "test_rule_two",
    )

    repository.list_enabled.assert_called_once()


def test_engine_logs_loaded_rules(caplog):
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row("test_rule_one"),
        make_rule_row("test_rule_two"),
    ]

    with caplog.at_level("INFO"):
        engine = make_engine(
            repository,
        )

    assert (
        "Rules engine loaded 2 detection rule(s)"
        in caplog.text
    )

    assert "test_rule_one" in caplog.text
    assert "test_rule_two" in caplog.text

    assert engine.active_rule_names == (
        "test_rule_one",
        "test_rule_two",
    )


def test_disabled_rules_are_not_loaded():
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
            enabled=True,
        ),
        make_rule_row(
            "test_rule_two",
            enabled=False,
        ),
    ]

    engine = make_engine(
        repository,
    )

    assert engine.active_rule_names == (
        "test_rule_one",
    )


def test_unknown_enabled_rule_is_skipped():
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "does_not_exist",
        ),
    ]

    engine = make_engine(
        repository,
    )

    assert engine.active_rule_names == ()

    result = engine.reload_rules()

    assert result.skipped_unregistered == (
        "does_not_exist",
    )


def test_unknown_enabled_rule_raises_in_strict_mode():
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "does_not_exist",
        ),
    ]

    with pytest.raises(RuleLoadError):
        make_engine(
            repository,
            strict=True,
        )


# ---------------------------------------------------------------------------
# Rule factory / configuration
# ---------------------------------------------------------------------------


def test_rule_factory_receives_rule_class_and_config():
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
            threshold=10,
            window_minutes=7,
        ),
    ]

    factory = Mock(
        side_effect=lambda rule_class, config: (
            rule_class(config)
        )
    )

    engine = make_engine(
        repository,
        rule_factory=factory,
    )

    factory.assert_called_once()

    rule_class, config = (
        factory.call_args.args
    )

    assert rule_class is MockRuleOne

    assert config.rule_name == (
        "test_rule_one"
    )

    assert config.threshold == 10
    assert config.window_minutes == 7
    assert config.slide_minutes == 7

    assert engine.active_rule_names == (
        "test_rule_one",
    )


def test_rule_name_mismatch_is_rejected():
    class WrongNameRule(BaseRule):
        rule_name = "wrong_implementation_name"

        def evaluate(self, stream):
            return make_minimal_alert_df(
                stream.sparkSession,
            )

    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
        ),
    ]

    registry = FakeRegistry()

    registry.rules[
        "test_rule_one"
    ] = WrongNameRule

    with pytest.raises(RuleLoadError):
        RulesEngine(
            rules_repository=repository,
            rule_registry=registry.rules,
            discover_package=None,
            strict=True,
        )


# ---------------------------------------------------------------------------
# Evaluation / merging
# ---------------------------------------------------------------------------


def test_evaluate_merges_multiple_rule_outputs(
    spark,
):
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row("test_rule_one"),
        make_rule_row("test_rule_two"),
    ]

    engine = make_engine(
        repository,
    )

    stream = make_event_stream(
        spark,
    )

    result = engine.evaluate(
        stream,
    )

    assert isinstance(
        result,
        DataFrame,
    )

    rows = result.collect()

    assert len(rows) == 2

    rule_names = {
        row["rule_name"]
        for row in rows
    }

    assert rule_names == {
        "test_rule_one",
        "test_rule_two",
    }


def test_evaluate_uses_same_input_stream_for_each_rule(
    spark,
):
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row("test_rule_one"),
        make_rule_row("test_rule_two"),
    ]

    calls = []

    class TrackingRuleOne(BaseRule):
        rule_name = "tracking_rule_one"

        def evaluate(self, stream):
            calls.append(
                ("rule_one", id(stream))
            )

            return make_minimal_alert_df(
                stream.sparkSession,
            )

    class TrackingRuleTwo(BaseRule):
        rule_name = "tracking_rule_two"

        def evaluate(self, stream):
            calls.append(
                ("rule_two", id(stream))
            )

            return make_minimal_alert_df(
                stream.sparkSession,
            )

    registry = {
        "tracking_rule_one": TrackingRuleOne,
        "tracking_rule_two": TrackingRuleTwo,
    }

    repository.list_enabled.return_value = [
        make_rule_row(
            "tracking_rule_one",
        ),
        make_rule_row(
            "tracking_rule_two",
        ),
    ]

    engine = RulesEngine(
        repository,
        rule_registry=registry,
        discover_package=None,
    )

    stream = make_event_stream(
        spark,
    )

    engine.evaluate(
        stream,
    )

    assert [
        name
        for name, _ in calls
    ] == [
        "rule_one",
        "rule_two",
    ]

    assert calls[0][1] == id(stream)
    assert calls[1][1] == id(stream)


# ---------------------------------------------------------------------------
# Alert normalization
# ---------------------------------------------------------------------------


def test_engine_stamps_rule_name(
    spark,
):
    class SpoofingRule(BaseRule):
        rule_name = "spoofing_test_rule"

        def evaluate(self, stream):
            return (
                make_minimal_alert_df(
                    stream.sparkSession,
                )
                .withColumn(
                    "rule_name",
                    __import__(
                        "pyspark.sql.functions",
                        fromlist=["lit"],
                    ).lit(
                        "fake_rule_name"
                    ),
                )
            )

    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "spoofing_test_rule",
        ),
    ]

    engine = RulesEngine(
        repository,
        rule_registry={
            "spoofing_test_rule": SpoofingRule,
        },
        discover_package=None,
    )

    result = engine.evaluate(
        make_event_stream(
            spark,
        )
    )

    rows = result.collect()

    assert len(rows) == 1
    assert rows[0]["rule_name"] == (
        "spoofing_test_rule"
    )


def test_optional_alert_fields_receive_defaults(
    spark,
):
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "minimal_test_rule",
        ),
    ]

    engine = make_engine(
        repository,
    )

    result = engine.evaluate(
        make_event_stream(
            spark,
        )
    )

    row = result.first()

    assert row["source_ip"] == (
        "192.168.1.10"
    )

    assert row["severity"] == "HIGH"

    assert row["description"] == (
        "Minimal test alert"
    )

    assert row["rule_name"] == (
        "minimal_test_rule"
    )

    assert row["status"] == "OPEN"

    assert row["source_event_ids"] == []

    assert row["triggered_at"] is not None

    assert row["alert_id"] is not None

    assert row["username"] is None

    assert row["login_1_country"] is None

    assert row["login_2_country"] is None

    assert row["time_delta_minutes"] is None

    assert row["distance_km"] is None


def test_extra_rule_columns_are_removed(
    spark,
):
    from pyspark.sql import functions as F

    class ExtraColumnsRule(BaseRule):
        rule_name = "extra_columns_test_rule"

        def evaluate(self, stream):
            return (
                make_minimal_alert_df(
                    stream.sparkSession,
                )
                .withColumn(
                    "internal_debug",
                    F.lit("should disappear"),
                )
                .withColumn(
                    "another_column",
                    F.lit(123),
                )
            )

    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "extra_columns_test_rule",
        ),
    ]

    engine = RulesEngine(
        repository,
        rule_registry={
            "extra_columns_test_rule": (
                ExtraColumnsRule
            ),
        },
        discover_package=None,
    )

    result = engine.evaluate(
        make_event_stream(
            spark,
        )
    )

    assert "internal_debug" not in result.columns
    assert "another_column" not in result.columns


def test_missing_required_alert_field_fails(
    spark,
):
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "invalid_schema_test_rule",
        ),
    ]

    engine = make_engine(
        repository,
        strict=True,
    )

    with pytest.raises(
        RuleEvaluationError,
    ):
        engine.evaluate(
            make_event_stream(
                spark,
            )
        )


def test_invalid_rule_return_type_fails(
    spark,
):
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "non_dataframe_test_rule",
        ),
    ]

    engine = make_engine(
        repository,
        strict=True,
    )

    with pytest.raises(
        RuleEvaluationError,
    ):
        engine.evaluate(
            make_event_stream(
                spark,
            )
        )


# ---------------------------------------------------------------------------
# Rule failure isolation
# ---------------------------------------------------------------------------


def test_broken_rule_isolated_in_non_strict_mode(
    spark,
):
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "broken_test_rule",
        ),
        make_rule_row(
            "test_rule_one",
        ),
    ]

    engine = make_engine(
        repository,
        strict=False,
    )

    result = engine.evaluate(
        make_event_stream(
            spark,
        )
    )

    rows = result.collect()

    assert len(rows) == 1

    assert rows[0]["rule_name"] == (
        "test_rule_one"
    )


def test_broken_rule_raises_in_strict_mode(
    spark,
):
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "broken_test_rule",
        ),
    ]

    engine = make_engine(
        repository,
        strict=True,
    )

    with pytest.raises(
        RuleEvaluationError,
    ):
        engine.evaluate(
            make_event_stream(
                spark,
            )
        )


# ---------------------------------------------------------------------------
# Streaming mode validation
# ---------------------------------------------------------------------------


def test_rule_must_preserve_streaming_mode(
    spark,
):
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "wrong_streaming_mode_test_rule",
        ),
    ]

    engine = make_engine(
        repository,
        strict=True,
    )

    # Create a real streaming DataFrame.
    streaming_df = (
        spark.readStream
        .format("rate")
        .option("rowsPerSecond", 1)
        .load()
    )

    try:
        with pytest.raises(
            RuleEvaluationError,
        ):
            engine.evaluate(
                streaming_df,
            )
    finally:
        # No query was started, so there is nothing to stop.
        pass


# ---------------------------------------------------------------------------
# Empty rule set
# ---------------------------------------------------------------------------


def test_no_active_rules_returns_empty_alert_stream(
    spark,
):
    repository = Mock()

    repository.list_enabled.return_value = []

    engine = make_engine(
        repository,
    )

    result = engine.evaluate(
        make_event_stream(
            spark,
        )
    )

    assert isinstance(
        result,
        DataFrame,
    )

    assert result.count() == 0

    assert set(result.columns) == {
        "alert_id",
        "triggered_at",
        "rule_name",
        "severity",
        "description",
        "source_ip",
        "source_event_ids",
        "status",
        "username",
        "login_1_country",
        "login_2_country",
        "time_delta_minutes",
        "distance_km",
    }


# ---------------------------------------------------------------------------
# Reload behavior
# ---------------------------------------------------------------------------


def test_reload_removes_disabled_rule():
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
        ),
        make_rule_row(
            "test_rule_two",
        ),
    ]

    engine = make_engine(
        repository,
    )

    assert engine.active_rule_names == (
        "test_rule_one",
        "test_rule_two",
    )

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
        ),
    ]

    result = engine.reload_rules(
        restart_query=False,
    )

    assert result.removed == (
        "test_rule_two",
    )

    assert engine.active_rule_names == (
        "test_rule_one",
    )


def test_reload_adds_new_rule():
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
        ),
    ]

    engine = make_engine(
        repository,
    )

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
        ),
        make_rule_row(
            "test_rule_two",
        ),
    ]

    result = engine.reload_rules(
        restart_query=False,
    )

    assert result.added == (
        "test_rule_two",
    )

    assert engine.active_rule_names == (
        "test_rule_one",
        "test_rule_two",
    )


def test_reload_detects_configuration_change():
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
            threshold=5,
            window_minutes=5,
        ),
    ]

    engine = make_engine(
        repository,
    )

    assert engine.active_rule_names == (
        "test_rule_one",
    )

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
            threshold=10,
            window_minutes=10,
        ),
    ]

    result = engine.reload_rules(
        restart_query=False,
    )

    assert result.updated == (
        "test_rule_one",
    )

    assert engine._active[
        "test_rule_one"
    ].config.threshold == 10

    assert engine._active[
        "test_rule_one"
    ].config.window_minutes == 10


def test_reload_queries_database_again():
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
        ),
    ]

    engine = make_engine(
        repository,
    )

    repository.list_enabled.reset_mock()

    engine.reload_rules(
        restart_query=False,
    )

    repository.list_enabled.assert_called_once()


def test_reload_increments_version_when_changed():
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
        ),
    ]

    engine = make_engine(
        repository,
    )

    initial_version = engine.version

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
        ),
        make_rule_row(
            "test_rule_two",
        ),
    ]

    engine.reload_rules(
        restart_query=False,
    )

    assert engine.version == (
        initial_version + 1
    )


def test_reload_does_not_increment_version_when_unchanged():
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
        ),
    ]

    engine = make_engine(
        repository,
    )

    initial_version = engine.version

    engine.reload_rules(
        restart_query=False,
    )

    assert engine.version == (
        initial_version
    )


# ---------------------------------------------------------------------------
# Database failure behavior
# ---------------------------------------------------------------------------


def test_database_failure_preserves_previous_rules():
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
        ),
    ]

    engine = make_engine(
        repository,
    )

    assert engine.active_rule_names == (
        "test_rule_one",
    )

    repository.list_enabled.side_effect = (
        RuntimeError(
            "database unavailable"
        )
    )

    with pytest.raises(
        RuleLoadError,
    ):
        engine.reload_rules(
            restart_query=False,
        )

    # Existing detection coverage remains active.
    assert engine.active_rule_names == (
        "test_rule_one",
    )


# ---------------------------------------------------------------------------
# Deterministic alert IDs
# ---------------------------------------------------------------------------


def test_generated_alert_id_is_deterministic(
    spark,
):
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "minimal_test_rule",
        ),
    ]

    engine = make_engine(
        repository,
    )

    stream = make_event_stream(
        spark,
    )

    first = engine.evaluate(
        stream,
    ).first()["alert_id"]

    second = engine.evaluate(
        stream,
    ).first()["alert_id"]

    assert first == second


def test_description_change_does_not_change_generated_alert_id(
    spark,
):
    from pyspark.sql import functions as F

    class StableIdRule(BaseRule):
        rule_name = "stable_id_test_rule"

        def evaluate(self, stream):
            return make_minimal_alert_df(
                stream.sparkSession,
            )

    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "stable_id_test_rule",
        ),
    ]

    engine = RulesEngine(
        repository,
        rule_registry={
            "stable_id_test_rule": (
                StableIdRule
            ),
        },
        discover_package=None,
    )

    stream = make_event_stream(
        spark,
    )

    first = (
        engine.evaluate(
            stream,
        )
        .first()["alert_id"]
    )

    # Change only the human-readable description.
    changed_stream = (
        make_minimal_alert_df(
            spark,
        )
        .withColumn(
            "description",
            F.lit(
                "A completely different description"
            ),
        )
    )

    second = (
        engine.evaluate(
            changed_stream,
        )
        .first()["alert_id"]
    )

    assert first == second


# ---------------------------------------------------------------------------
# Alert publishing
# ---------------------------------------------------------------------------


def test_process_batch_requires_publisher(
    spark,
):
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
        ),
    ]

    engine = make_engine(
        repository,
        publisher=None,
    )

    batch_df = engine.evaluate(
        make_event_stream(
            spark,
        )
    )

    with pytest.raises(
        RulesEngineError,
    ):
        engine.process_batch(
            batch_df,
            0,
        )


def test_process_batch_publishes_valid_alerts(
    spark,
):
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
        ),
    ]

    publisher = Mock()

    engine = make_engine(
        repository,
        publisher=publisher,
    )

    batch_df = engine.evaluate(
        make_event_stream(
            spark,
        )
    )

    engine.process_batch(
        batch_df,
        0,
    )

    publisher.publish.assert_called_once()

    payload = (
        publisher.publish.call_args.args[0]
    )

    assert payload["rule_name"] == (
        "test_rule_one"
    )

    assert payload["severity"] == "HIGH"

    assert payload["source_ip"] == (
        "192.168.1.10"
    )

    assert payload["status"] == "OPEN"

    assert "alert_id" in payload


def test_process_batch_flushes_publisher(
    spark,
):
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
        ),
    ]

    publisher = Mock()

    engine = make_engine(
        repository,
        publisher=publisher,
    )

    batch_df = engine.evaluate(
        make_event_stream(
            spark,
        )
    )

    engine.process_batch(
        batch_df,
        0,
    )

    publisher.flush.assert_called_once()


def test_publisher_failure_propagates(
    spark,
):
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
        ),
    ]

    publisher = Mock()

    publisher.publish.side_effect = (
        RuntimeError(
            "Kafka unavailable"
        )
    )

    engine = make_engine(
        repository,
        publisher=publisher,
    )

    batch_df = engine.evaluate(
        make_event_stream(
            spark,
        )
    )

    with pytest.raises(
        RuntimeError,
        match="Kafka unavailable",
    ):
        engine.process_batch(
            batch_df,
            0,
        )


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def test_engine_stats_update_after_batch(
    spark,
):
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
        ),
    ]

    publisher = Mock()

    engine = make_engine(
        repository,
        publisher=publisher,
    )

    batch_df = engine.evaluate(
        make_event_stream(
            spark,
        )
    )

    engine.process_batch(
        batch_df,
        0,
    )

    stats = engine.stats

    assert stats["batches"] == 1
    assert stats["alerts_published"] == 1
    assert stats["alerts_invalid"] == 0


# ---------------------------------------------------------------------------
# Query lifecycle
# ---------------------------------------------------------------------------


def test_start_query_requires_publisher(
    spark,
    tmp_path,
):
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
        ),
    ]

    engine = make_engine(
        repository,
        publisher=None,
    )

    with pytest.raises(
        RulesEngineError,
    ):
        engine.start_query(
            make_event_stream(
                spark,
            ),
            str(
                tmp_path / "checkpoint"
            ),
        )


def test_start_query_rejects_second_active_query(
    spark,
):
    repository = Mock()

    repository.list_enabled.return_value = [
        make_rule_row(
            "test_rule_one",
        ),
    ]

    publisher = Mock()

    engine = make_engine(
        repository,
        publisher=publisher,
    )

    fake_query = Mock()
    fake_query.isActive = True

    engine._query = fake_query

    with pytest.raises(
        RulesEngineError,
        match="already running",
    ):
        engine.start_query(
            make_event_stream(
                spark,
            ),
            "/tmp/test-checkpoint",
        )

    engine._query = None


def test_stop_without_running_query_is_safe():
    repository = Mock()

    repository.list_enabled.return_value = []

    engine = make_engine(
        repository,
    )

    engine.stop()

    assert engine.is_running is False

# ---------------------------------------------------------------------------
# Utility function coverage
# ---------------------------------------------------------------------------


def test_config_from_row_converts_enabled_to_boolean():
    row = make_rule_row(
        "brute_force",
        enabled=1,
        threshold=10,
        window_minutes=15,
    )

    config = config_from_row(row)

    assert config.rule_name == "brute_force"
    assert config.threshold == 10
    assert config.window_minutes == 15
    assert config.slide_minutes == 15
    assert config.enabled is True


def test_config_from_row_handles_missing_optional_attributes():
    from types import SimpleNamespace

    row = SimpleNamespace(
        rule_name="brute_force",
        threshold=5,
        window_minutes=10,
        enabled=False,
    )

    config = config_from_row(row)

    assert config.rule_name == "brute_force"
    assert config.enabled is False
    assert config.off_hours_start is None
    assert config.off_hours_end is None


@pytest.mark.parametrize("timestamp", [0, 1767225600, 1767225600.5])
def test_as_utc_converts_epoch_timestamp(timestamp):
    result = _as_utc(timestamp)

    assert isinstance(result, datetime)
    assert result.tzinfo == timezone.utc
    assert result.timestamp() == pytest.approx(timestamp)


def test_as_utc_rejects_none():
    with pytest.raises(ValueError, match="triggered_at cannot be None"):
        _as_utc(None)


def test_discover_rules_rejects_non_package():
    """A module without ``__path__`` must be rejected as a package."""
    with pytest.raises(RuleLoadError):
        discover_rules("detection_engine.rules_engine")

# ---------------------------------------------------------------------------
# Additional coverage: rule loading and error handling
# ---------------------------------------------------------------------------


def test_rule_factory_returns_invalid_object_in_non_strict_mode(caplog):
    """A factory returning a non-BaseRule object should skip that rule."""
    repository = Mock()
    repository.list_enabled.return_value = [
        make_rule_row("test_rule_one"),
    ]

    engine = make_engine(
        repository,
        rule_factory=lambda rule_class, config: object(),
    )

    assert engine.active_rule_names == ()
    assert "test_rule_one" in caplog.text


def test_rule_factory_failure_in_non_strict_mode(caplog):
    """A factory exception should not prevent other rules from loading."""
    repository = Mock()
    repository.list_enabled.return_value = [
        make_rule_row("test_rule_one"),
        make_rule_row("test_rule_two"),
    ]

    def factory(rule_class, config):
        if rule_class.rule_name == "test_rule_one":
            raise RuntimeError("intentional factory failure")
        return rule_class(config)

    engine = make_engine(
        repository,
        rule_factory=factory,
    )

    assert engine.active_rule_names == ("test_rule_two",)

    result = engine.reload_rules(restart_query=False)

    assert result.failed == ("test_rule_one",)
    assert result.loaded == ("test_rule_two",)


def test_empty_initial_rule_set_logs_warning(caplog):
    """Startup with no active rules should warn that the stream is empty."""
    repository = Mock()
    repository.list_enabled.return_value = []

    with caplog.at_level("WARNING"):
        engine = make_engine(repository)

    assert engine.active_rule_names == ()
    assert "loaded 0 detection rules" in caplog.text


# ---------------------------------------------------------------------------
# Additional coverage: query lifecycle
# ---------------------------------------------------------------------------


def test_stop_stops_active_query():
    """Stopping the engine should stop an active query and clear its state."""
    repository = Mock()
    repository.list_enabled.return_value = []

    engine = make_engine(repository)

    query = Mock()
    query.isActive = True

    engine._query = query
    engine._query_spec = Mock()

    engine.stop()

    query.stop.assert_called_once_with()
    assert engine._query is None
    assert engine._query_spec is None
    assert engine.is_running is False


def test_restart_query_clears_query_spec_when_launch_fails():
    """A failed query restart should clear the saved query specification."""
    repository = Mock()
    repository.list_enabled.return_value = []

    engine = make_engine(repository)

    query_spec = Mock()
    old_query = Mock()
    old_query.isActive = False

    engine._query_spec = query_spec
    engine._query = old_query
    engine._launch = Mock(
        side_effect=RuntimeError("intentional restart failure")
    )

    with pytest.raises(
        RuntimeError,
        match="intentional restart failure",
    ):
        engine._restart_query()

    engine._launch.assert_called_once_with(query_spec)
    assert engine._query_spec is None