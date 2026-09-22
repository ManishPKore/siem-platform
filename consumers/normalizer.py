"""
consumers/normalizer.py

Normalization stage for the Spark Structured Streaming pipeline (Issue #11).

Converts raw log events -- as actually emitted by producers/log_generator.py
-- into the canonical LogEvent shape defined in consumers/schemas.py
(Issue #6), so every downstream detection rule can rely on consistent field
names (`event_type`, `severity`, `source`, ...) regardless of which raw
source produced the event.

Why this exists
----------------
consumers/spark_consumer.py (Issue #10) currently parses the Kafka `value`
bytes directly against a schema that assumes the JSON *already* looks like
a LogEvent (has `source`, `severity`, canonical `event_type` values, and
so on). Real producer output does not: producers/log_generator.py emits
`event_type="web_access"` (not "web_request"), has no `source` field at
all, uses `outcome`/`service` instead of `success`/`auth_method`, and so
on. Without a normalization stage sitting between raw parsing and
validation, almost every real event fails required-field validation and
is wrongly routed to the dead-letter store. This module is that missing
translation layer.

Design notes
------------
* Implemented with native Spark column expressions (F.when/F.col) rather
  than a Python UDF, per the issue notes -- native expressions run
  entirely inside the JVM (Catalyst/Tungsten), and the <1ms/event
  overhead budget in the acceptance criteria is not realistically
  hittable with a Python UDF once per-row Py4J serialization is added.
* `normalize_event()` is a pure DataFrame -> DataFrame transform: no
  side effects, nothing Kafka- or sink-specific, so it's trivially
  unit-testable against small in-memory DataFrames (see
  tests/consumers/test_normalizer.py) without a running cluster or
  Kafka broker.
* Source detection and the canonical `event_type` are derived together,
  since they're the same underlying classification (e.g. "the raw
  event_type is 'web_access'" implies both source="web" and canonical
  event_type="web_request"). Keeping that classification in one place
  (rather than two chains that could drift apart) is why
  `_derive_canonical_event_type()` takes the already-derived `source`
  column as input instead of re-deriving it.
* Events whose raw `event_type` doesn't match any known category get
  source=NULL (and therefore canonical event_type=NULL, severity=NULL
  too). That NULL is what routes them to the dead-letter queue as
  "unrecognized source" -- via the same required-field check used for
  every other missing-field reason, since `source` is itself one of
  consumers.log_consumer.REQUIRED_LOG_FIELDS. There's no separate
  "unrecognized source" code path; it falls out of the normal
  required-field mask, so there's exactly one definition of "invalid".
* `normalize_event()` never drops or filters rows. Splitting into
  valid/dead-letter streams is the caller's job (see
  `is_normalization_valid()` / `required_field_mask()` below) -- keeping
  normalization and filtering as separate steps is what makes each one
  independently testable row-by-row.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional

from pyspark.sql import Column, DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import (
    BooleanType,
    IntegerType,
    StringType,
    StructField,
    StructType,
)

from consumers.log_consumer import REQUIRED_LOG_FIELDS

# --------------------------------------------------------------------------- #
# Raw event schema -- matches producers/log_generator.py's NDJSON output
# exactly. This is what is actually published to `logs-raw`; it is NOT the
# canonical LogEvent shape (no `source`, no `severity`, `outcome`/`service`
# instead of `success`/`auth_method`, etc).
# --------------------------------------------------------------------------- #

RAW_EVENT_SCHEMA = StructType(
    [
        # --- Universal (producers/log_generator.py::base_event()) ---
        StructField("schema_version", StringType(), True),
        StructField("event_id", StringType(), True),
        StructField("timestamp", StringType(), True),
        StructField("source_ip", StringType(), True),
        StructField("event_type", StringType(), True),
        StructField("raw_message", StringType(), True),
        # --- SSH / auth (ssh_failed_login, ssh_successful_login,
        # linux_auth_event) ---
        StructField("username", StringType(), True),
        StructField("service", StringType(), True),
        StructField("outcome", StringType(), True),
        StructField("dest_port", IntegerType(), True),
        # --- Web (web_access_event) ---
        StructField("method", StringType(), True),
        StructField("path", StringType(), True),
        StructField("status_code", IntegerType(), True),
        StructField("user_agent", StringType(), True),
        StructField("bytes_sent", IntegerType(), True),
        # --- Firewall (firewall_event) ---
        StructField("dest_ip", StringType(), True),
        StructField("src_port", IntegerType(), True),
        StructField("protocol", StringType(), True),
        StructField("action", StringType(), True),
    ]
)

# Raw `event_type` values grouped by which canonical `source` they belong
# to. Kept as plain tuples (not a dict-of-sets) so they drop straight into
# F.col("event_type").isin(...) below.
_SSH_LOGIN_EVENT_TYPES = ("failed_login", "successful_login")
_AUTH_EVENT_TYPES = (
    "sudo_command",
    "sudo_failure",
    "su_success",
    "su_failure",
    "pam_session_opened",
    "pam_auth_failure",
)
_WEB_EVENT_TYPES = ("web_access",)
_FIREWALL_EVENT_TYPES = ("firewall_traffic",)

# ISO-8601 patterns actually seen on `logs-raw`:
#   producers/log_generator.py's iso()          -> "2026-09-04T10:00:00Z"
#   consumers/schemas.py's LogEvent (isoformat)  -> "2026-09-04T10:00:00+00:00"
# Both are tried, in order; F.coalesce keeps the first non-null result.
_TIMESTAMP_PATTERNS = ("yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ssXXX")


def _parse_event_timestamp(column: str) -> Column:
    candidates = [F.to_timestamp(F.col(column), p) for p in _TIMESTAMP_PATTERNS]
    # Bare fallback with no explicit pattern, in case a producer ever emits
    # fractional seconds or an offset the two patterns above don't cover
    # but Spark's default parser does.
    candidates.append(F.to_timestamp(F.col(column)))
    return F.coalesce(*candidates)


# --------------------------------------------------------------------------- #
# Per-field derivations
# --------------------------------------------------------------------------- #


def _derive_source() -> Column:
    return (
        F.when(F.col("event_type").isin(*_SSH_LOGIN_EVENT_TYPES), F.lit("ssh"))
        .when(F.col("event_type").isin(*_AUTH_EVENT_TYPES), F.lit("auth"))
        .when(F.col("event_type").isin(*_WEB_EVENT_TYPES), F.lit("web"))
        .when(F.col("event_type").isin(*_FIREWALL_EVENT_TYPES), F.lit("firewall"))
        .otherwise(F.lit(None).cast(StringType()))
    )


def _derive_canonical_event_type(source: Column) -> Column:
    """Map the raw `event_type` to the canonical EventType literal for its
    source. Mirrors the normalize_*_log() functions in consumers/schemas.py
    -- the other half of this same canonical contract -- so a raw SSH
    failed login normalized here and one normalized by normalize_ssh_log()
    land on identical canonical values."""
    return (
        F.when(
            source == "ssh",
            F.when(
                F.col("event_type") == "successful_login", F.lit("successful_login")
            ).otherwise(F.lit("failed_login")),
        )
        .when(source == "auth", F.lit("sudo_attempt"))
        .when(source == "web", F.lit("web_request"))
        .when(
            source == "firewall",
            F.when(F.col("action") == "ACCEPT", F.lit("firewall_accept"))
            .when(F.col("action") == "DROP", F.lit("firewall_drop"))
            # An unrecognized/missing `action` must NOT default to
            # "firewall_drop" -- that would silently manufacture a
            # MEDIUM-severity canonical event out of a firewall row that
            # is actually malformed. It falls through to NULL instead,
            # which required_field_mask() below then correctly routes to
            # the dead letter queue as a missing required field.
            .otherwise(F.lit(None).cast(StringType())),
        )
        .otherwise(F.lit(None).cast(StringType()))
    )


def _derive_severity(source: Column, canonical_event_type: Column) -> Column:
    """Mirrors the severity rules in consumers/schemas.py's normalize_*
    functions exactly:
        ssh   successful_login -> INFO,    failed_login -> MEDIUM
        auth  sudo_attempt     -> MEDIUM (always, regardless of outcome)
        web   status_code>=400 -> MEDIUM, else INFO
        fw    DROP -> MEDIUM,  ACCEPT -> INFO
    """
    return (
        F.when(canonical_event_type == "successful_login", F.lit("INFO"))
        .when(canonical_event_type == "failed_login", F.lit("MEDIUM"))
        .when(canonical_event_type == "sudo_attempt", F.lit("MEDIUM"))
        .when(
            source == "web",
            F.when(F.col("status_code") >= 400, F.lit("MEDIUM")).otherwise(
                F.lit("INFO")
            ),
        )
        .when(canonical_event_type == "firewall_drop", F.lit("MEDIUM"))
        .when(canonical_event_type == "firewall_accept", F.lit("INFO"))
        .otherwise(F.lit(None).cast(StringType()))
    )


def _derive_auth_method(source: Column) -> Column:
    """producers/log_generator.py always renders SSH auth as "password" in
    the raw_message (see ssh_failed_login/ssh_successful_login) and always
    renders sudo auth as "sudo" -- matching normalize_auth_log()'s
    hardcoded auth_method="sudo" in consumers/schemas.py."""
    return (
        F.when(source == "ssh", F.lit("password"))
        .when(source == "auth", F.lit("sudo"))
        .otherwise(F.lit(None).cast(StringType()))
    )


def _derive_success(source: Column) -> Column:
    return F.when(
        source.isin("ssh", "auth"), F.col("outcome") == "success"
    ).otherwise(F.lit(None).cast(BooleanType()))


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def normalize_event(raw_df: DataFrame) -> DataFrame:
    """
    Normalize a DataFrame of raw log events (RAW_EVENT_SCHEMA-shaped
    columns, already parsed out of the Kafka `value` bytes) into the
    canonical LogEvent shape from consumers/schemas.py.

    Adds/overwrites:
        source                -- inferred from the raw event_type
        event_type             -- remapped to the canonical EventType literal
        severity                -- derived per-source (see _derive_severity)
        auth_method, success    -- derived for ssh/auth sources
        event_timestamp          -- the `timestamp` string parsed as a real
                                     TimestampType, for validation/lag metrics
        normalized_at             -- wall-clock time this row was normalized

    Passes web/firewall source-specific fields (method, path, status_code,
    user_agent, bytes_sent, action, dest_ip, dest_port, protocol) through
    unchanged -- producers/log_generator.py already names them exactly as
    the canonical schema expects.

    Never drops or filters rows -- pair this with `is_normalization_valid()`
    (or your own required-field check against `required_field_mask()`) to
    split the result into valid vs dead-letter streams.
    """
    source = _derive_source()
    df = raw_df.withColumn("source", source)

    canonical_event_type = _derive_canonical_event_type(F.col("source"))
    df = df.withColumn("event_type", canonical_event_type)

    df = df.withColumn(
        "severity", _derive_severity(F.col("source"), F.col("event_type"))
    )
    df = df.withColumn("auth_method", _derive_auth_method(F.col("source")))
    df = df.withColumn("success", _derive_success(F.col("source")))
    df = df.withColumn("event_timestamp", _parse_event_timestamp("timestamp"))
    df = df.withColumn("normalized_at", F.current_timestamp())

    return df


def required_field_mask() -> Column:
    """AND together an isNotNull/non-blank check for every canonical
    required field (consumers.log_consumer.REQUIRED_LOG_FIELDS), using the
    parsed `event_timestamp` column in place of the raw `timestamp` string
    -- a non-blank-but-unparsable timestamp is exactly as invalid as a
    missing one. A row whose `source` came back NULL (raw event_type
    didn't match any known category) fails here too, since `source` is
    itself one of REQUIRED_LOG_FIELDS -- there is no separate
    "unrecognized source" branch."""
    checks = []
    for field in sorted(REQUIRED_LOG_FIELDS):
        if field == "timestamp":
            checks.append(F.col("event_timestamp").isNotNull())
        else:
            checks.append(
                F.col(field).isNotNull()
                & (F.trim(F.col(field).cast(StringType())) != "")
            )
    mask = checks[0]
    for check in checks[1:]:
        mask = mask & check
    return mask


def is_normalization_valid(normalized_df: DataFrame) -> DataFrame:
    """Convenience wrapper around normalize_event()'s output: adds
    `_is_valid` (True/False) using required_field_mask(). Callers filter
    on this column to split valid records from dead-letter records."""
    return normalized_df.withColumn("_is_valid", required_field_mask())


# --------------------------------------------------------------------------- #
# Dead-letter path convention
# --------------------------------------------------------------------------- #


def dead_letter_output_path(base_dir: str, moment: Optional[datetime] = None) -> str:
    """`<base_dir>/YYYY-MM-DD/`, partitioned by UTC date -- the dead-letter
    path convention for this issue, so a day's worth of rejected events can
    be inspected or replayed without scanning the entire history.

    `moment` defaults to the current UTC time; pass an explicit datetime
    (e.g. from a test) for a deterministic path.
    """
    when = moment or datetime.now(timezone.utc)
    return os.path.join(base_dir, when.strftime("%Y-%m-%d"))