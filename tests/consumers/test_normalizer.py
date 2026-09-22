"""
tests/consumers/test_normalizer.py

Unit tests for consumers/normalizer.py (Issue #11): normalize_event(),
required_field_mask() / is_normalization_valid(), and
dead_letter_output_path().

Run:
    pytest tests/consumers/test_normalizer.py -v
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timezone

import pytest

pyspark = pytest.importorskip("pyspark")

from pyspark.sql import Row, SparkSession

from consumers.normalizer import (
    RAW_EVENT_SCHEMA,
    dead_letter_output_path,
    is_normalization_valid,
    normalize_event,
)


@pytest.fixture(scope="session")
def spark():
    session = (
        SparkSession.builder.master("local[2]")
        .appName("siem-normalizer-tests")
        .config("spark.ui.enabled", "false")
        .config("spark.sql.shuffle.partitions", "2")
        .getOrCreate()
    )
    session.sparkContext.setLogLevel("ERROR")
    yield session
    session.stop()


def make_df(spark, rows: list[dict]):
    """Build a RAW_EVENT_SCHEMA-shaped DataFrame from plain dicts, filling
    any field a given row doesn't set with None -- so each test's sample
    event only needs to state the fields it actually cares about."""
    field_names = [f.name for f in RAW_EVENT_SCHEMA.fields]
    complete_rows = [
        Row(**{name: row.get(name) for name in field_names}) for row in rows
    ]
    return spark.createDataFrame(complete_rows, schema=RAW_EVENT_SCHEMA)


# --------------------------------------------------------------------------- #
# Sample raw events -- matching producers/log_generator.py's ACTUAL output
# shape (event_type="web_access"/"firewall_traffic", outcome/service
# instead of success/auth_method, no `source` field at all), not the
# canonical shape.
# --------------------------------------------------------------------------- #


def raw_ssh_failed_login(**overrides) -> dict:
    event = {
        "schema_version": "1.0",
        "event_id": "evt-ssh-failed-1",
        "timestamp": "2026-09-22T10:00:00Z",
        "source_ip": "203.0.113.5",
        "event_type": "failed_login",
        "username": "admin",
        "service": "sshd",
        "outcome": "failure",
        "dest_port": 22,
        "raw_message": "Failed password for admin from 203.0.113.5 port 51234 ssh2",
    }
    event.update(overrides)
    return event


def raw_ssh_successful_login(**overrides) -> dict:
    event = raw_ssh_failed_login(
        event_id="evt-ssh-success-1",
        event_type="successful_login",
        outcome="success",
        raw_message="Accepted password for admin from 203.0.113.5 port 51234 ssh2",
    )
    event.update(overrides)
    return event


def raw_web_request(**overrides) -> dict:
    event = {
        "schema_version": "1.0",
        "event_id": "evt-web-1",
        "timestamp": "2026-09-22T10:05:00Z",
        "source_ip": "198.51.100.23",
        "event_type": "web_access",
        "method": "GET",
        "path": "/login",
        "status_code": 200,
        "user_agent": "Mozilla/5.0",
        "bytes_sent": 512,
        "raw_message": (
            '198.51.100.23 - - [22/Sep/2026:10:05:00 +0000] '
            '"GET /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        ),
    }
    event.update(overrides)
    return event


def raw_firewall_drop(**overrides) -> dict:
    event = {
        "schema_version": "1.0",
        "event_id": "evt-fw-1",
        "timestamp": "2026-09-22T10:10:00Z",
        "source_ip": "198.51.100.44",
        "event_type": "firewall_traffic",
        "dest_ip": "10.0.0.5",
        "dest_port": 22,
        "src_port": 51000,
        "protocol": "TCP",
        "action": "DROP",
        "raw_message": (
            "DROP IN=eth0 OUT= SRC=198.51.100.44 DST=10.0.0.5 "
            "PROTO=TCP SPT=51000 DPT=22"
        ),
    }
    event.update(overrides)
    return event


def raw_sudo_command(**overrides) -> dict:
    event = {
        "schema_version": "1.0",
        "event_id": "evt-sudo-1",
        "timestamp": "2026-09-22T10:15:00Z",
        "source_ip": "203.0.113.9",
        "event_type": "sudo_command",
        "username": "alice",
        "service": "sudo",
        "outcome": "success",
        "raw_message": (
            "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
        ),
    }
    event.update(overrides)
    return event


# --------------------------------------------------------------------------- #
# RAW_EVENT_SCHEMA
# --------------------------------------------------------------------------- #


class TestRawEventSchema:
    def test_contains_universal_fields(self):
        fields = {f.name for f in RAW_EVENT_SCHEMA.fields}
        assert {
            "event_id",
            "timestamp",
            "source_ip",
            "event_type",
            "raw_message",
        } <= fields

    def test_contains_source_specific_fields(self):
        fields = {f.name for f in RAW_EVENT_SCHEMA.fields}
        expected = {
            "username",
            "service",
            "outcome",
            "dest_port",
            "method",
            "path",
            "status_code",
            "user_agent",
            "bytes_sent",
            "dest_ip",
            "src_port",
            "protocol",
            "action",
        }
        assert expected <= fields


# --------------------------------------------------------------------------- #
# SSH normalization
#
# Acceptance criterion: SSH failed login raw event -> normalized with
# event_type="failed_login", username, source_ip populated.
# --------------------------------------------------------------------------- #


class TestNormalizeSsh:
    def test_failed_login_maps_to_canonical_fields(self, spark):
        df = make_df(spark, [raw_ssh_failed_login()])
        row = normalize_event(df).first()

        assert row.source == "ssh"
        assert row.event_type == "failed_login"
        assert row.username == "admin"
        assert row.source_ip == "203.0.113.5"
        assert row.severity == "MEDIUM"
        assert row.auth_method == "password"
        assert row.success is False

    def test_successful_login_maps_to_canonical_fields(self, spark):
        df = make_df(spark, [raw_ssh_successful_login()])
        row = normalize_event(df).first()

        assert row.source == "ssh"
        assert row.event_type == "successful_login"
        assert row.severity == "INFO"
        assert row.success is True

    def test_is_valid_for_complete_ssh_event(self, spark):
        df = make_df(spark, [raw_ssh_failed_login()])
        row = is_normalization_valid(normalize_event(df)).first()
        assert row._is_valid is True


# --------------------------------------------------------------------------- #
# Web normalization
#
# Acceptance criterion: web request raw event -> normalized with method,
# path, status_code, user_agent.
# --------------------------------------------------------------------------- #


class TestNormalizeWeb:
    def test_web_request_maps_to_canonical_fields(self, spark):
        df = make_df(spark, [raw_web_request()])
        row = normalize_event(df).first()

        assert row.source == "web"
        assert row.event_type == "web_request"
        assert row.method == "GET"
        assert row.path == "/login"
        assert row.status_code == 200
        assert row.user_agent == "Mozilla/5.0"
        assert row.severity == "INFO"

    def test_error_status_gets_medium_severity(self, spark):
        df = make_df(
            spark, [raw_web_request(event_id="evt-web-404", status_code=404)]
        )
        row = normalize_event(df).first()
        assert row.severity == "MEDIUM"

    def test_is_valid_for_complete_web_event(self, spark):
        df = make_df(spark, [raw_web_request()])
        row = is_normalization_valid(normalize_event(df)).first()
        assert row._is_valid is True


# --------------------------------------------------------------------------- #
# Firewall normalization
#
# Acceptance criterion: firewall drop raw event -> normalized with
# action="DROP", dest_ip, dest_port.
# --------------------------------------------------------------------------- #


class TestNormalizeFirewall:
    def test_drop_maps_to_canonical_fields(self, spark):
        df = make_df(spark, [raw_firewall_drop()])
        row = normalize_event(df).first()

        assert row.source == "firewall"
        assert row.event_type == "firewall_drop"
        assert row.action == "DROP"
        assert row.dest_ip == "10.0.0.5"
        assert row.dest_port == 22
        assert row.severity == "MEDIUM"

    def test_accept_maps_to_canonical_fields(self, spark):
        df = make_df(spark, [raw_firewall_drop(event_id="evt-fw-2", action="ACCEPT")])
        row = normalize_event(df).first()

        assert row.event_type == "firewall_accept"
        assert row.severity == "INFO"

    def test_is_valid_for_complete_firewall_event(self, spark):
        df = make_df(spark, [raw_firewall_drop()])
        row = is_normalization_valid(normalize_event(df)).first()
        assert row._is_valid is True

    def test_unknown_firewall_action_does_not_default_to_drop(self, spark):
        """An unrecognized `action` value must NOT silently become
        "firewall_drop" -- that would manufacture a valid MEDIUM-severity
        canonical event out of a row that's actually malformed."""
        df = make_df(
            spark, [raw_firewall_drop(event_id="evt-fw-3", action="UNKNOWN")]
        )
        row = normalize_event(df).first()

        assert row.event_type is None
        assert row.severity is None

    def test_unknown_firewall_action_is_invalid(self, spark):
        df = make_df(
            spark, [raw_firewall_drop(event_id="evt-fw-3", action="UNKNOWN")]
        )
        row = is_normalization_valid(normalize_event(df)).first()
        assert row._is_valid is False

    def test_missing_firewall_action_does_not_default_to_drop(self, spark):
        df = make_df(spark, [raw_firewall_drop(event_id="evt-fw-4", action=None)])
        row = normalize_event(df).first()

        assert row.event_type is None
        assert row.severity is None


# --------------------------------------------------------------------------- #
# Auth (sudo) normalization
# --------------------------------------------------------------------------- #


class TestNormalizeAuth:
    def test_sudo_success_maps_to_canonical_fields(self, spark):
        df = make_df(spark, [raw_sudo_command()])
        row = normalize_event(df).first()

        assert row.source == "auth"
        assert row.event_type == "sudo_attempt"
        assert row.auth_method == "sudo"
        assert row.success is True
        assert row.severity == "MEDIUM"

    def test_sudo_failure_still_gets_medium_severity(self, spark):
        df = make_df(
            spark,
            [
                raw_sudo_command(
                    event_id="evt-sudo-2",
                    event_type="sudo_failure",
                    outcome="failure",
                )
            ],
        )
        row = normalize_event(df).first()

        assert row.source == "auth"
        assert row.success is False
        assert row.severity == "MEDIUM"

    def test_is_valid_for_complete_auth_event(self, spark):
        df = make_df(spark, [raw_sudo_command()])
        row = is_normalization_valid(normalize_event(df)).first()
        assert row._is_valid is True


# --------------------------------------------------------------------------- #
# Unrecognized source -> dead letter
#
# Acceptance criterion: events with unrecognized `source` field go to dead
# letter queue. (There's no raw `source` field to begin with -- source is
# *derived* from event_type -- so "unrecognized source" means "raw
# event_type didn't match any known category".)
# --------------------------------------------------------------------------- #


class TestUnrecognizedSource:
    def test_unknown_event_type_yields_null_source_and_type(self, spark):
        df = make_df(spark, [raw_ssh_failed_login(event_type="totally_unknown_event")])
        row = normalize_event(df).first()

        assert row.source is None
        assert row.event_type is None
        assert row.severity is None

    def test_unknown_event_type_is_invalid(self, spark):
        df = make_df(spark, [raw_ssh_failed_login(event_type="totally_unknown_event")])
        row = is_normalization_valid(normalize_event(df)).first()
        assert row._is_valid is False


# --------------------------------------------------------------------------- #
# Missing required fields after normalization -> dead letter
# --------------------------------------------------------------------------- #


class TestMissingRequiredFields:
    @pytest.mark.parametrize(
        "field", ["event_id", "timestamp", "source_ip", "raw_message"]
    )
    def test_missing_universal_field_is_invalid(self, spark, field):
        event = raw_ssh_failed_login()
        event[field] = None
        df = make_df(spark, [event])
        row = is_normalization_valid(normalize_event(df)).first()
        assert row._is_valid is False

    def test_blank_source_ip_is_invalid(self, spark):
        event = raw_ssh_failed_login(source_ip="   ")
        df = make_df(spark, [event])
        row = is_normalization_valid(normalize_event(df)).first()
        assert row._is_valid is False

    def test_unparsable_timestamp_is_invalid(self, spark):
        event = raw_ssh_failed_login(timestamp="not-a-timestamp")
        df = make_df(spark, [event])
        row = is_normalization_valid(normalize_event(df)).first()
        assert row._is_valid is False


# --------------------------------------------------------------------------- #
# normalized_at / event_timestamp
# --------------------------------------------------------------------------- #


class TestTimestamps:
    def test_normalized_at_is_populated(self, spark):
        df = make_df(spark, [raw_ssh_failed_login()])
        row = normalize_event(df).first()
        assert row.normalized_at is not None

    def test_utc_z_timestamp_is_parsed(self, spark):
        df = make_df(spark, [raw_ssh_failed_login(timestamp="2026-09-22T10:00:00Z")])
        row = normalize_event(df).first()
        assert row.event_timestamp is not None

    def test_offset_timestamp_is_parsed(self, spark):
        df = make_df(
            spark, [raw_ssh_failed_login(timestamp="2026-09-22T10:00:00+00:00")]
        )
        row = normalize_event(df).first()
        assert row.event_timestamp is not None


# --------------------------------------------------------------------------- #
# dead_letter_output_path
#
# Note: dead_letter_output_path() only computes the "data/dead_letter/
# YYYY-MM-DD/" path string used by the dead-letter *sink* -- it does no
# I/O itself, so it's tested directly rather than through a streaming
# write (see consumers/spark_consumer.py for where a caller wires this
# into an actual foreachBatch writer).
# --------------------------------------------------------------------------- #


class TestDeadLetterOutputPath:
    def test_appends_utc_date_subdirectory(self):
        moment = datetime(2026, 9, 22, 15, 30, tzinfo=timezone.utc)
        path = dead_letter_output_path("data/dead_letter", moment=moment)
        assert path == os.path.join("data/dead_letter", "2026-09-22")

    def test_defaults_to_current_utc_date(self):
        path = dead_letter_output_path("data/dead_letter")
        assert re.search(r"data[/\\]dead_letter[/\\]\d{4}-\d{2}-\d{2}$", path)


# --------------------------------------------------------------------------- #
# Normalization overhead benchmark
#
# Acceptance criterion: normalization adds <1ms overhead per event in
# local benchmarks. That figure is a local-machine target, not something
# safe to assert as a hard cross-environment gate -- it would flake on a
# slower/shared CI runner. This test checks the same order of magnitude
# on a realistically sized batch, after a warm-up pass so JVM/codegen
# startup cost isn't charged against the budget.
# --------------------------------------------------------------------------- #


class TestNormalizationOverhead:
    def test_normalization_overhead_is_small_per_event(self, spark):
        n = 5000
        builders = [
            raw_ssh_failed_login,
            raw_ssh_successful_login,
            raw_web_request,
            raw_firewall_drop,
            raw_sudo_command,
        ]
        events = [
            builders[i % len(builders)](event_id=f"evt-bench-{i}") for i in range(n)
        ]
        df = make_df(spark, events).cache()
        df.count()  # materialize the cache before timing

        # Warm-up: run the transform once so JIT/codegen cost isn't
        # charged to the timed run below.
        normalize_event(df).count()

        start = time.perf_counter()
        normalize_event(df).count()
        elapsed_seconds = time.perf_counter() - start

        avg_ms_per_event = (elapsed_seconds * 1000) / n

        # Generous multiple of the 1ms target to keep this stable on
        # shared/slow CI hardware while still catching a real regression
        # (e.g. an accidental Python UDF added to the hot path).
        assert avg_ms_per_event < 2.0, (
            f"normalize_event() averaged {avg_ms_per_event:.3f}ms/event over "
            f"{n} events, expected close to the <1ms/event target"
        )