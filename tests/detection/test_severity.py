"""Tests for shared severity classification across detection rules."""

import pytest

from detection_engine.rules.severity import Severity, severity_for_count


@pytest.mark.parametrize(
    ("event_count", "expected"),
    [
        # INFO: fewer than 5 events.
        (0, "INFO"),
        (1, "INFO"),
        (4, "INFO"),
        # MEDIUM: 5-9 events.
        (5, "MEDIUM"),
        (6, "MEDIUM"),
        (9, "MEDIUM"),
        # HIGH: 10-19 events.
        (10, "HIGH"),
        (11, "HIGH"),
        (19, "HIGH"),
        # CRITICAL: 20 or more events.
        (20, "CRITICAL"),
        (21, "CRITICAL"),
        (100, "CRITICAL"),
    ],
)
def test_severity_for_count_boundaries(
    event_count: int,
    expected: str,
) -> None:
    """Map event counts to the correct severity."""
    assert severity_for_count(event_count) == expected


def test_severity_for_count_returns_plain_string() -> None:
    """Return a plain string suitable for alert records."""
    result = severity_for_count(20)

    assert result == "CRITICAL"
    assert type(result) is str


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (Severity.INFO, "INFO"),
        (Severity.MEDIUM, "MEDIUM"),
        (Severity.HIGH, "HIGH"),
        (Severity.CRITICAL, "CRITICAL"),
    ],
)
def test_severity_enum_values(
    severity: Severity,
    expected: str,
) -> None:
    """Verify that each enum member has the expected string value."""
    assert severity.value == expected


def test_severity_for_count_uses_inclusive_thresholds() -> None:
    """Verify that each threshold belongs to its corresponding level."""
    assert severity_for_count(5) == Severity.MEDIUM.value
    assert severity_for_count(10) == Severity.HIGH.value
    assert severity_for_count(20) == Severity.CRITICAL.value