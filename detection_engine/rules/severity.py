"""
Severity classification shared across detection rules.

Scale (per project spec):
    5-9 events   -> MEDIUM
    10-19 events -> HIGH
    20+ events   -> CRITICAL

Below 5 events, callers should not be triggering an alert at all (the
rule's own threshold gates that); INFO is the floor purely so this stays
total and never returns a value outside api.models.event.VALID_SEVERITIES.
"""

from enum import Enum


class Severity(str, Enum):
    INFO = "INFO"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def severity_for_count(event_count: int) -> str:
    """Map an event count to a severity level using the project-wide scale.

    Returns a plain str matching api.models.event.VALID_SEVERITIES exactly
    ("INFO" | "MEDIUM" | "HIGH" | "CRITICAL"), so it can be written straight
    into Alert.severity or AlertEvent.severity without conversion.
    """
    if event_count >= 20:
        return Severity.CRITICAL.value
    if event_count >= 10:
        return Severity.HIGH.value
    if event_count >= 5:
        return Severity.MEDIUM.value
    return Severity.INFO.value