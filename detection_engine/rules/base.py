"""
Base abstraction for streaming detection rules.

Every rule:
  1. Loads its own tunable config (threshold, window, etc.) from the
     `rules` DB table via a RuleConfigRepository (never hardcoded).
  2. Exposes a pure, batch-testable `detect(events_df)` method that
     returns a DataFrame of raw alert rows (no DB/Kafka side effects).
  3. Exposes a `build_streaming_query(...)` that wires `detect()` into
     a structured-streaming `foreachBatch` sink which persists to
     Postgres and publishes to Kafka.

Keeping (2) side-effect-free is what makes rules unit-testable without
spinning up Kafka/Postgres or a live streaming query.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from pyspark.sql import DataFrame


@dataclass(frozen=True)
class RuleConfig:
    """Tunable parameters for a rule, sourced from the `rules` DB table."""

    rule_name: str
    threshold: int
    window_minutes: int
    slide_minutes: int
    enabled: bool = True


class BaseRule(ABC):
    """Contract every detection rule must implement."""

    rule_name: str

    @abstractmethod
    def load_config(self) -> RuleConfig:
        """Fetch this rule's current threshold/window from the `rules` table."""
        raise NotImplementedError

    @abstractmethod
    def detect(self, events_df: DataFrame, config: RuleConfig) -> DataFrame:
        """Pure transformation: events in, alert rows out. No side effects."""
        raise NotImplementedError