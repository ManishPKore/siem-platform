"""
api/services/storage_service.py

Persists normalized LogEvent objects (consumers/schemas.py) to the
`events` table (api/models/event.py) in PostgreSQL.

Design notes
------------
* Bulk insert only. Everything goes through
  `insert(Event.__table__).values([...])` (SQLAlchemy Core) in chunks of
  at most `chunk_size` rows, never a loop of individual `.add()` calls.
  `save_event()` is a thin wrapper around `save_events_bulk()` with a
  one-item list, so there is exactly one insert code path.

* `ON CONFLICT (event_id) DO NOTHING` makes duplicate event_id values
  (e.g. consumer redelivery after a crash before offset commit) inert
  instead of raising IntegrityError and killing the whole batch.

* Retry scope is deliberately narrow: only `OperationalError` (can't
  reach the DB / connection dropped / pool exhausted -- i.e. actually
  transient) is retried with exponential backoff + jitter. Everything
  else `DBAPIError` covers -- IntegrityError, DataError,
  ProgrammingError, a bad CHECK-constraint value slipping through, a
  typo'd column -- is NOT transient, gets logged, and is re-raised
  immediately with no retry. Retrying a non-transient error just burns
  several seconds before failing anyway, and a "retrying..." log line
  for it would be actively misleading about what's actually wrong.

* Batches are chunked (default 500 rows) before hitting Postgres. Each
  row here has 8 columns, and Postgres caps bound parameters per
  statement at 65535, so an unchunked caller sending a few thousand
  events would eventually hit that ceiling -- and a multi-thousand-row
  single transaction is bad for lock contention/WAL even under the
  limit regardless. The caller-supplied batch is never trusted to
  already be a safe size.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass
from typing import Callable

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.orm import Session

from api.database import SessionLocal
from api.models.event import Event
from consumers.schemas import LogEvent

logger = logging.getLogger(__name__)

# Columns that exist directly on the `events` table. Everything else on a
# LogEvent (username, status_code, action, dest_port, ...) is source-
# specific and has no dedicated column, so it is folded into the JSONB
# `metadata` column instead of growing the events table schema per log
# source (see consumers/schemas.py for why LogEvent is a single flat
# model in the first place).
_CORE_FIELDS = {
    "event_id",
    "timestamp",
    "source_ip",
    "event_type",
    "severity",
    "source",
    "raw_message",
}

MAX_RETRIES = 3
BASE_BACKOFF_SECONDS = 0.5
MAX_BACKOFF_SECONDS = 4.0
DEFAULT_CHUNK_SIZE = 500


class EventStorageError(RuntimeError):
    """Raised when a save could not be completed after exhausting the
    OperationalError retry budget. Never raised silently -- every retry
    and the final failure are logged before this is raised."""


@dataclass
class StorageStats:
    """Running counters for observability. Not persisted anywhere --
    read `service.stats` from a health-check endpoint or log it
    periodically if you want visibility beyond the per-batch log lines."""

    events_received: int = 0
    events_inserted: int = 0
    events_duplicate: int = 0
    retry_attempts: int = 0
    hard_failures: int = 0


class EventStorageService:
    """Bulk-persists LogEvent objects to the `events` table."""

    def __init__(
        self,
        session_factory: Callable[[], Session] = SessionLocal,
        max_retries: int = MAX_RETRIES,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        self._session_factory = session_factory
        self._max_retries = max_retries
        self._chunk_size = chunk_size
        self.stats = StorageStats()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def save_event(self, event: LogEvent) -> int:
        """Persist a single event. Delegates to save_events_bulk() with a
        one-item list -- there is no separate single-row insert path."""
        return self.save_events_bulk([event])

    def save_events_bulk(self, events: list[LogEvent]) -> int:
        """Bulk-insert events, chunked to at most `chunk_size` rows per
        transaction (never a loop of individual inserts within a chunk).

        Returns the number of rows Postgres actually inserted across all
        chunks, which can be less than len(events) when ON CONFLICT DO
        NOTHING skips duplicate event_ids.
        """
        if not events:
            return 0

        self.stats.events_received += len(events)
        total_inserted = 0

        for start in range(0, len(events), self._chunk_size):
            chunk = events[start : start + self._chunk_size]
            total_inserted += self._insert_chunk(chunk)

        duplicates = len(events) - total_inserted
        self.stats.events_inserted += total_inserted
        self.stats.events_duplicate += duplicates

        logger.info(
            "EventStorageService: inserted %d/%d events (%d duplicate, skipped)",
            total_inserted,
            len(events),
            duplicates,
        )

        return total_inserted

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _insert_chunk(self, events: list[LogEvent]) -> int:
        rows = [self._to_row(event) for event in events]

        stmt = (
            pg_insert(Event.__table__)
            .values(rows)
            .on_conflict_do_nothing(index_elements=["event_id"])
        )

        return self._execute_with_retry(stmt)

    def _to_row(self, event: LogEvent) -> dict:
        metadata = {
            field: _jsonable(value)
            for field, value in event.model_dump(mode="python").items()
            if field not in _CORE_FIELDS and value is not None
        }

        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "source_ip": str(event.source_ip) if event.source_ip else None,
            "event_type": event.event_type,
            "severity": event.severity,
            "source": event.source,
            "raw_message": event.raw_message,
            "metadata": metadata,
        }

    def _execute_with_retry(self, stmt) -> int:
        attempt = 0

        while True:
            attempt += 1
            session = self._session_factory()

            try:
                result = session.execute(stmt)
                session.commit()

                return result.rowcount or 0

            except OperationalError as exc:
                # Transient: connection dropped, pool exhausted, DB
                # unreachable. Worth retrying.
                session.rollback()
                self.stats.retry_attempts += 1

                if attempt > self._max_retries:
                    self.stats.hard_failures += 1

                    logger.error(
                        "EventStorageService: giving up after %d attempt(s) "
                        "(connection error): %s",
                        attempt,
                        exc,
                    )

                    raise EventStorageError(
                        f"Failed to persist events after {attempt} attempt(s): "
                        f"{exc}"
                    ) from exc

                backoff = min(
                    BASE_BACKOFF_SECONDS * (2 ** (attempt - 1)),
                    MAX_BACKOFF_SECONDS,
                )

                backoff += random.uniform(0, backoff * 0.25)

                logger.warning(
                    "EventStorageService: connection error on attempt %d/%d "
                    "(%s); retrying in %.2fs",
                    attempt,
                    self._max_retries + 1,
                    exc,
                    backoff,
                )

                time.sleep(backoff)

            except DBAPIError as exc:
                # Non-transient: IntegrityError, DataError,
                # ProgrammingError, etc. Retrying would not help and
                # would just delay a failure that is going to happen
                # again -- log and raise immediately instead.
                session.rollback()
                self.stats.hard_failures += 1

                logger.error(
                    "EventStorageService: non-transient DB error, not "
                    "retrying: %s",
                    exc,
                )

                raise

            finally:
                session.close()


def _jsonable(value):
    """Best-effort conversion of a LogEvent field into a JSON-serializable
    value for the metadata JSONB column. Literal-based schema values such
    as EventType, Severity, SourceType, FirewallAction, and Protocol are
    already strings; the main conversion needed is for ipaddress objects
    such as dest_ip."""
    if isinstance(value, (str, int, float, bool)):
        return value

    return str(value)