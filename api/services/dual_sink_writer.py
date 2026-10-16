"""Concurrent PostgreSQL + Elasticsearch writes with recoverable ES failures."""

from __future__ import annotations

import json
import logging
import os
import threading

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from api.services.es_storage_service import (
    BulkResult,
    ElasticsearchStorageService,
)

logger = logging.getLogger(__name__)


@dataclass
class DualWriteResult:
    events_received: int
    postgres_result: Any
    elasticsearch_result: BulkResult
    dead_letter_path: str | None = None


class DualSinkWriter:
    def __init__(
        self,
        postgres_write: Callable[[list[Any]], Any],
        es_service: ElasticsearchStorageService,
        dead_letter_dir: str | Path | None = None,
        max_workers: int = 2,
    ) -> None:
        self.postgres_write = postgres_write
        self.es_service = es_service

        self.dead_letter_dir = Path(
            dead_letter_dir
            or os.getenv(
                "ES_DEAD_LETTER_DIR",
                "data/es_dead_letter",
            )
        )

        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="siem-sink",
        )

        self._lock = threading.Lock()
        self._closed = False

    def write(
        self,
        events: Iterable[Any],
    ) -> DualWriteResult:
        batch = list(events)

        if not batch:
            return DualWriteResult(
                0,
                0,
                BulkResult(),
            )

        with self._lock:
            if self._closed:
                raise RuntimeError(
                    "DualSinkWriter is closed"
                )

        # Start both writes concurrently.
        pg_future = self._executor.submit(
            self.postgres_write,
            batch,
        )

        es_future = self._executor.submit(
            self.es_service.bulk_index,
            batch,
        )

        pg_result = None
        pg_error = None

        try:
            pg_result = pg_future.result()

        except Exception as exc:
            pg_error = exc
            logger.exception(
                "PostgreSQL batch write failed"
            )

        try:
            es_result = es_future.result()

            if not isinstance(es_result, BulkResult):
                raise TypeError(
                    "Elasticsearch bulk_index must return BulkResult"
                )

        except Exception as exc:
            logger.exception(
                "Elasticsearch batch write raised an exception"
            )

            es_result = BulkResult(
                attempted=len(batch),
                failed=len(batch),
                errors=[{"error": str(exc)}],
            )

        dead_letter_path = None

        if not es_result.ok:
            dead_letter_path = self._spill(batch)

            logger.error(
                "Elasticsearch write incomplete: "
                "failed=%d dead_letter=%s",
                es_result.failed,
                dead_letter_path,
            )

        if pg_error is not None:
            raise pg_error

        return DualWriteResult(
            events_received=len(batch),
            postgres_result=pg_result,
            elasticsearch_result=es_result,
            dead_letter_path=dead_letter_path,
        )

    def _spill(self, events: list[Any]) -> str:
        self.dead_letter_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        filename = (
            "es-failed-"
            + datetime.now(timezone.utc).strftime(
                "%Y%m%dT%H%M%S%fZ"
            )
            + ".jsonl"
        )

        path = self.dead_letter_dir / filename

        try:
            with path.open("w", encoding="utf-8") as handle:
                for event in events:
                    if hasattr(event, "model_dump"):
                        payload = event.model_dump(
                            mode="json",
                            exclude_none=True,
                        )
                    elif isinstance(event, dict):
                        payload = event
                    else:
                        payload = vars(event)

                    handle.write(
                        json.dumps(
                            payload,
                            default=str,
                            separators=(",", ":"),
                        )
                        + "\n"
                    )

                handle.flush()
                os.fsync(handle.fileno())

            return str(path)

        except Exception as exc:
            logger.exception(
                "Could not persist Elasticsearch dead-letter batch"
            )

            raise RuntimeError(
                "Elasticsearch failed and dead-letter persistence failed"
            ) from exc

    def replay_dead_letters(
        self,
        path: str | Path,
    ) -> BulkResult:
        path = Path(path)
        events = []

        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if line.strip():
                    try:
                        events.append(json.loads(line))

                    except json.JSONDecodeError as exc:
                        raise ValueError(
                            f"Invalid JSON at {path}:{line_number}"
                        ) from exc

        result = self.es_service.bulk_index(events)

        if result.ok:
            path.unlink(missing_ok=True)

        return result

    def close(self) -> None:
        with self._lock:
            self._closed = True

        self._executor.shutdown(
            wait=True,
            cancel_futures=False,
        )