"""
consumers/run_consumer.py

Entry point that wires the Kafka log consumer (Issue #5) to the storage
service (Issue #7) and runs the pipeline end to end:

    python -m consumers.run_consumer
    python -m consumers.run_consumer --batch-size 100

Default mode (no --batch-size): each validated LogEvent is handed to
EventStorageService.save_event() one at a time. Per the Issue #5 design,
LogConsumer only commits a message's offset after the handler returns --
so with this default, a message is never marked "done" until it is
durably in Postgres (or EventStorageError propagates and the consumer
should stop rather than skip-and-commit).

--batch-size mode: events are buffered in memory and flushed via
EventStorageService.save_events_bulk() once BATCH_SIZE events have
accumulated (see BatchingHandler below). This is what actually satisfies
"bulk insert handles batches of N events in a single transaction" against
the live pipeline rather than only in a unit test. The trade-off: if the
process crashes after LogConsumer has committed offsets for messages
that are still sitting in the in-memory buffer (not yet flushed), those
events are lost even though Kafka considers them "consumed". That window
is at most (batch_size - 1) events. If that's not acceptable for your
use case, use the default per-event mode instead, or use --batch-size
only once you can flush the buffer before the offset commit happens
(needs offset-commit control in LogConsumer that isn't currently
exposed here). This trade-off is inherent to buffering ahead of an
already-committing consumer -- it isn't something that can be papered
over in this file alone.

NOTE: this assumes LogConsumer accepts a `handler` callable in its
constructor alongside `config`, per the Issue #5 description ("call
downstream handler"). Adjust the constructor call below if your actual
LogConsumer signature differs (e.g. handler passed to .run() instead).
"""

from __future__ import annotations

import argparse
import logging
import time

from api.services.storage_service import EventStorageService
from consumers.log_consumer import ConsumerConfig, LogConsumer
from consumers.schemas import LogEvent

logger = logging.getLogger(__name__)


class BatchingHandler:
    """Buffers events and flushes to EventStorageService.save_events_bulk()
    once `batch_size` events have accumulated, or `flush_interval_seconds`
    have elapsed since the last flush (whichever comes first) -- so a
    slow trickle of events doesn't sit in memory indefinitely waiting to
    reach batch_size. See the data-loss trade-off documented above before
    using this instead of the default per-event handler.
    """

    def __init__(
        self,
        storage: EventStorageService,
        batch_size: int = 100,
        flush_interval_seconds: float = 5.0,
    ) -> None:
        self._storage = storage
        self._batch_size = batch_size
        self._flush_interval = flush_interval_seconds
        self._buffer: list[LogEvent] = []
        self._last_flush = time.monotonic()

    def __call__(self, event: LogEvent) -> None:
        self._buffer.append(event)
        due_by_size = len(self._buffer) >= self._batch_size
        due_by_time = (time.monotonic() - self._last_flush) >= self._flush_interval
        if due_by_size or due_by_time:
            self.flush()

    def flush(self) -> int:
        if not self._buffer:
            return 0
        events, self._buffer = self._buffer, []
        self._last_flush = time.monotonic()
        return self._storage.save_events_bulk(events)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the SIEM Kafka consumer -> storage pipeline")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=None,
        help=(
            "Buffer and bulk-insert events in batches of this size instead "
            "of writing one at a time. See this file's module docstring "
            "for the data-loss trade-off before enabling this."
        ),
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    storage = EventStorageService()
    config = ConsumerConfig.from_env()

    if args.batch_size:
        logger.warning(
            "Batching enabled (batch_size=%d): up to %d events may be lost "
            "on a crash between Kafka offset commit and DB flush. See "
            "run_consumer.py's module docstring.",
            args.batch_size,
            args.batch_size - 1,
        )
        handler = BatchingHandler(storage, batch_size=args.batch_size)
    else:
        handler = storage.save_event

    consumer = LogConsumer(config=config, handler=handler)

    logger.info(
        "Starting consumer -> storage pipeline (topic=%s, group_id=%s, batching=%s)",
        config.topic,
        config.group_id,
        bool(args.batch_size),
    )
    consumer.run()


if __name__ == "__main__":
    main()