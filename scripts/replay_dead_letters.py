"""Replay Elasticsearch dead-letter events without writing to PostgreSQL."""

import argparse
import logging
import sys
from pathlib import Path

from api.services.dual_sink_writer import DualSinkWriter
from api.services.es_storage_service import ElasticsearchStorageService


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

DEFAULT_DEAD_LETTER = Path(
    "data/es_dead_letter/es-failed-20261016T151038331937Z.jsonl"
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay a dead-letter JSONL file into Elasticsearch."
    )
    parser.add_argument(
        "--file",
        type=Path,
        default=DEFAULT_DEAD_LETTER,
        help="Path to the dead-letter JSONL file.",
    )
    args = parser.parse_args()

    path = args.file

    if not path.is_file():
        print(f"ERROR: Dead-letter file not found: {path}")
        return 1

    line_count = sum(
        1
        for line in path.open("r", encoding="utf-8")
        if line.strip()
    )
    print(f"Dead-letter file: {path}")
    print(f"Events to replay: {line_count}")
    print("Destination: Elasticsearch only")
    print("PostgreSQL writes: disabled")

    es_service = ElasticsearchStorageService()
    writer = DualSinkWriter(
        postgres_write=lambda events: None,
        es_service=es_service,
    )

    try:
        result = writer.replay_dead_letters(path)

        print("\n=== Replay result ===")
        print(f"Events attempted: {result.attempted}")
        print(f"Events indexed:   {result.indexed}")
        print(f"Events failed:    {result.failed}")
        print(f"Dead-letter file remains: {path.exists()}")

        if result.ok:
            print("\nPASS: All events were replayed successfully.")
            return 0

        print("\nPARTIAL FAILURE: The dead-letter file has been preserved.")
        for error in result.errors[:10]:
            print(error)

        return 2

    except Exception:
        logging.exception("Dead-letter replay failed")
        return 1

    finally:
        writer.close()
        es_service.close()


if __name__ == "__main__":
    sys.exit(main())