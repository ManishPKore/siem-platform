#!/usr/bin/env python3
"""Initialize the siem-events Elasticsearch index.

The script is idempotent. Existing indices are verified and left unchanged
unless --recreate is supplied.

Usage:
    python scripts/init_es.py
    python scripts/init_es.py --host http://localhost:9200
    python scripts/init_es.py --recreate

Environment:
    ES_HOST: Elasticsearch URL (default: http://localhost:9200)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from typing import Any

from elasticsearch import (
    ApiError,
    BadRequestError,
    ConnectionError as ESConnectionError,
    ConnectionTimeout,
    Elasticsearch,
)

logger = logging.getLogger("init_es")

DEFAULT_HOST = "http://localhost:9200"
INDEX_NAME = "siem-events"

INDEX_BODY: dict[str, Any] = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "5s",
    },
    "mappings": {
        "dynamic": "false",
        "properties": {
            "timestamp": {
                "type": "date",
                "format": "strict_date_optional_time||epoch_millis",
            },
            "source_ip": {"type": "keyword"},
            "event_type": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "country": {"type": "keyword"},
            "raw_message": {"type": "text"},
        },
    },
}

EXPECTED_TYPES = {
    name: spec["type"]
    for name, spec in INDEX_BODY["mappings"]["properties"].items()
}


def wait_for_cluster(
    client: Elasticsearch,
    timeout_s: int,
) -> None:
    """Wait until Elasticsearch reports a green or yellow cluster status."""
    if timeout_s < 1:
        raise ValueError("timeout_s must be at least 1 second")

    deadline = time.monotonic() + timeout_s
    attempt = 0
    last_error: Exception | None = None

    while time.monotonic() < deadline:
        attempt += 1

        remaining = deadline - time.monotonic()
        request_timeout = max(1, min(5, int(remaining)))

        try:
            health = client.options(
                request_timeout=request_timeout
            ).cluster.health(
                wait_for_status="yellow",
                timeout=f"{request_timeout}s",
            )

            status = health.get("status")

            if status in {"green", "yellow"}:
                logger.info("Elasticsearch cluster status: %s", status)
                return

            last_error = RuntimeError(
                f"Unexpected Elasticsearch cluster status: {status}"
            )

        except (ESConnectionError, ConnectionTimeout, ApiError) as exc:
            last_error = exc

        remaining = deadline - time.monotonic()

        if remaining > 0:
            logger.info(
                "Waiting for Elasticsearch (attempt %d); %.1f seconds remaining",
                attempt,
                remaining,
            )
            time.sleep(min(2, remaining))

    raise TimeoutError(
        f"Elasticsearch did not become ready within {timeout_s} seconds. "
        f"Last error: {last_error}"
    ) from last_error


def verify_mapping(
    client: Elasticsearch,
    index: str,
) -> list[str]:
    """Return human-readable differences from the expected index mapping."""
    response = client.indices.get_mapping(index=index)
    mappings = response[index]["mappings"]

    problems: list[str] = []
    actual_properties = mappings.get("properties", {})

    for field, expected_type in EXPECTED_TYPES.items():
        actual_type = actual_properties.get(field, {}).get("type")

        if actual_type != expected_type:
            problems.append(
                f"{field}: expected {expected_type}, found {actual_type}"
            )

    expected_dynamic = INDEX_BODY["mappings"]["dynamic"]

    if mappings.get("dynamic", True) != expected_dynamic:
        problems.append(
            f"dynamic: expected {expected_dynamic}, "
            f"found {mappings.get('dynamic', True)}"
        )

    settings = client.indices.get_settings(
        index=index,
        flat_settings=True,
    )

    actual_settings = settings[index].get("settings", {})
    expected_settings = INDEX_BODY["settings"]

    for setting, expected_value in expected_settings.items():
        actual_value = actual_settings.get(f"index.{setting}")

        if (
            actual_value is not None
            and str(actual_value) != str(expected_value)
        ):
            problems.append(
                f"{setting}: expected {expected_value}, found {actual_value}"
            )

    return problems


def ensure_index(
    client: Elasticsearch,
    index: str = INDEX_NAME,
    recreate: bool = False,
) -> bool:
    """Create the index if necessary; return True when this call creates it."""
    exists = client.indices.exists(index=index)

    if exists and recreate:
        logger.warning(
            "Deleting existing index '%s' because --recreate was supplied",
            index,
        )
        client.indices.delete(index=index)
        exists = False

    if exists:
        problems = verify_mapping(client, index)

        if problems:
            raise RuntimeError(
                f"Index '{index}' has an incompatible configuration: "
                + "; ".join(problems)
                + ". Use --recreate only if deleting existing index data "
                "is acceptable."
            )

        logger.info(
            "Index '%s' already exists with the expected configuration",
            index,
        )
        return False

    try:
        client.indices.create(
            index=index,
            settings=INDEX_BODY["settings"],
            mappings=INDEX_BODY["mappings"],
        )

    except BadRequestError as exc:
        # Another process may have created the index between the existence
        # check and the create operation. Inspect the structured error body
        # because exc.error contains the message, not necessarily the error type.
        error_body = (
            exc.body.get("error", {})
            if isinstance(exc.body, dict)
            else {}
        )

        error_type = (
            error_body.get("type")
            if isinstance(error_body, dict)
            else None
        )

        if error_type == "resource_already_exists_exception":
            logger.info("Index '%s' was created concurrently", index)

            # Verify the concurrently created index before treating the
            # operation as successful.
            problems = verify_mapping(client, index)

            if problems:
                raise RuntimeError(
                    f"Concurrent index creation produced an incompatible "
                    f"configuration: {'; '.join(problems)}"
                ) from exc

            return False

        raise

    logger.info("Created index '%s'", index)
    return True


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "--host",
        default=os.getenv("ES_HOST", DEFAULT_HOST),
        help="Elasticsearch URL; defaults to ES_HOST or localhost:9200",
    )

    parser.add_argument(
        "--index",
        default=INDEX_NAME,
        help="Index name (default: siem-events)",
    )

    parser.add_argument(
        "--recreate",
        action="store_true",
        help="Delete and recreate the index; existing index data will be lost",
    )

    parser.add_argument(
        "--wait-timeout",
        type=int,
        default=60,
        help="Maximum seconds to wait for Elasticsearch (default: 60)",
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the Elasticsearch index initialization."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    args = parse_args(argv)

    if args.wait_timeout < 1:
        logger.error("--wait-timeout must be at least 1 second")
        return 2

    client = Elasticsearch(
        args.host,
        request_timeout=5,
        max_retries=0,
    )

    try:
        wait_for_cluster(client, args.wait_timeout)

        ensure_index(
            client,
            index=args.index,
            recreate=args.recreate,
        )

        logger.info("Elasticsearch index initialization completed")
        return 0

    except TimeoutError as exc:
        logger.error("%s", exc)
        return 1

    except RuntimeError as exc:
        logger.error("%s", exc)
        return 1

    except (ApiError, ESConnectionError, ConnectionTimeout) as exc:
        logger.error("Elasticsearch operation failed: %s", exc)
        return 1

    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())