#!/usr/bin/env python3
"""Initialize Elasticsearch for the SIEM: ILM policy, index template, write alias.

The script is idempotent. An existing, correctly configured setup is verified
and left unchanged unless --recreate is supplied.

What it provisions (definitions live in scripts/es_mapping.py):
    * ILM policy      siem-events-policy    (hot rollover -> delete after 7 days)
    * Index template  siem-events-template  (strict mapping, applies to siem-events-*)
    * Bootstrap index siem-events-000001 with write alias `siem-events`

Usage:
    python scripts/init_es.py
    python scripts/init_es.py --host http://localhost:9200 --replicas 0
    python scripts/init_es.py --recreate

Environment:
    ES_HOST (or ES_URL): Elasticsearch URL (default: http://localhost:9200)

Legacy note:
    Earlier versions created a concrete index named `siem-events`. An alias cannot
    share a name with an index, so that index blocks setup until it is removed.
    --recreate deletes it (and every index behind the alias): DATA LOSS, dev only.
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

from es_mapping import (
    ALIAS,
    EXPECTED_FIELD_TYPES,
    FIRST_INDEX,
    ILM_POLICY,
    MAPPINGS,
    POLICY_NAME,
    TEMPLATE_NAME,
    build_template,
)

logger = logging.getLogger("init_es")

DEFAULT_HOST = "http://localhost:9200"


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


def ensure_ilm_policy(client: Elasticsearch) -> None:
    """Create or update the ILM policy (PUT is idempotent)."""
    client.ilm.put_lifecycle(name=POLICY_NAME, policy=ILM_POLICY)
    logger.info("ILM policy '%s' applied", POLICY_NAME)


def ensure_index_template(client: Elasticsearch, replicas: int = 0) -> None:
    """Create or update the composable index template (PUT is idempotent)."""
    client.indices.put_index_template(
        name=TEMPLATE_NAME,
        **build_template(replicas=replicas),
    )
    logger.info("Index template '%s' applied", TEMPLATE_NAME)


def _alias_indices(client: Elasticsearch, alias: str = ALIAS) -> dict[str, Any]:
    """Return {backing_index: alias_info} for the alias."""
    response = client.indices.get_alias(name=alias)
    return {name: response[name] for name in response}


def get_write_index(client: Elasticsearch, alias: str = ALIAS) -> str:
    """Return the index that currently receives writes for the alias."""
    indices = _alias_indices(client, alias)

    for name, info in indices.items():
        if info.get("aliases", {}).get(alias, {}).get("is_write_index"):
            return name

    if len(indices) == 1:
        return next(iter(indices))

    raise RuntimeError(
        f"Alias '{alias}' has no write index among {sorted(indices)}"
    )


def verify_mapping(
    client: Elasticsearch,
    index: str,
    replicas: int = 0,
) -> list[str]:
    """Return human-readable differences from the expected configuration."""
    mappings = client.indices.get_mapping(index=index)[index]["mappings"]
    props = mappings.get("properties", {})

    problems: list[str] = []

    for field, expected_type in EXPECTED_FIELD_TYPES.items():
        actual_type = props.get(field, {}).get("type")

        if actual_type != expected_type:
            problems.append(
                f"{field}: expected {expected_type}, found {actual_type}"
            )

    expected_dynamic = MAPPINGS["dynamic"]

    if mappings.get("dynamic") != expected_dynamic:
        problems.append(
            f"dynamic: expected {expected_dynamic}, "
            f"found {mappings.get('dynamic')}"
        )

    expected_format = MAPPINGS["properties"]["timestamp"]["format"]
    actual_format = props.get("timestamp", {}).get("format")

    if actual_format != expected_format:
        problems.append(
            f"timestamp.format: expected {expected_format}, found {actual_format}"
        )

    for field in ("raw_message", "severity"):
        sub_type = (
            props.get(field, {}).get("fields", {}).get("keyword", {}).get("type")
        )

        if sub_type != "keyword":
            problems.append(
                f"{field}.keyword: expected keyword, found {sub_type}"
            )

    settings = client.indices.get_settings(
        index=index,
        flat_settings=True,
    )[index].get("settings", {})

    expected_settings = {
        "index.number_of_replicas": replicas,
        "index.lifecycle.name": POLICY_NAME,
        "index.lifecycle.rollover_alias": ALIAS,
    }

    for setting, expected_value in expected_settings.items():
        actual_value = settings.get(setting)

        if actual_value is None or str(actual_value) != str(expected_value):
            problems.append(
                f"{setting}: expected {expected_value}, found {actual_value}"
            )

    return problems


def verify_ilm(client: Elasticsearch) -> None:
    """Raise unless ILM manages every backing index with the expected policy."""
    for index in _alias_indices(client):
        info = client.ilm.explain_lifecycle(index=index)["indices"][index]

        if not info.get("managed") or info.get("policy") != POLICY_NAME:
            raise RuntimeError(
                f"ILM is not managing '{index}' with '{POLICY_NAME}': {info}"
            )

        logger.info(
            "ILM OK: '%s' managed by '%s' (phase=%s)",
            index,
            POLICY_NAME,
            info.get("phase"),
        )


def _raise_if_incompatible(client: Elasticsearch, replicas: int, context: str) -> None:
    index = get_write_index(client)
    problems = verify_mapping(client, index, replicas)

    if problems:
        raise RuntimeError(
            f"{context} '{index}' has an incompatible configuration: "
            + "; ".join(problems)
            + ". Roll over to pick up the current template "
            "(POST siem-events/_rollover) or use --recreate only if deleting "
            "existing index data is acceptable."
        )


def ensure_index(
    client: Elasticsearch,
    replicas: int = 0,
    recreate: bool = False,
) -> bool:
    """Ensure the write alias and first backing index exist.

    Returns True when this call creates the bootstrap index.
    """
    alias_exists = bool(client.indices.exists_alias(name=ALIAS))

    if alias_exists and recreate:
        for name in list(_alias_indices(client)):
            logger.warning(
                "Deleting index '%s' because --recreate was supplied", name
            )
            client.indices.delete(index=name)
        alias_exists = False

    if alias_exists:
        _raise_if_incompatible(client, replicas, "Write index")
        logger.info(
            "Alias '%s' already exists with the expected configuration", ALIAS
        )
        return False

    if client.indices.exists(index=ALIAS):
        # A concrete (legacy) index occupies the alias name.
        if not recreate:
            raise RuntimeError(
                f"A legacy concrete index named '{ALIAS}' exists and blocks the "
                "write alias. Reindex it into "
                f"'{FIRST_INDEX}' or use --recreate if deleting its data is "
                "acceptable."
            )

        logger.warning(
            "Deleting legacy index '%s' because --recreate was supplied", ALIAS
        )
        client.indices.delete(index=ALIAS)

    try:
        client.indices.create(
            index=FIRST_INDEX,
            aliases={ALIAS: {"is_write_index": True}},
        )

    except BadRequestError as exc:
        # Another process may have created the index between the existence
        # check and the create operation. Inspect the structured error body
        # because exc.error contains the message, not necessarily the error type.
        error_body = exc.body.get("error", {}) if isinstance(exc.body, dict) else {}
        error_type = error_body.get("type") if isinstance(error_body, dict) else None

        if error_type == "resource_already_exists_exception":
            logger.info("Index '%s' was created concurrently", FIRST_INDEX)

            try:
                _raise_if_incompatible(client, replicas, "Concurrently created index")
            except RuntimeError as inner:
                raise RuntimeError(
                    f"Concurrent index creation produced an incompatible "
                    f"configuration: {inner}"
                ) from exc

            return False

        raise

    logger.info("Created '%s' with write alias '%s'", FIRST_INDEX, ALIAS)
    return True


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "--host",
        default=os.getenv("ES_HOST") or os.getenv("ES_URL") or DEFAULT_HOST,
        help="Elasticsearch URL; defaults to ES_HOST/ES_URL or localhost:9200",
    )

    parser.add_argument(
        "--replicas",
        type=int,
        default=0,
        help="Replica count; 0 for the single-node Docker stack (default: 0)",
    )

    parser.add_argument(
        "--recreate",
        action="store_true",
        help="Delete the alias's indices (and any legacy 'siem-events' index) "
        "and recreate; existing data will be lost",
    )

    parser.add_argument(
        "--wait-timeout",
        type=int,
        default=60,
        help="Maximum seconds to wait for Elasticsearch (default: 60)",
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the Elasticsearch initialization."""
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
        ensure_ilm_policy(client)
        ensure_index_template(client, replicas=args.replicas)
        ensure_index(client, replicas=args.replicas, recreate=args.recreate)
        verify_ilm(client)

        logger.info("Elasticsearch initialization completed")
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