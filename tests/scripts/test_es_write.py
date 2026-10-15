#!/usr/bin/env python3
"""
Live acceptance checks for the siem-events Elasticsearch index.

Requires a running Elasticsearch instance.

Run after:
    python scripts/init_es.py

Run the checks with:
    python -m pytest tests/scripts/test_es_write.py -v

Or run the script directly:
    python tests/scripts/test_es_write.py --es-url http://localhost:9200

Checks:
    1. Index mappings, strict dynamic mapping, timestamp format,
       and keyword subfields.
    2. ILM policy retention and lifecycle management.
    3. Writing and retrieving test documents.
    4. Severity terms aggregations.
    5. Geo-distance queries.
    6. Rejection of unknown top-level fields.
    7. Acceptance of arbitrary metadata keys without mapping expansion.

All test documents use source="es-mapping-test" and are cleaned up
after execution.
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from elasticsearch import (
    ApiError,
    BadRequestError,
    Elasticsearch,
    TransportError,
)

# ---------------------------------------------------------------------
# Import configuration from scripts/es_mapping.py
# ---------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

for path in (PROJECT_ROOT, SCRIPTS_DIR):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

from es_mapping import (  # noqa: E402
    ALIAS,
    EXPECTED_FIELD_TYPES,
    POLICY_NAME,
    RETENTION,
)

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

TEST_SOURCE = "es-mapping-test"

MUMBAI = {
    "lat": 19.07,
    "lon": 72.87,
}


# ---------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------


class Report:
    """Collect and print acceptance-check results."""

    def __init__(self) -> None:
        self.failures = 0

    def check(
        self,
        name: str,
        ok: bool,
        detail: str = "",
    ) -> bool:
        """Print the result of one check and record failures."""
        status = "PASS" if ok else "FAIL"

        print(
            f"[{status}] {name}"
            + (f" -> {detail}" if detail and not ok else "")
        )

        if not ok:
            self.failures += 1

        return ok


# ---------------------------------------------------------------------
# Test document helpers
# ---------------------------------------------------------------------


def make_doc(
    severity: str = "HIGH",
    **overrides: Any,
) -> dict[str, Any]:
    """Create a representative SIEM event document."""
    document: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": TEST_SOURCE,
        "event_type": "failed_login",
        "severity": severity,
        "source_ip": "203.0.113.10",
        "username": "alice",
        "country": "IN",
        "city": "Mumbai",
        "location": dict(MUMBAI),
        "raw_message": (
            "Failed password for alice from "
            "203.0.113.10 port 22 ssh2"
        ),
        "metadata": {
            "attempt": 3,
            "tags": ["ssh", "auth"],
        },
    }

    document.update(overrides)
    return document


def cleanup(es: Elasticsearch) -> None:
    """
    Delete documents created by this acceptance test.

    Only documents tagged with TEST_SOURCE are deleted.
    """
    es.delete_by_query(
        index=ALIAS,
        query={
            "term": {
                "source": TEST_SOURCE,
            }
        },
        refresh=True,
        conflicts="proceed",
        ignore_unavailable=True,
    )


# ---------------------------------------------------------------------
# Mapping checks
# ---------------------------------------------------------------------


def check_mapping(
    es: Elasticsearch,
    report: Report,
) -> None:
    """Validate mappings on all indices resolved by the write alias."""
    response = es.indices.get_mapping(index=ALIAS)
    mappings_by_index = response.body

    report.check(
        "Alias resolves to at least one index",
        bool(mappings_by_index),
        str(list(mappings_by_index)),
    )

    for index_name, body in mappings_by_index.items():
        mappings = body.get("mappings", {})
        properties = mappings.get("properties", {})

        report.check(
            f"[{index_name}] dynamic == strict",
            mappings.get("dynamic") == "strict",
            str(mappings.get("dynamic")),
        )

        for field, expected_type in EXPECTED_FIELD_TYPES.items():
            actual_type = properties.get(field, {}).get("type")

            report.check(
                f"[{index_name}] {field}: {expected_type}",
                actual_type == expected_type,
                f"got {actual_type}",
            )

        timestamp_format = (
            properties.get("timestamp", {}).get("format")
        )

        report.check(
            f"[{index_name}] timestamp format",
            timestamp_format == "strict_date_optional_time",
            str(timestamp_format),
        )

        raw_message_keyword = (
            properties.get("raw_message", {})
            .get("fields", {})
            .get("keyword", {})
            .get("type")
        )

        report.check(
            f"[{index_name}] raw_message.keyword exists",
            raw_message_keyword == "keyword",
            str(raw_message_keyword),
        )

        severity_keyword = (
            properties.get("severity", {})
            .get("fields", {})
            .get("keyword", {})
            .get("type")
        )

        report.check(
            f"[{index_name}] severity.keyword exists",
            severity_keyword == "keyword",
            str(severity_keyword),
        )


# ---------------------------------------------------------------------
# Index lifecycle management checks
# ---------------------------------------------------------------------


def check_ilm(
    es: Elasticsearch,
    report: Report,
) -> None:
    """Verify the ILM policy and lifecycle management of backing indices."""
    response = es.ilm.get_lifecycle(name=POLICY_NAME)

    policy = (
        response.body[POLICY_NAME]
        .get("policy", {})
        .get("phases", {})
    )

    delete_phase = policy.get("delete", {})
    hot_phase = policy.get("hot", {})
    hot_actions = hot_phase.get("actions", {})

    report.check(
        f"ILM delete.min_age == {RETENTION}",
        delete_phase.get("min_age") == RETENTION,
        str(delete_phase),
    )

    report.check(
        "ILM hot phase contains rollover",
        "rollover" in hot_actions,
        str(hot_actions),
    )

    aliases = es.indices.get_alias(name=ALIAS)

    report.check(
        "Alias has at least one backing index",
        bool(aliases),
        str(list(aliases)),
    )

    for index_name in aliases:
        response = es.ilm.explain_lifecycle(index=index_name)
        info = response.body.get("indices", {}).get(index_name, {})

        report.check(
            f"[{index_name}] managed by {POLICY_NAME}",
            bool(info.get("managed"))
            and info.get("policy") == POLICY_NAME,
            str(info),
        )


# ---------------------------------------------------------------------
# Write, read, aggregation, and geo-distance checks
# ---------------------------------------------------------------------


def check_write_and_read(
    es: Elasticsearch,
    report: Report,
) -> None:
    """Test indexing, retrieval, aggregations, and geo queries."""
    documents = [
        make_doc("HIGH"),
        make_doc("HIGH"),
        make_doc("LOW"),
    ]

    indexed_ids: list[tuple[str, str]] = []

    for document in documents:
        response = es.index(
            index=ALIAS,
            id=document["event_id"],
            document=document,
            refresh=False,
        )

        indexed_ids.append(
            (response["_index"], document["event_id"])
        )

        report.check(
            f"Document indexed: {document['severity']}",
            response.get("result") in {"created", "updated"},
            str(response),
        )

    es.indices.refresh(index=ALIAS)

    # Retrieve the first document from the concrete index where it landed.
    first_index, first_id = indexed_ids[0]

    retrieved = es.get(
        index=first_index,
        id=first_id,
    )

    retrieved_source = retrieved["_source"]

    report.check(
        "Test document retrieved intact",
        retrieved_source.get("event_id") == documents[0]["event_id"]
        and retrieved_source.get("location") == MUMBAI
        and retrieved_source.get("raw_message")
        == documents[0]["raw_message"],
        str(retrieved_source),
    )

    test_query = {
        "term": {
            "source": TEST_SOURCE,
        }
    }

    # Check both keyword and text fields if the mapping supports them.
    for field in ("severity.keyword", "severity"):
        try:
            aggregation_response = es.search(
                index=ALIAS,
                size=0,
                query=test_query,
                aggs={
                    "by_severity": {
                        "terms": {
                            "field": field,
                        }
                    }
                },
            )

            buckets = {
                bucket["key"]: bucket["doc_count"]
                for bucket in aggregation_response[
                    "aggregations"
                ]["by_severity"]["buckets"]
            }

            report.check(
                f"Terms aggregation on {field}",
                buckets == {"HIGH": 2, "LOW": 1},
                str(buckets),
            )

        except ApiError as exc:
            report.check(
                f"Terms aggregation on {field}",
                False,
                str(exc),
            )

    # Confirm that the indexed geo_point field supports geo-distance queries.
    geo_response = es.search(
        index=ALIAS,
        size=0,
        track_total_hits=True,
        query={
            "bool": {
                "filter": [
                    test_query,
                    {
                        "geo_distance": {
                            "distance": "10km",
                            "location": MUMBAI,
                        }
                    },
                ]
            }
        },
    )

    geo_total = geo_response["hits"]["total"]["value"]

    report.check(
        "Geo-distance query matches 3 test documents",
        geo_total == 3,
        str(geo_response["hits"]["total"]),
    )

    # Restrict full-text verification to documents created by this test.
    text_response = es.search(
        index=ALIAS,
        size=0,
        track_total_hits=True,
        query={
            "bool": {
                "filter": [test_query],
                "must": [
                    {
                        "match": {
                            "raw_message": "failed password",
                        }
                    }
                ],
            }
        },
    )

    text_total = text_response["hits"]["total"]["value"]

    report.check(
        "Full-text match on raw_message",
        text_total >= 3,
        str(text_response["hits"]["total"]),
    )


# ---------------------------------------------------------------------
# Strict mapping and metadata checks
# ---------------------------------------------------------------------


def check_strictness(
    es: Elasticsearch,
    report: Report,
) -> None:
    """Check strict dynamic mapping and arbitrary metadata handling."""

    # An unknown top-level field should be rejected.
    try:
        es.index(
            index=ALIAS,
            document=make_doc(bogus_field="x"),
            refresh=True,
        )

        report.check(
            "Unknown top-level field rejected",
            False,
            "Document was unexpectedly accepted",
        )

    except BadRequestError as exc:
        report.check(
            "Unknown top-level field rejected",
            "strict_dynamic_mapping_exception" in str(exc),
            str(exc),
        )

    # Metadata keys should not expand the top-level mapping when metadata
    # is mapped as an appropriate object type, such as flattened.
    before_response = es.indices.get_mapping(index=ALIAS)
    before_mappings = before_response.body

    big_metadata = {
        f"key_{i}": {
            "nested": i,
        }
        for i in range(300)
    }

    try:
        document = make_doc(metadata=big_metadata)

        es.index(
            index=ALIAS,
            id=document["event_id"],
            document=document,
            refresh=True,
        )

        after_response = es.indices.get_mapping(index=ALIAS)
        after_mappings = after_response.body

        report.check(
            "300 arbitrary metadata keys accepted without mapping expansion",
            before_mappings == after_mappings,
            "Mapping changed or remained unchanged",
        )

    except ApiError as exc:
        report.check(
            "300 arbitrary metadata keys accepted without mapping expansion",
            False,
            str(exc),
        )


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Run all Elasticsearch acceptance checks."""
    parser = argparse.ArgumentParser(
        description="Live acceptance checks for siem-events"
    )

    parser.add_argument(
        "--es-url",
        default=os.getenv(
            "ES_URL",
            "http://localhost:9200",
        ),
        help="Elasticsearch URL (default: ES_URL or localhost:9200)",
    )

    args = parser.parse_args(argv)

    report = Report()

    es = Elasticsearch(
        args.es_url,
        request_timeout=30,
    )

    try:
        if not es.ping():
            print(
                f"Cannot connect to Elasticsearch at {args.es_url}",
                file=sys.stderr,
            )
            return 2

        if not es.indices.exists_alias(name=ALIAS):
            print(
                f"Alias '{ALIAS}' not found. "
                "Run `python scripts/init_es.py` first.",
                file=sys.stderr,
            )
            return 2

        # Remove leftovers from a previous run.
        cleanup(es)

        check_mapping(es, report)
        check_ilm(es, report)
        check_write_and_read(es, report)
        check_strictness(es, report)

    except (ApiError, TransportError) as exc:
        print(
            f"Elasticsearch error: {exc}",
            file=sys.stderr,
        )
        return 2

    finally:
        try:
            cleanup(es)
        except (ApiError, TransportError) as exc:
            print(
                f"WARNING: Could not remove test documents: {exc}",
                file=sys.stderr,
            )

        es.close()

    if report.failures == 0:
        print("\nALL CHECKS PASSED")
        return 0

    print(f"\n{report.failures} CHECK(S) FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())