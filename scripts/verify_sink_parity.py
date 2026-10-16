"""Compare PostgreSQL and Elasticsearch counts."""

from __future__ import annotations

import argparse
import os
import re

from datetime import datetime, timedelta, timezone

from elasticsearch import Elasticsearch
from sqlalchemy import text

from api.database import SessionLocal
from api.services.es_storage_service import build_client_from_env


IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def safe_identifier(value: str) -> str:
    if not IDENTIFIER.fullmatch(value):
        raise ValueError(
            f"Invalid SQL identifier: {value!r}"
        )

    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__
    )

    parser.add_argument(
        "--table",
        default="events",
    )

    parser.add_argument(
        "--column",
        default="timestamp",
    )

    parser.add_argument(
        "--index",
        default=os.getenv(
            "ES_INDEX",
            "siem-events",
        ),
    )

    parser.add_argument(
        "--minutes",
        type=int,
        default=None,
    )

    parser.add_argument(
        "--tolerance",
        type=float,
        default=0.01,
    )

    args = parser.parse_args()

    if args.minutes is not None and args.minutes < 1:
        parser.error("--minutes must be >= 1")

    if not 0 <= args.tolerance <= 1:
        parser.error(
            "--tolerance must be between 0 and 1"
        )

    table = safe_identifier(args.table)
    column = safe_identifier(args.column)

    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(minutes=args.minutes)
        if args.minutes
        else None
    )

    db = SessionLocal()
    client = build_client_from_env()

    try:
        sql = f"SELECT count(*) FROM {table}"
        params = {}

        if cutoff:
            sql += f" WHERE {column} >= :cutoff"
            params["cutoff"] = cutoff

        pg_count = int(
            db.execute(
                text(sql),
                params,
            ).scalar_one()
        )

        query = (
            {"match_all": {}}
            if cutoff is None
            else {
                "range": {
                    "timestamp": {
                        "gte": cutoff.isoformat()
                    }
                }
            }
        )

        es_count = int(
            client.count(
                index=args.index,
                query=query,
            )["count"]
        )

    finally:
        db.close()
        client.close()

    difference = (
        abs(pg_count - es_count)
        / max(pg_count, es_count, 1)
    )

    print(f"PostgreSQL: {pg_count}")
    print(f"Elasticsearch: {es_count}")

    print(
        f"Difference: {difference:.2%} "
        f"(allowed {args.tolerance:.2%})"
    )

    print(
        "PASS"
        if difference <= args.tolerance
        else "FAIL"
    )

    return (
        0
        if difference <= args.tolerance
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())