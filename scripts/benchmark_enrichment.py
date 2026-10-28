#!/usr/bin/env python3
"""Benchmark and load-test the enrichment stage against the issue's targets.

    python scripts/benchmark_enrichment.py micro            # per-event latency
    python scripts/benchmark_enrichment.py spark --cores 4  # pipeline throughput
    python scripts/benchmark_enrichment.py kafka --bootstrap localhost:9092

Targets (exit code 1 if missed, so it can gate CI):
    * enrichment latency   < 10 ms per event
    * pipeline throughput  >= 500 events/second (on a 4-core machine)
    * end-to-end latency   < 10 s  (log generated -> enriched event in Kafka)

micro   In-process ``PipelineEnricher`` on a realistic IP mix (private
        traffic, repeated attacker IPs with a skewed distribution). Uses the
        real GeoLite2 databases if present in data/, otherwise generates
        synthetic ones. AbuseIPDB is SIMULATED with a fixed latency
        (--api-latency-ms) so the benchmark is repeatable and burns no quota.
        Reports the batch path the Spark UDF uses and the single-event path.

spark   Raw JSON events -> parse -> normalize -> validate -> unified
        enrichment -> Kafka payload, on a local Spark with --cores cores, with
        a no-op sink (everything except Kafka transport). Reputation runs on
        the local blocklist only: a mocked API cannot cross into Spark's
        Python worker processes, so API latency is covered by ``micro``.

kafka   The real end-to-end test (needs the docker stack and a running
        spark_consumer): produces events to logs-raw at --rate and reads
        logs-enriched, measuring throughput and end-to-end latency as
        (time the enriched message was consumed) - (event timestamp).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import statistics
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

LATENCY_TARGET_MS = 10.0
THROUGHPUT_TARGET_EPS = 500.0
E2E_TARGET_SECONDS = 10.0


# --------------------------------------------------------------------------- #
# Helpers (pure, unit-tested)
# --------------------------------------------------------------------------- #


def percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile (pct in 0-100) of a non-empty list."""
    if not values:
        raise ValueError("percentile of an empty list")
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100.0 * len(ordered)))
    return ordered[rank - 1]


def summarize(values_ms: list[float]) -> dict[str, float]:
    return {
        "mean": statistics.fmean(values_ms),
        "p50": percentile(values_ms, 50),
        "p95": percentile(values_ms, 95),
        "p99": percentile(values_ms, 99),
        "max": max(values_ms),
    }


def make_ip_pool(distinct: int, seed: int = 7) -> list[str]:
    """Deterministic pool of distinct *public* IPv4 addresses."""
    rng = random.Random(seed)
    pool: set[str] = set()
    while len(pool) < distinct:
        first = rng.choice([11, 23, 31, 45, 62, 77, 91, 104, 141, 185, 193, 203])
        pool.add(f"{first}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}")
    return sorted(pool)


def make_traffic(
    events: int, pool: list[str], private_ratio: float, seed: int = 11
) -> list[str]:
    """Source IPs: ``private_ratio`` private, the rest from ``pool`` with a
    Zipf-like skew (a few noisy attackers, a long tail), like real traffic."""
    rng = random.Random(seed)
    weights = [1.0 / (rank + 1) for rank in range(len(pool))]
    publics = rng.choices(pool, weights=weights, k=events)
    ips = []
    for public in publics:
        if rng.random() < private_ratio:
            ips.append(f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}")
        else:
            ips.append(public)
    return ips


class SimulatedAbuseIPDB:
    """requests.Session stand-in with fixed latency and deterministic scores."""

    def __init__(self, latency_ms: float) -> None:
        self._latency = latency_ms / 1000.0
        self.calls = 0
        self._lock = threading.Lock()

    def get(self, url: str, **kwargs: Any) -> Any:
        with self._lock:
            self.calls += 1
        time.sleep(self._latency)
        ip = kwargs["params"]["ipAddress"]
        score = (sum(map(ord, ip)) * 7) % 100
        payload = {
            "data": {
                "abuseConfidenceScore": score,
                "reports": [{"categories": [18, 22]}] if score >= 50 else [],
            }
        }
        return type(
            "SimulatedResponse",
            (),
            {"status_code": 200, "headers": {}, "json": lambda self: payload},
        )()

    def close(self) -> None:
        pass


def _verdict(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


# --------------------------------------------------------------------------- #
# Databases
# --------------------------------------------------------------------------- #


def prepare_databases(pool: list[str], workdir: Path) -> tuple[Path, Path, str]:
    """Return (city_db, asn_db, description): the real GeoLite2 files if both
    exist in data/, otherwise synthetic MaxMind-format ones covering the pool."""
    real_city = REPO_ROOT / "data" / "GeoLite2-City.mmdb"
    real_asn = REPO_ROOT / "data" / "GeoLite2-ASN.mmdb"
    if real_city.is_file() and real_asn.is_file():
        return real_city, real_asn, "real GeoLite2 databases"

    try:
        import mmdb_writer
        from netaddr import IPSet
    except ImportError as exc:  # pragma: no cover - dev dependency
        raise SystemExit(
            "No GeoLite2 databases in data/ and mmdb-writer is not installed "
            f"(pip install -r requirements-dev.txt): {exc}"
        )

    city = mmdb_writer.MMDBWriter(
        ip_version=4, database_type="GeoIP2-City", languages=["en"],
        description={"en": "benchmark"},
    )
    asn = mmdb_writer.MMDBWriter(
        ip_version=6, ipv4_compatible=True, database_type="GeoLite2-ASN",
        languages=["en"], description={"en": "benchmark"},
    )
    for i, ip in enumerate(pool):
        city.insert_network(
            IPSet([f"{ip}/32"]),
            {
                "country": {"iso_code": "US", "names": {"en": "US"}},
                "city": {"names": {"en": f"City{i % 500}"}},
                "location": {"latitude": 37.0 + (i % 90) / 10, "longitude": -122.0 + (i % 90) / 10},
            },
        )
        asn.insert_network(
            IPSet([f"{ip}/32"]),
            {
                "autonomous_system_number": 64512 + i % 1000,
                "autonomous_system_organization": f"ORG-{i % 1000}",
            },
        )
    city_path, asn_path = workdir / "bench-city.mmdb", workdir / "bench-asn.mmdb"
    city.to_db_file(str(city_path))
    asn.to_db_file(str(asn_path))
    return city_path, asn_path, "synthetic MaxMind-format databases"


# --------------------------------------------------------------------------- #
# micro
# --------------------------------------------------------------------------- #


def run_micro(args: argparse.Namespace) -> int:
    from enrichment.asn import ASNEnricher
    from enrichment.geoip import GeoIPEnricher
    from enrichment.ip_reputation import IPReputationEnricher
    from enrichment.pipeline_enricher import PipelineEnricher

    pool = make_ip_pool(args.distinct_ips)
    ips = make_traffic(args.events, pool, args.private_ratio)

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        city_db, asn_db, db_desc = prepare_databases(pool, workdir)
        blocklist = workdir / "bad.txt"
        blocklist.write_text("\n".join(pool[: max(1, len(pool) // 50)]) + "\n")

        def build() -> tuple[PipelineEnricher, SimulatedAbuseIPDB]:
            session = SimulatedAbuseIPDB(args.api_latency_ms)
            enricher = PipelineEnricher(
                geoip=GeoIPEnricher(city_db),
                asn=ASNEnricher(asn_db),
                reputation=IPReputationEnricher(
                    api_key="benchmark", session=session,
                    blocklist_path=blocklist, daily_limit=None,
                ),
            )
            return enricher, session

        print(f"events={args.events} distinct_public_ips={args.distinct_ips} "
              f"private={args.private_ratio:.0%} batch={args.batch_size}")
        print(f"databases: {db_desc}; AbuseIPDB: SIMULATED, "
              f"{args.api_latency_ms:.0f} ms per call\n")

        # --- batch path (what the Spark UDF runs)
        enricher, session = build()
        per_event_ms: list[float] = []
        batch_ms: list[float] = []
        started = time.perf_counter()
        for i in range(0, len(ips), args.batch_size):
            batch = ips[i:i + args.batch_size]
            t0 = time.perf_counter()
            enricher.enrich_many(batch)
            elapsed = (time.perf_counter() - t0) * 1000
            batch_ms.append(elapsed)
            per_event_ms.extend([elapsed / len(batch)] * len(batch))
        total = time.perf_counter() - started
        batch_stats = summarize(per_event_ms)
        eps = len(ips) / total
        enricher.close()

        print("BATCH path (Spark UDF): amortised per-event latency")
        print(f"  mean {batch_stats['mean']:.3f} ms | p50 {batch_stats['p50']:.3f} | "
              f"p95 {batch_stats['p95']:.3f} | p99 {batch_stats['p99']:.3f} | "
              f"max {batch_stats['max']:.3f}")
        print(f"  slowest batch {max(batch_ms):.0f} ms | throughput {eps:,.0f} events/s | "
              f"API calls {session.calls}")

        # --- single-event path (cold start: every first sighting pays the API)
        enricher, session = build()
        single_ms = []
        for ip in ips[: min(len(ips), 5000)]:
            t0 = time.perf_counter()
            enricher.enrich(ip)
            single_ms.append((time.perf_counter() - t0) * 1000)
        single = summarize(single_ms)
        enricher.close()
        print("\nSINGLE-event path (sequential, cold cache; each first sighting "
              "waits for the API)")
        print(f"  mean {single['mean']:.3f} ms | p50 {single['p50']:.3f} | "
              f"p95 {single['p95']:.3f} | p99 {single['p99']:.3f} | "
              f"max {single['max']:.3f}  (API calls {session.calls})")

    ok = batch_stats["mean"] < LATENCY_TARGET_MS
    print(f"\n{_verdict(ok)}: batch-path mean {batch_stats['mean']:.3f} ms/event "
          f"(target < {LATENCY_TARGET_MS:.0f} ms)")
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# spark
# --------------------------------------------------------------------------- #


def run_spark(args: argparse.Namespace) -> int:
    os.environ.setdefault("PYSPARK_PYTHON", sys.executable)
    os.environ.setdefault("PYSPARK_DRIVER_PYTHON", sys.executable)
    os.environ.pop("ABUSEIPDB_API_KEY", None)  # blocklist-only: see module docstring
    os.environ.setdefault("POSTGRES_URL", "postgresql+psycopg2://bench:bench@localhost/bench")

    from pyspark.sql import SparkSession
    from pyspark.sql.types import (LongType, StringType, StructField,
                                   StructType, TimestampType)

    from consumers.enriched_events import build_enriched_payload
    from consumers.spark_consumer import (_executor_python_path,
                                          build_enrichment_stage,
                                          parse_normalize_and_validate)

    pool = make_ip_pool(args.distinct_ips)
    ips = make_traffic(args.events, pool, args.private_ratio)

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        city_db, asn_db, db_desc = prepare_databases(pool, workdir)
        blocklist = workdir / "bad.txt"
        blocklist.write_text("\n".join(pool[: max(1, len(pool) // 50)]) + "\n")

        spark = (
            SparkSession.builder.master(f"local[{args.cores}]")
            .appName("enrichment-benchmark")
            .config("spark.ui.enabled", "false")
            .config("spark.sql.session.timeZone", "UTC")
            .config("spark.sql.shuffle.partitions", str(args.cores))
            .config("spark.executorEnv.PYTHONPATH", _executor_python_path())
            .getOrCreate()
        )
        spark.sparkContext.setLogLevel("ERROR")

        schema = StructType([
            StructField("value", StringType()), StructField("key", StringType()),
            StructField("topic", StringType()), StructField("partition", LongType()),
            StructField("offset", LongType()), StructField("timestamp", TimestampType()),
        ])
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        def raw(i: int, ip: str) -> tuple:
            event = {
                "schema_version": "1.0", "event_id": str(uuid.uuid4()),
                "timestamp": (now - timedelta(seconds=i % 5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source_ip": ip, "event_type": "successful_login",
                "username": f"user{i % 200}", "service": "sshd", "outcome": "success",
                "dest_port": 22,
                "raw_message": f"Accepted password for user{i % 200} from {ip} port 22 ssh2",
            }
            return (json.dumps(event), None, "logs-raw", 0, i, now)

        rows = [raw(i, ip) for i, ip in enumerate(ips)]
        source = spark.createDataFrame(rows, schema).repartition(args.cores * 2).cache()
        source.count()

        def pipeline():
            from pyspark.sql import functions as F
            parsed = parse_normalize_and_validate(source)
            valid = parsed.filter(F.col("_is_valid")).drop("_is_valid")
            enriched = build_enrichment_stage(
                valid, geoip_db_path=str(city_db), asn_db_path=str(asn_db),
                blocklist_path=str(blocklist),
            )
            return build_enriched_payload(enriched)

        # warm-up: JVM, Python workers, database readers and caches
        pipeline().limit(2000).write.format("noop").mode("overwrite").save()

        print(f"events={args.events} cores={args.cores} databases: {db_desc}")
        print("reputation: local blocklist only (see module docstring)\n")
        best = 0.0
        for run in range(1, args.runs + 1):
            t0 = time.perf_counter()
            pipeline().write.format("noop").mode("overwrite").save()
            elapsed = time.perf_counter() - t0
            eps = args.events / elapsed
            best = max(best, eps)
            print(f"  run {run}: {elapsed:.2f} s -> {eps:,.0f} events/s "
                  f"({1000 * elapsed / args.events:.3f} ms/event amortised)")
        spark.stop()

    ok = best >= THROUGHPUT_TARGET_EPS
    note = "" if args.cores >= 4 else f" [measured with {args.cores} core(s), not 4]"
    print(f"\n{_verdict(ok)}: best {best:,.0f} events/s "
          f"(target >= {THROUGHPUT_TARGET_EPS:.0f}){note}")
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# kafka
# --------------------------------------------------------------------------- #


def run_kafka(args: argparse.Namespace) -> int:
    from confluent_kafka import Consumer, Producer

    from producers.log_generator import scenario_normal

    group = f"enrichment-loadtest-{uuid.uuid4().hex[:8]}"
    consumer = Consumer({
        "bootstrap.servers": args.bootstrap, "group.id": group,
        "auto.offset.reset": "latest", "enable.auto.commit": False,
    })
    consumer.subscribe([args.enriched_topic])
    consumer.poll(5.0)  # join the group and get partitions before producing

    producer = Producer({"bootstrap.servers": args.bootstrap, "linger.ms": 5})
    events = scenario_normal(args.events)
    sent_ids: set[str] = set()
    interval = 1.0 / args.rate
    started = time.perf_counter()
    for i, event in enumerate(events):
        event["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        sent_ids.add(event["event_id"])
        producer.produce(args.raw_topic, json.dumps(event).encode(), key=event["event_id"])
        producer.poll(0)
        delay = started + (i + 1) * interval - time.perf_counter()
        if delay > 0:
            time.sleep(delay)
    producer.flush(30)
    produced_in = time.perf_counter() - started
    print(f"produced {len(events)} events in {produced_in:.1f} s "
          f"({len(events) / produced_in:,.0f}/s)")

    latencies: list[float] = []
    seen: set[str] = set()
    deadline = time.perf_counter() + args.timeout
    while len(seen) < len(sent_ids) and time.perf_counter() < deadline:
        message = consumer.poll(1.0)
        if message is None or message.error():
            continue
        received = time.time()
        payload = json.loads(message.value())
        event_id = payload.get("event_id")
        if event_id in sent_ids and event_id not in seen:
            seen.add(event_id)
            sent_at = datetime.fromisoformat(payload["timestamp"].replace("Z", "+00:00"))
            latencies.append(received - sent_at.timestamp())
    consumer.close()

    if not latencies:
        print("FAIL: no enriched events arrived (is spark_consumer running?)")
        return 1
    stats = summarize([v * 1000 for v in latencies])
    missing = len(sent_ids) - len(seen)
    drain = time.perf_counter() - started
    print(f"enriched events received: {len(seen)}/{len(sent_ids)} "
          f"({missing} missing) in {drain:.1f} s -> {len(seen) / drain:,.0f}/s")
    print(f"end-to-end latency: mean {stats['mean'] / 1000:.2f} s | "
          f"p50 {stats['p50'] / 1000:.2f} | p95 {stats['p95'] / 1000:.2f} | "
          f"max {stats['max'] / 1000:.2f}")
    ok_latency = stats["p95"] / 1000 < E2E_TARGET_SECONDS and missing == 0
    ok_rate = args.rate < THROUGHPUT_TARGET_EPS or (len(seen) / drain) >= THROUGHPUT_TARGET_EPS * 0.95
    print(f"{_verdict(ok_latency)}: p95 end-to-end < {E2E_TARGET_SECONDS:.0f} s, no loss")
    print(f"{_verdict(ok_rate)}: sustained >= {THROUGHPUT_TARGET_EPS:.0f} events/s "
          f"(offered {args.rate:.0f}/s)")
    return 0 if ok_latency and ok_rate else 1


# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="mode", required=True)

    def traffic(p: argparse.ArgumentParser, events: int) -> None:
        p.add_argument("--events", type=int, default=events)
        p.add_argument("--distinct-ips", type=int, default=2000)
        p.add_argument("--private-ratio", type=float, default=0.2)

    micro = sub.add_parser("micro", help="in-process per-event latency")
    traffic(micro, 20_000)
    micro.add_argument("--batch-size", type=int, default=1000)
    micro.add_argument("--api-latency-ms", type=float, default=150.0)
    micro.set_defaults(func=run_micro)

    spark = sub.add_parser("spark", help="Spark pipeline throughput")
    traffic(spark, 60_000)
    spark.add_argument("--cores", type=int, default=4)
    spark.add_argument("--runs", type=int, default=3)
    spark.set_defaults(func=run_spark)

    kafka = sub.add_parser("kafka", help="end-to-end load test against Kafka")
    kafka.add_argument("--bootstrap", default=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"))
    kafka.add_argument("--raw-topic", default="logs-raw")
    kafka.add_argument("--enriched-topic", default="logs-enriched")
    kafka.add_argument("--events", type=int, default=6000)
    kafka.add_argument("--rate", type=float, default=600.0, help="events/second offered")
    kafka.add_argument("--timeout", type=float, default=60.0)
    kafka.set_defaults(func=run_kafka)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())