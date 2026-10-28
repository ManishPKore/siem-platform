"""Tests for scripts/benchmark_enrichment.py (the pure helpers)."""

import importlib.util
import ipaddress
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "benchmark_enrichment.py"
_spec = importlib.util.spec_from_file_location("benchmark_enrichment", SCRIPT)
bench = importlib.util.module_from_spec(_spec)
sys.modules["benchmark_enrichment"] = bench
_spec.loader.exec_module(bench)


def test_percentile_uses_nearest_rank():
    values = list(range(1, 101))
    assert bench.percentile(values, 50) == 50
    assert bench.percentile(values, 95) == 95
    assert bench.percentile(values, 99) == 99
    assert bench.percentile([7], 99) == 7
    with pytest.raises(ValueError):
        bench.percentile([], 50)


def test_summarize_reports_mean_percentiles_and_max():
    stats = bench.summarize([1.0, 2.0, 3.0, 4.0, 10.0])
    assert stats["mean"] == 4.0 and stats["max"] == 10.0 and stats["p50"] == 3.0


def test_ip_pool_is_deterministic_distinct_and_public():
    pool = bench.make_ip_pool(300)
    assert pool == bench.make_ip_pool(300) and len(set(pool)) == 300
    assert all(ipaddress.ip_address(ip).is_global for ip in pool)


def test_traffic_mix_has_the_requested_private_share_and_a_skew():
    pool = bench.make_ip_pool(200)
    ips = bench.make_traffic(20_000, pool, private_ratio=0.25)
    private = sum(ipaddress.ip_address(ip).is_private for ip in ips) / len(ips)
    assert 0.22 < private < 0.28
    counts = {}
    for ip in ips:
        counts[ip] = counts.get(ip, 0) + 1
    assert max(counts.values()) > 10 * (len(ips) / len(counts))  # a few noisy IPs


def test_simulated_api_is_deterministic_and_counts_calls():
    api = bench.SimulatedAbuseIPDB(latency_ms=0)
    first = api.get("u", params={"ipAddress": "8.8.8.8"}).json()
    again = api.get("u", params={"ipAddress": "8.8.8.8"}).json()
    assert first == again and api.calls == 2
    assert 0 <= first["data"]["abuseConfidenceScore"] <= 100


def test_targets_match_the_issue():
    assert (bench.LATENCY_TARGET_MS, bench.THROUGHPUT_TARGET_EPS, bench.E2E_TARGET_SECONDS) == (10.0, 500.0, 10.0)


def test_micro_benchmark_runs_and_passes_on_a_small_workload(capsys):
    code = bench.main(["micro", "--events", "1500", "--distinct-ips", "60",
                       "--batch-size", "300", "--api-latency-ms", "1"])
    out = capsys.readouterr().out
    assert code == 0 and "PASS" in out and "BATCH path" in out