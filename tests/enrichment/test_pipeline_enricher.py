"""Tests for enrichment/pipeline_enricher.py (the composite enricher)."""

import logging
import threading
import time

import pytest

from enrichment import ASNEnricher, GeoIPEnricher, IPReputationEnricher
from enrichment.pipeline_enricher import (
    ENRICHMENT_FIELDS,
    PipelineEnricher,
    null_enrichment,
    startup_warnings,
)
from tests.enrichment.conftest import KNOWN_ASNS, UNKNOWN_PUBLIC_IP

MALICIOUS = "81.2.69.142"  # in the City and ASN test databases


class _Response:
    status_code = 200
    headers: dict = {}

    def __init__(self, score, categories):
        self._payload = {
            "data": {
                "abuseConfidenceScore": score,
                "reports": [{"categories": list(categories)}] if categories else [],
            }
        }

    def json(self):
        return self._payload


class FakeAPI:
    """Mocked AbuseIPDB with optional latency; tracks calls and concurrency."""

    def __init__(self, scores=None, delay=0.0):
        self.scores = scores or {MALICIOUS: (95, (18, 22))}
        self.delay = delay
        self.calls = []
        self._active = 0
        self.max_active = 0
        self._lock = threading.Lock()

    def get(self, url, **kwargs):
        ip = kwargs["params"]["ipAddress"]
        with self._lock:
            self.calls.append(ip)
            self._active += 1
            self.max_active = max(self.max_active, self._active)
        try:
            if self.delay:
                time.sleep(self.delay)
            return _Response(*self.scores.get(ip, (0, ())))
        finally:
            with self._lock:
                self._active -= 1

    def close(self):
        pass


class Exploding:
    def enrich(self, ip):
        raise RuntimeError("boom")

    enrich_cached = enrich

    def prefetch(self, ips, **kwargs):
        raise RuntimeError("boom")

    def close(self):
        pass


@pytest.fixture
def api():
    return FakeAPI()


@pytest.fixture
def parts(city_db, asn_db, api, tmp_path):
    geo = GeoIPEnricher(city_db)
    asn = ASNEnricher(asn_db)
    reputation = IPReputationEnricher(
        api_key="test-key", session=api, blocklist_path=tmp_path / "none.txt",
        daily_limit=None,
    )
    yield {"geoip": geo, "asn": asn, "reputation": reputation}
    for part in (geo, asn, reputation):
        part.close()


@pytest.fixture
def enricher(parts):
    return PipelineEnricher(**parts)


# ---- composition -----------------------------------------------------------


def test_composes_geoip_asn_and_reputation(enricher):
    result = enricher.enrich("8.8.8.8")
    assert result == {
        "geo_country": "US",
        "geo_city": "Mountain View",
        "geo_latitude": 37.39,
        "geo_longitude": -122.08,
        "geo_is_private": False,
        "asn_number": 15169,
        "asn_org": "GOOGLE",
        "reputation_score": 0,
        "is_known_threat": False,
        "threat_categories": [],
    }


def test_a_malicious_ip_is_flagged_with_geo_and_asn(enricher):
    result = enricher.enrich(MALICIOUS)
    assert (result["geo_country"], result["geo_city"]) == ("GB", "London")
    assert result["asn_number"] == KNOWN_ASNS[MALICIOUS][0]
    assert result["reputation_score"] == 95
    assert result["is_known_threat"] is True
    assert result["threat_categories"] == ["brute_force", "ssh"]


def test_every_field_is_always_present(enricher):
    for ip in ("8.8.8.8", "10.0.0.1", UNKNOWN_PUBLIC_IP, "garbage", None, 42):
        assert set(enricher.enrich(ip)) == set(ENRICHMENT_FIELDS)


def test_null_enrichment_shape():
    nulls = null_enrichment()
    assert set(nulls) == set(ENRICHMENT_FIELDS)
    assert nulls["is_known_threat"] is False and nulls["threat_categories"] == []
    assert all(
        v is None for k, v in nulls.items()
        if k not in ("is_known_threat", "threat_categories")
    )
    assert null_enrichment()["threat_categories"] is not nulls["threat_categories"]


# ---- public IPs only ---------------------------------------------------------


@pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "::1", "fc00::1"])
def test_private_ips_are_not_looked_up_or_sent_to_the_api(enricher, api, ip):
    result = enricher.enrich(ip)
    assert result["geo_is_private"] is True
    assert result["asn_number"] is None and result["asn_org"] is None
    assert result["reputation_score"] is None and result["is_known_threat"] is False
    assert api.calls == []


def test_a_blocklisted_private_host_is_still_flagged(city_db, asn_db, api, tmp_path):
    blocklist = tmp_path / "bad.txt"
    blocklist.write_text("10.9.8.7\n")
    with PipelineEnricher(
        geoip=GeoIPEnricher(city_db), asn=ASNEnricher(asn_db),
        reputation=IPReputationEnricher(api_key="k", session=api, blocklist_path=blocklist),
    ) as pipeline:
        result = pipeline.enrich("10.9.8.7")
    assert result["geo_is_private"] is True
    assert result["is_known_threat"] is True
    assert result["threat_categories"] == ["local_blocklist"]
    assert api.calls == []


@pytest.mark.parametrize("bad", ["not_an_ip", "", None, 123, "999.1.1.1"])
def test_invalid_ips_yield_null_enrichment(enricher, api, bad):
    assert enricher.enrich(bad) == null_enrichment()
    assert api.calls == []


# ---- failure isolation: never raise, never lose the others ------------------


def test_a_failing_geoip_enricher_only_nulls_the_geo_fields(parts):
    pipeline = PipelineEnricher(**{**parts, "geoip": Exploding()})
    result = pipeline.enrich("8.8.8.8")
    assert result["geo_country"] is None and result["geo_is_private"] is None
    assert result["asn_org"] == "GOOGLE" and result["reputation_score"] == 0
    assert pipeline.stats["failures_geoip"] == 1


def test_a_failing_asn_enricher_only_nulls_the_asn_fields(parts):
    pipeline = PipelineEnricher(**{**parts, "asn": Exploding()})
    result = pipeline.enrich("8.8.8.8")
    assert result["asn_number"] is None and result["asn_org"] is None
    assert result["geo_country"] == "US" and result["reputation_score"] == 0
    assert pipeline.stats["failures_asn"] == 1


def test_a_failing_reputation_enricher_only_nulls_the_reputation_fields(parts):
    pipeline = PipelineEnricher(**{**parts, "reputation": Exploding()})
    result = pipeline.enrich("8.8.8.8")
    assert result["reputation_score"] is None
    assert result["is_known_threat"] is False and result["threat_categories"] == []
    assert result["geo_country"] == "US" and result["asn_org"] == "GOOGLE"
    assert pipeline.stats["failures_reputation"] == 1


def test_every_enricher_failing_still_returns_nulls_and_never_raises(parts):
    pipeline = PipelineEnricher(
        geoip=Exploding(), asn=Exploding(), reputation=Exploding()
    )
    assert pipeline.enrich("8.8.8.8") == null_enrichment()
    results = pipeline.enrich_many(["8.8.8.8", "1.1.1.1", None])
    assert results == [null_enrichment()] * 3


def test_failure_logs_are_rate_limited(parts, caplog):
    pipeline = PipelineEnricher(**{**parts, "geoip": Exploding()})
    with caplog.at_level(logging.ERROR, logger="enrichment.pipeline_enricher"):
        for _ in range(3000):
            pipeline.enrich("8.8.8.8")
    assert len(caplog.records) == 23  # first 20, then #1000, #2000, #3000
    assert pipeline.stats["failures_geoip"] == 3000


def test_a_misbehaving_enricher_returning_junk_is_treated_as_empty(parts):
    class Junk:
        def enrich(self, ip):
            return "not a dict"

        enrich_cached = enrich

    pipeline = PipelineEnricher(**{**parts, "asn": Junk()})
    assert pipeline.enrich("8.8.8.8")["asn_org"] is None


# ---- batch path --------------------------------------------------------------


def test_enrich_many_preserves_order_and_matches_single_enrich(enricher):
    ips = ["8.8.8.8", "10.0.0.1", MALICIOUS, "garbage", UNKNOWN_PUBLIC_IP, "8.8.8.8"]
    batch = enricher.enrich_many(ips)
    assert len(batch) == len(ips)
    for ip, result in zip(ips, batch):
        assert result == enricher.enrich(ip)


def test_enrich_many_handles_empty_input(enricher):
    assert enricher.enrich_many([]) == []


def test_each_distinct_ip_is_enriched_and_looked_up_once_per_batch(enricher, api):
    ips = ["8.8.8.8"] * 500 + [MALICIOUS] * 300 + ["10.0.0.1"] * 200
    results = enricher.enrich_many(ips)
    assert len(results) == 1000
    assert sorted(api.calls) == sorted(["8.8.8.8", MALICIOUS])
    stats = enricher.stats
    assert stats["events"] == 1000 and stats["distinct_ips"] == 3


def test_batch_results_are_independent_copies(enricher):
    first, second = enricher.enrich_many([MALICIOUS, MALICIOUS])
    first["threat_categories"].append("tampered")
    first["asn_org"] = "TAMPERED"
    assert second["threat_categories"] == ["brute_force", "ssh"]
    assert enricher.enrich_many([MALICIOUS])[0]["asn_org"] != "TAMPERED"


def test_new_ips_are_looked_up_concurrently_not_one_by_one(city_db, asn_db, tmp_path):
    api = FakeAPI(delay=0.2)
    ips = [f"20.0.0.{i}" for i in range(1, 17)]  # 16 distinct public IPs
    with PipelineEnricher(
        geoip=GeoIPEnricher(city_db), asn=ASNEnricher(asn_db),
        reputation=IPReputationEnricher(
            api_key="k", session=api, blocklist_path=tmp_path / "n.txt", daily_limit=None
        ),
        prefetch_workers=8,
    ) as pipeline:
        started = time.perf_counter()
        results = pipeline.enrich_many(ips)
        elapsed = time.perf_counter() - started

    assert all(r["reputation_score"] == 0 for r in results)
    assert api.max_active > 1
    assert elapsed < 16 * 0.2 / 2  # sequential would take 3.2 s
    assert pipeline.stats["prefetched"] == 16


def test_a_slow_api_cannot_stall_a_batch_beyond_the_deadline(city_db, asn_db, tmp_path):
    api = FakeAPI(delay=1.0)
    ips = [f"21.0.0.{i}" for i in range(1, 9)]
    with PipelineEnricher(
        geoip=GeoIPEnricher(city_db), asn=ASNEnricher(asn_db),
        reputation=IPReputationEnricher(
            api_key="k", session=api, blocklist_path=tmp_path / "n.txt", daily_limit=None
        ),
        prefetch_deadline_seconds=0.2,
    ) as pipeline:
        started = time.perf_counter()
        results = pipeline.enrich_many(ips)
        elapsed = time.perf_counter() - started

    assert elapsed < 0.8  # bounded by the deadline, not the 1 s API latency
    assert len(results) == 8
    # unfinished lookups are not assessed in this batch -- but nothing crashed
    assert all(r["is_known_threat"] is False for r in results)
    assert all(r["geo_is_private"] is False for r in results)


def test_a_failing_prefetch_does_not_lose_the_batch(parts):
    class BadPrefetch(IPReputationEnricher):
        def prefetch(self, ips, **kwargs):
            raise RuntimeError("boom")

    reputation = BadPrefetch(api_key="", blocklist_path=None)
    pipeline = PipelineEnricher(**{**parts, "reputation": reputation})
    results = pipeline.enrich_many(["8.8.8.8", "10.0.0.1"])
    assert results[0]["geo_country"] == "US"
    assert pipeline.stats["failures_reputation"] == 1


def test_results_after_a_batch_are_served_from_cache(enricher, api):
    enricher.enrich_many(["8.8.8.8", MALICIOUS])
    calls_after_batch = len(api.calls)
    for _ in range(5):
        enricher.enrich("8.8.8.8")
        enricher.enrich_many([MALICIOUS])
    assert len(api.calls) == calls_after_batch


# ---- lifecycle / configuration ------------------------------------------------


def test_close_only_closes_enrichers_it_built(city_db, asn_db, tmp_path):
    injected = ASNEnricher(asn_db)
    pipeline = PipelineEnricher(
        geoip_db_path=city_db, asn=injected, blocklist_path=tmp_path / "n.txt"
    )
    pipeline.close()
    assert injected.database_loaded is True  # not ours: left open
    assert pipeline.enrich("8.8.8.8")["asn_org"] == "GOOGLE"  # still usable
    injected.close()


def test_builds_its_own_enrichers_from_paths(city_db, asn_db, tmp_path):
    with PipelineEnricher(
        geoip_db_path=city_db, asn_db_path=asn_db, blocklist_path=tmp_path / "n.txt"
    ) as pipeline:
        result = pipeline.enrich("8.8.8.8")
    assert result["geo_country"] == "US" and result["asn_org"] == "GOOGLE"
    assert result["reputation_score"] is None  # no API key in the test env


def test_missing_databases_and_key_degrade_to_nulls(tmp_path):
    with PipelineEnricher(
        geoip_db_path=tmp_path / "a.mmdb", asn_db_path=tmp_path / "b.mmdb",
        blocklist_path=tmp_path / "c.txt",
    ) as pipeline:
        result = pipeline.enrich("8.8.8.8")
    assert result["geo_is_private"] is False
    assert result["geo_country"] is None and result["asn_number"] is None
    assert result["is_known_threat"] is False


@pytest.mark.parametrize("kwargs", [{"prefetch_workers": 0}, {"prefetch_deadline_seconds": 0}])
def test_invalid_arguments_raise(parts, kwargs):
    with pytest.raises(ValueError):
        PipelineEnricher(**parts, **kwargs)


def test_concurrent_use_is_safe(enricher):
    errors = []

    def work():
        try:
            for _ in range(20):
                enricher.enrich_many(["8.8.8.8", MALICIOUS, "10.0.0.1"])
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
    assert enricher.stats["events"] == 6 * 20 * 3


# ---- startup warnings -----------------------------------------------------------


def test_startup_warnings_describe_a_degraded_setup(tmp_path):
    messages = startup_warnings(
        geoip_db_path=tmp_path / "x.mmdb", asn_db_path=tmp_path / "y.mmdb",
        blocklist_path=tmp_path / "z.txt",
    )
    text = "\n".join(messages)
    assert len(messages) == 3
    assert "GeoIP database not found" in text and "ASN database not found" in text
    assert "ABUSEIPDB_API_KEY is not set" in text


def test_startup_warnings_are_empty_for_a_healthy_setup(monkeypatch, city_db, asn_db, tmp_path):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    assert startup_warnings(geoip_db_path=city_db, asn_db_path=asn_db,
                            blocklist_path=tmp_path / "z.txt") == []


def test_output_fields_match_the_spark_columns():
    from enrichment.spark_enrichment import ENRICHMENT_COLUMNS

    assert tuple(ENRICHMENT_FIELDS) == tuple(ENRICHMENT_COLUMNS)