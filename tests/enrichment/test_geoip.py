"""Unit tests for enrichment/geoip.py (GeoIPEnricher)."""

import logging
import time
from pathlib import Path
from types import SimpleNamespace

import geoip2.errors
import pytest

from enrichment.geoip import (
    DEFAULT_DB_PATH,
    ENV_DB_PATH,
    GeoIPEnricher,
    resolve_db_path,
)
from tests.enrichment.conftest import (
    COUNTRY_ONLY_IP,
    KNOWN_IPS,
    UNKNOWN_PUBLIC_IP,
)

NULL_GEO = {"country": None, "city": None, "latitude": None, "longitude": None}


class FakeReader:
    def __init__(self, table):
        self.table = table
        self.calls = 0
        self.closed = False

    def city(self, ip):
        self.calls += 1
        if ip not in self.table:
            raise geoip2.errors.AddressNotFoundError(f"{ip} not found")
        country, city, lat, lon = self.table[ip]
        return SimpleNamespace(
            country=SimpleNamespace(iso_code=country),
            city=SimpleNamespace(name=city),
            location=SimpleNamespace(latitude=lat, longitude=lon),
        )

    def close(self):
        self.closed = True


@pytest.fixture
def reader():
    return FakeReader({"8.8.8.8": KNOWN_IPS["8.8.8.8"]})


@pytest.fixture
def enricher(reader):
    return GeoIPEnricher(reader=reader)


# ---- Acceptance criteria ----------------------------------------------------


def test_acceptance_known_public_ip(enricher):
    assert enricher.enrich("8.8.8.8") == {
        "country": "US",
        "city": "Mountain View",
        "latitude": 37.39,
        "longitude": -122.08,
        "is_private": False,
    }


def test_acceptance_private_ip_returns_nulls_without_exception(enricher):
    result = enricher.enrich("192.168.1.1")
    assert result["is_private"] is True
    assert result["country"] is None and result["city"] is None


def test_acceptance_invalid_ip_returns_nulls_and_warns(enricher, caplog):
    with caplog.at_level(logging.WARNING, logger="enrichment.geoip"):
        result = enricher.enrich("not_an_ip")
    assert result == {**NULL_GEO, "is_private": None}
    assert any("invalid IP" in r.getMessage() for r in caplog.records)


# ---- Public lookups ---------------------------------------------------------


def test_public_ip_missing_from_database(enricher):
    assert enricher.enrich(UNKNOWN_PUBLIC_IP) == {**NULL_GEO, "is_private": False}


def test_ipv4_mapped_ipv6_is_unwrapped(enricher):
    assert enricher.enrich("::ffff:8.8.8.8")["country"] == "US"


def test_surrounding_whitespace_is_ignored(enricher):
    assert enricher.enrich("  8.8.8.8 ")["country"] == "US"


def test_precision_is_configurable(reader):
    result = GeoIPEnricher(reader=reader, precision=4).enrich("8.8.8.8")
    assert (result["latitude"], result["longitude"]) == (37.3861, -122.0839)


# ---- Private / reserved -----------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1", "10.255.255.255", "172.16.0.1", "192.168.1.1",
        "127.0.0.1", "169.254.1.1", "100.64.0.1",
        "203.0.113.5",  # documentation range, used by the project's samples
        "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fc00::1",
    ],
)
def test_private_and_reserved_ips(enricher, reader, ip):
    assert enricher.enrich(ip) == {**NULL_GEO, "is_private": True}
    assert reader.calls == 0  # never touches the database


def test_private_ip_works_without_a_database(tmp_path):
    enricher = GeoIPEnricher(tmp_path / "missing.mmdb")
    assert enricher.database_loaded is False
    assert enricher.enrich("192.168.1.1")["is_private"] is True


# ---- Invalid input ----------------------------------------------------------


@pytest.mark.parametrize(
    "bad", ["not_an_ip", "", "999.1.1.1", "1.2.3", None, 12345, b"8.8.8.8"]
)
def test_invalid_input_never_raises(enricher, bad):
    assert enricher.enrich(bad) == {**NULL_GEO, "is_private": None}


def test_invalid_warnings_are_rate_limited(enricher, caplog):
    with caplog.at_level(logging.WARNING, logger="enrichment.geoip"):
        for _ in range(500):
            enricher.enrich("garbage")
    assert len(caplog.records) == 50


# ---- Database handling ------------------------------------------------------


def test_missing_database_degrades_and_logs_error(tmp_path, caplog):
    with caplog.at_level(logging.ERROR, logger="enrichment.geoip"):
        enricher = GeoIPEnricher(tmp_path / "nope.mmdb")
    assert enricher.enrich("8.8.8.8") == {**NULL_GEO, "is_private": False}
    assert any("unavailable" in r.getMessage() for r in caplog.records)


def test_missing_database_strict_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        GeoIPEnricher(tmp_path / "nope.mmdb", strict=True)


def test_corrupt_database_is_handled(tmp_path):
    bad = tmp_path / "bad.mmdb"
    bad.write_bytes(b"this is not an mmdb file")
    assert GeoIPEnricher(bad).database_loaded is False


def test_resolve_db_path_precedence(monkeypatch, tmp_path):
    monkeypatch.delenv(ENV_DB_PATH, raising=False)
    assert resolve_db_path() == Path(DEFAULT_DB_PATH)
    monkeypatch.setenv(ENV_DB_PATH, str(tmp_path / "env.mmdb"))
    assert resolve_db_path() == tmp_path / "env.mmdb"
    assert resolve_db_path(tmp_path / "arg.mmdb") == tmp_path / "arg.mmdb"


def test_relative_paths_are_anchored_at_the_repo_root(monkeypatch, tmp_path):
    from enrichment.geoip import REPO_ROOT

    monkeypatch.chdir(tmp_path)  # a worker's cwd is not the repo root
    monkeypatch.setenv(ENV_DB_PATH, "data/GeoLite2-City.mmdb")
    assert resolve_db_path() == REPO_ROOT / "data" / "GeoLite2-City.mmdb"
    assert resolve_db_path("data/x.mmdb") == REPO_ROOT / "data" / "x.mmdb"


def test_reader_exception_is_swallowed():
    class Boom:
        def city(self, ip):
            raise RuntimeError("corrupt")

    assert GeoIPEnricher(reader=Boom()).enrich("8.8.8.8") == {
        **NULL_GEO,
        "is_private": False,
    }


def test_injected_reader_is_not_closed_by_enricher(enricher, reader):
    enricher.close()
    assert reader.closed is False


# ---- Caching ("Reader opened once") -----------------------------------------


def test_repeat_lookups_hit_the_cache(enricher, reader):
    for _ in range(100):
        enricher.enrich("8.8.8.8")
    assert reader.calls == 1


def test_cache_can_be_disabled(reader):
    enricher = GeoIPEnricher(reader=reader, cache_size=0)
    enricher.enrich("8.8.8.8")
    enricher.enrich("8.8.8.8")
    assert reader.calls == 2


def test_mutating_a_result_does_not_poison_the_cache(enricher):
    first = enricher.enrich("8.8.8.8")
    first["country"] = "XX"
    assert enricher.enrich("8.8.8.8")["country"] == "US"


def test_reader_is_opened_once(monkeypatch, city_db):
    import geoip2.database

    opened = []
    real_reader = geoip2.database.Reader

    def counting_reader(*args, **kwargs):
        opened.append(args)
        return real_reader(*args, **kwargs)

    monkeypatch.setattr(geoip2.database, "Reader", counting_reader)
    with GeoIPEnricher(city_db, strict=True) as enricher:
        for ip in list(KNOWN_IPS) * 50:
            enricher.enrich(ip)
    assert len(opened) == 1


# ---- Real MMDB file (genuine geoip2 Reader path) ----------------------------


def test_real_database_known_ips(city_db):
    with GeoIPEnricher(city_db, strict=True) as enricher:
        assert enricher.enrich("8.8.8.8") == {
            "country": "US",
            "city": "Mountain View",
            "latitude": 37.39,
            "longitude": -122.08,
            "is_private": False,
        }
        london = enricher.enrich("81.2.69.142")
        assert (london["country"], london["city"]) == ("GB", "London")


def test_real_database_country_only_record(city_db):
    with GeoIPEnricher(city_db, strict=True) as enricher:
        assert enricher.enrich(COUNTRY_ONLY_IP) == {
            "country": "AU",
            "city": None,
            "latitude": None,
            "longitude": None,
            "is_private": False,
        }


def test_real_database_unknown_public_ip(city_db):
    with GeoIPEnricher(city_db, strict=True) as enricher:
        assert enricher.enrich(UNKNOWN_PUBLIC_IP)["country"] is None


def test_latency_under_5ms_per_ip(city_db):
    """Acceptance criterion; cache disabled so every call is a real lookup."""
    with GeoIPEnricher(city_db, strict=True, cache_size=0) as enricher:
        ips = [f"{a}.{b}.7.7" for a in range(20, 60) for b in range(25)]  # 1000
        start = time.perf_counter()
        for ip in ips:
            enricher.enrich(ip)
        average_ms = (time.perf_counter() - start) / len(ips) * 1000
    assert average_ms < 5, f"average lookup took {average_ms:.3f} ms"


# ---- Optional: the real licensed file (skipped when not downloaded) ----------


@pytest.mark.skipif(
    not Path(DEFAULT_DB_PATH).exists(),
    reason="data/GeoLite2-City.mmdb not downloaded (see README)",
)
def test_real_geolite2_google_dns_is_in_the_us():
    with GeoIPEnricher(strict=True) as enricher:
        result = enricher.enrich("8.8.8.8")
    assert result["country"] == "US"
    assert result["is_private"] is False