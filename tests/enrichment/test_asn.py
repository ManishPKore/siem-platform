"""Unit tests for enrichment/asn.py (ASNEnricher)."""

import logging
import threading
from pathlib import Path
from types import SimpleNamespace

import geoip2.errors
import pytest
from maxminddb import InvalidDatabaseError

from enrichment.asn import (
    DEFAULT_DB_PATH,
    ENV_DB_PATH,
    ASNEnricher,
    resolve_db_path,
)
from enrichment.geoip import REPO_ROOT
from tests.enrichment.conftest import (
    ASN_IPV6,
    ASN_NUMBER_ONLY_IP,
    KNOWN_ASNS,
    UNKNOWN_PUBLIC_IP,
)

NULL_ASN = {"asn_number": None, "asn_org": None}


class FakeReader:
    """Stands in for geoip2.database.Reader; counts lookups."""

    def __init__(self, table):
        self.table = table
        self.calls = 0
        self.closed = False

    def asn(self, ip):
        self.calls += 1
        if ip not in self.table:
            raise geoip2.errors.AddressNotFoundError(f"{ip} not found")
        number, org = self.table[ip]
        return SimpleNamespace(
            autonomous_system_number=number,
            autonomous_system_organization=org,
        )

    def close(self):
        self.closed = True


@pytest.fixture
def reader():
    return FakeReader({"8.8.8.8": KNOWN_ASNS["8.8.8.8"]})


@pytest.fixture
def enricher(reader):
    return ASNEnricher(reader=reader)


@pytest.fixture
def real_format_enricher(asn_db):
    with ASNEnricher(asn_db, strict=True) as e:
        yield e


# ---- Acceptance criteria ----------------------------------------------------


def test_acceptance_8_8_8_8_returns_google(real_format_enricher):
    assert real_format_enricher.enrich("8.8.8.8") == {
        "asn_number": 15169,
        "asn_org": "GOOGLE",
    }


def test_acceptance_8_8_8_8_with_default_construction(asn_db, monkeypatch):
    """``ASNEnricher()`` with no arguments resolves the DB from ASN_DB_PATH."""
    monkeypatch.setenv(ENV_DB_PATH, asn_db)
    with ASNEnricher() as e:
        assert e.enrich("8.8.8.8") == {"asn_number": 15169, "asn_org": "GOOGLE"}


_REAL_DB = resolve_db_path()


@pytest.mark.skipif(
    not _REAL_DB.is_file(),
    reason=f"real GeoLite2-ASN database not downloaded at {_REAL_DB}",
)
def test_acceptance_with_the_real_geolite2_asn_database():
    """The literal acceptance criterion, against the licensed MaxMind file."""
    with ASNEnricher(strict=True) as e:
        assert e.enrich("8.8.8.8") == {"asn_number": 15169, "asn_org": "GOOGLE"}


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",  # RFC 1918
        "172.16.5.4",
        "192.168.1.1",
        "127.0.0.1",  # loopback
        "169.254.10.10",  # link-local
        "100.64.0.1",  # CGNAT
        "0.0.0.0",
        "224.0.0.1",  # multicast
        "::1",
        "fc00::1",  # unique local
        "fe80::1",  # link-local v6
    ],
)
def test_acceptance_private_ips_return_nulls(enricher, reader, ip):
    assert enricher.enrich(ip) == {"asn_number": None, "asn_org": None}
    assert reader.calls == 0  # never touches the database


def test_acceptance_result_has_exactly_the_two_documented_keys(enricher):
    assert set(enricher.enrich("8.8.8.8")) == {"asn_number", "asn_org"}
    assert set(enricher.enrich("10.0.0.1")) == {"asn_number", "asn_org"}


# ---- Real-format database ----------------------------------------------------


@pytest.mark.parametrize(
    "ip,number,org",
    [(ip, n, o) for ip, (n, o) in KNOWN_ASNS.items()],
)
def test_known_ips_resolve(real_format_enricher, ip, number, org):
    assert real_format_enricher.enrich(ip) == {"asn_number": number, "asn_org": org}


def test_cloud_hosting_orgs_are_surfaced(real_format_enricher):
    assert real_format_enricher.enrich("104.131.0.1")["asn_org"].startswith(
        "DIGITALOCEAN"
    )
    assert real_format_enricher.enrich("52.95.110.1")["asn_org"].startswith("AMAZON")


def test_asn_number_is_a_plain_int_and_keeps_full_uint32_range(real_format_enricher):
    result = real_format_enricher.enrich("81.2.69.142")
    assert type(result["asn_number"]) is int
    assert result["asn_number"] == 4_200_000_000  # > 2**31


def test_ipv6_address(real_format_enricher):
    assert real_format_enricher.enrich(ASN_IPV6) == {
        "asn_number": 15169,
        "asn_org": "GOOGLE",
    }


def test_ipv4_mapped_ipv6_is_treated_as_ipv4(real_format_enricher):
    assert real_format_enricher.enrich("::ffff:8.8.8.8") == real_format_enricher.enrich(
        "8.8.8.8"
    )


def test_surrounding_whitespace_is_ignored(real_format_enricher):
    assert real_format_enricher.enrich("  8.8.8.8\n")["asn_number"] == 15169


def test_public_ip_not_in_database_returns_nulls(real_format_enricher):
    assert real_format_enricher.enrich(UNKNOWN_PUBLIC_IP) == NULL_ASN


def test_record_without_organization_keeps_the_number(real_format_enricher):
    assert real_format_enricher.enrich(ASN_NUMBER_ONLY_IP) == {
        "asn_number": 64500,
        "asn_org": None,
    }


# ---- Invalid input ----------------------------------------------------------


@pytest.mark.parametrize(
    "bad", ["not_an_ip", "", "   ", "999.1.1.1", "1.2.3", "8.8.8.8/24", None, 123, b"8.8.8.8"]
)
def test_invalid_input_returns_nulls_and_never_raises(enricher, reader, bad):
    assert enricher.enrich(bad) == NULL_ASN
    assert reader.calls == 0


def test_invalid_input_logs_a_warning(enricher, caplog):
    with caplog.at_level(logging.WARNING, logger="enrichment.asn"):
        enricher.enrich("not_an_ip")
    assert any("invalid IP" in r.getMessage() for r in caplog.records)


def test_invalid_input_warnings_are_rate_limited(enricher, caplog):
    with caplog.at_level(logging.WARNING, logger="enrichment.asn"):
        for _ in range(5_000):
            enricher.enrich("garbage")
    # first 50, then every 1000th (1000, 2000, ... 5000) => 55
    assert len(caplog.records) == 55


def test_overlong_invalid_input_is_truncated_in_the_log(enricher, caplog):
    with caplog.at_level(logging.WARNING, logger="enrichment.asn"):
        enricher.enrich("x" * 10_000)
    assert len(caplog.records[0].getMessage()) < 200


# ---- Caching ----------------------------------------------------------------


def test_repeated_ip_is_served_from_the_cache(enricher, reader):
    for _ in range(10):
        assert enricher.enrich("8.8.8.8")["asn_number"] == 15169
    assert reader.calls == 1


def test_negative_results_are_cached_too(enricher, reader):
    for _ in range(10):
        enricher.enrich(UNKNOWN_PUBLIC_IP)
    assert reader.calls == 1


def test_cache_can_be_disabled(reader):
    e = ASNEnricher(reader=reader, cache_size=0)
    for _ in range(3):
        e.enrich("8.8.8.8")
    assert reader.calls == 3


def test_mutating_a_result_does_not_poison_the_cache(enricher):
    first = enricher.enrich("8.8.8.8")
    first["asn_org"] = "TAMPERED"
    first["extra"] = 1
    assert enricher.enrich("8.8.8.8") == {"asn_number": 15169, "asn_org": "GOOGLE"}


def test_cache_is_bounded(reader):
    e = ASNEnricher(reader=reader, cache_size=2)
    for ip in ("1.1.1.1", "1.0.0.1", "9.9.9.9", "1.1.1.1"):
        e.enrich(ip)
    assert reader.calls == 4  # "1.1.1.1" was evicted by the 3rd distinct IP


def test_ipv4_and_its_mapped_form_share_a_cache_entry(enricher, reader):
    enricher.enrich("8.8.8.8")
    enricher.enrich("::ffff:8.8.8.8")
    assert reader.calls == 1


# ---- Resilience ---------------------------------------------------------------


def test_reader_failure_degrades_to_nulls_and_logs(caplog):
    class Broken:
        def asn(self, ip):
            raise RuntimeError("boom")

    with caplog.at_level(logging.ERROR, logger="enrichment.asn"):
        result = ASNEnricher(reader=Broken()).enrich("8.8.8.8")
    assert result == NULL_ASN
    assert any("ASN lookup failed" in r.getMessage() for r in caplog.records)


def test_missing_database_degrades_gracefully(tmp_path, caplog):
    missing = tmp_path / "nope.mmdb"
    with caplog.at_level(logging.ERROR, logger="enrichment.asn"):
        e = ASNEnricher(missing)
    assert e.database_loaded is False
    assert e.enrich("8.8.8.8") == NULL_ASN
    assert e.enrich("10.0.0.1") == NULL_ASN
    assert any("ASN database unavailable" in r.getMessage() for r in caplog.records)


def test_missing_database_raises_in_strict_mode(tmp_path):
    with pytest.raises(FileNotFoundError):
        ASNEnricher(tmp_path / "nope.mmdb", strict=True)


def test_corrupt_database_degrades_gracefully(tmp_path):
    bad = tmp_path / "corrupt.mmdb"
    bad.write_bytes(b"this is not a maxmind database")
    e = ASNEnricher(bad)
    assert e.database_loaded is False
    assert e.enrich("8.8.8.8") == NULL_ASN


def test_corrupt_database_raises_in_strict_mode(tmp_path):
    bad = tmp_path / "corrupt.mmdb"
    bad.write_bytes(b"this is not a maxmind database")
    with pytest.raises(InvalidDatabaseError):
        ASNEnricher(bad, strict=True)


def test_city_database_is_rejected_as_the_wrong_type(city_db):
    """ASN_DB_PATH pointing at GeoLite2-City must fail fast, not per lookup."""
    assert ASNEnricher(city_db).database_loaded is False
    with pytest.raises(InvalidDatabaseError, match="expected an ASN database"):
        ASNEnricher(city_db, strict=True)


# ---- Lifecycle ----------------------------------------------------------------


def test_close_closes_an_owned_reader(asn_db):
    e = ASNEnricher(asn_db)
    assert e.database_loaded
    e.close()
    assert e.database_loaded is False
    assert e.enrich("8.8.8.8") == NULL_ASN  # no use-after-close crash
    e.close()  # idempotent


def test_close_does_not_close_an_injected_reader(reader):
    ASNEnricher(reader=reader).close()
    assert reader.closed is False


def test_context_manager_closes_the_reader(asn_db):
    with ASNEnricher(asn_db) as e:
        assert e.enrich("8.8.8.8")["asn_number"] == 15169
    assert e.database_loaded is False


def test_concurrent_lookups_are_safe(real_format_enricher):
    ips = list(KNOWN_ASNS) * 50
    results, errors = [], []

    def work():
        try:
            for ip in ips:
                results.append(real_format_enricher.enrich(ip)["asn_number"])
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]

    assert not errors
    assert len(results) == 8 * len(ips)
    assert None not in results


# ---- Database path resolution ---------------------------------------------------


def test_default_path_is_data_geolite2_asn_mmdb(monkeypatch):
    monkeypatch.delenv(ENV_DB_PATH, raising=False)
    assert DEFAULT_DB_PATH == REPO_ROOT / "data" / "GeoLite2-ASN.mmdb"
    assert resolve_db_path() == DEFAULT_DB_PATH


def test_explicit_argument_beats_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv(ENV_DB_PATH, "/from/env.mmdb")
    explicit = tmp_path / "explicit.mmdb"
    assert resolve_db_path(explicit) == explicit


def test_environment_beats_the_default(monkeypatch):
    monkeypatch.setenv(ENV_DB_PATH, "/from/env.mmdb")
    assert resolve_db_path() == Path("/from/env.mmdb")


def test_relative_paths_are_anchored_at_the_repo_root(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # Spark workers don't run from the repo root
    monkeypatch.setenv(ENV_DB_PATH, "data/GeoLite2-ASN.mmdb")
    assert resolve_db_path() == REPO_ROOT / "data" / "GeoLite2-ASN.mmdb"


def test_the_database_file_is_gitignored():
    patterns = (REPO_ROOT / ".gitignore").read_text().splitlines()
    assert "*.mmdb" in patterns
    assert "data/*" in patterns