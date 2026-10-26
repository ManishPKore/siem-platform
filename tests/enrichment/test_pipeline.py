"""Tests for enrichment/pipeline.py (combined enrich_event)."""

import logging
from types import SimpleNamespace

import pytest

from enrichment import ASNEnricher, GeoIPEnricher, enrich_event
from enrichment.asn import ENV_DB_PATH as ASN_ENV
from enrichment.geoip import ENV_DB_PATH as GEO_ENV
from enrichment.pipeline import (
    ENRICHMENT_FIELDS,
    reset_default_enrichers,
)
from tests.enrichment.conftest import KNOWN_ASNS, KNOWN_IPS, UNKNOWN_PUBLIC_IP


@pytest.fixture
def enrichers(city_db, asn_db):
    with GeoIPEnricher(city_db) as geo, ASNEnricher(asn_db) as asn:
        yield {"geoip": geo, "asn": asn}


def test_acceptance_adds_geo_and_asn_fields_in_one_call(enrichers):
    event = {"event_id": "e1", "source_ip": "8.8.8.8"}
    out = enrich_event(event, **enrichers)
    assert out == {
        "event_id": "e1",
        "source_ip": "8.8.8.8",
        "geo_country": "US",
        "geo_city": "Mountain View",
        "geo_latitude": 37.39,
        "geo_longitude": -122.08,
        "geo_is_private": False,
        "asn_number": 15169,
        "asn_org": "GOOGLE",
    }


def test_every_enrichment_field_is_always_present(enrichers):
    for ip in ("8.8.8.8", "10.0.0.1", UNKNOWN_PUBLIC_IP, "garbage", None):
        out = enrich_event({"source_ip": ip}, **enrichers)
        assert set(ENRICHMENT_FIELDS) <= set(out)


def test_private_ip(enrichers):
    out = enrich_event({"source_ip": "192.168.1.1"}, **enrichers)
    assert out["geo_is_private"] is True
    assert out["geo_country"] is None
    assert out["asn_number"] is None and out["asn_org"] is None


def test_invalid_and_missing_ip_do_not_raise(enrichers):
    bad = enrich_event({"source_ip": "not_an_ip"}, **enrichers)
    missing = enrich_event({"event_id": "x"}, **enrichers)
    for out in (bad, missing):
        assert all(out[f] is None for f in ENRICHMENT_FIELDS)


def test_input_is_not_mutated_and_other_fields_survive(enrichers):
    event = {"source_ip": "8.8.8.8", "username": "alice", "nested": {"a": 1}}
    snapshot = {"source_ip": "8.8.8.8", "username": "alice", "nested": {"a": 1}}
    out = enrich_event(event, **enrichers)
    assert event == snapshot
    assert out["username"] == "alice" and out["nested"] == {"a": 1}
    assert out is not event


def test_enriching_twice_is_idempotent(enrichers):
    once = enrich_event({"source_ip": "8.8.8.8"}, **enrichers)
    assert enrich_event(once, **enrichers) == once


def test_stale_enrichment_fields_are_overwritten(enrichers):
    out = enrich_event({"source_ip": "8.8.8.8", "asn_org": "STALE"}, **enrichers)
    assert out["asn_org"] == "GOOGLE"


def test_custom_ip_field(enrichers):
    out = enrich_event({"client_ip": "8.8.8.8"}, ip_field="client_ip", **enrichers)
    assert out["asn_number"] == 15169 and out["geo_country"] == "US"


def test_accepts_any_mapping(enrichers):
    from types import MappingProxyType

    out = enrich_event(MappingProxyType({"source_ip": "8.8.8.8"}), **enrichers)
    assert out["asn_org"] == "GOOGLE"


@pytest.mark.parametrize("bad", [None, "8.8.8.8", ["8.8.8.8"], 5, object()])
def test_non_mapping_event_is_a_type_error(bad, enrichers):
    with pytest.raises(TypeError, match="mapping"):
        enrich_event(bad, **enrichers)


def test_one_failing_enricher_does_not_lose_the_other(city_db, caplog):
    class Exploding:
        def enrich(self, ip):
            raise RuntimeError("boom")

    with GeoIPEnricher(city_db) as geo, caplog.at_level(
        logging.ERROR, logger="enrichment.pipeline"
    ):
        out = enrich_event({"source_ip": "8.8.8.8"}, geoip=geo, asn=Exploding())
    assert out["geo_country"] == "US"
    assert out["asn_number"] is None and out["asn_org"] is None
    assert any("ASN enrichment failed" in r.getMessage() for r in caplog.records)

    with ASNEnricher(reader=SimpleNamespace(
        asn=lambda ip: SimpleNamespace(
            autonomous_system_number=1, autonomous_system_organization="X"
        )
    )) as asn:
        out = enrich_event({"source_ip": "8.8.8.8"}, geoip=Exploding(), asn=asn)
    assert out["asn_number"] == 1
    assert out["geo_country"] is None and out["geo_is_private"] is None


def test_missing_databases_degrade_to_nulls(tmp_path):
    geo = GeoIPEnricher(tmp_path / "a.mmdb")
    asn = ASNEnricher(tmp_path / "b.mmdb")
    out = enrich_event({"source_ip": "8.8.8.8"}, geoip=geo, asn=asn)
    assert out["geo_is_private"] is False  # still classified without a DB
    assert out["geo_country"] is None and out["asn_number"] is None


def test_default_enrichers_use_env_paths_and_are_shared(
    monkeypatch, city_db, asn_db
):
    monkeypatch.setenv(GEO_ENV, city_db)
    monkeypatch.setenv(ASN_ENV, asn_db)
    reset_default_enrichers()
    try:
        first = enrich_event({"source_ip": "8.8.8.8"})
        second = enrich_event({"source_ip": "81.2.69.142"})
        assert first["geo_country"] == "US" and first["asn_number"] == 15169
        assert second["geo_country"] == "GB"
        assert second["asn_number"] == KNOWN_ASNS["81.2.69.142"][0]

        from enrichment import pipeline

        shared = dict(pipeline._defaults)
        enrich_event({"source_ip": "8.8.8.8"})
        assert pipeline._defaults == shared  # not rebuilt per call
    finally:
        reset_default_enrichers()


def test_every_known_ip_enriches_consistently(enrichers):
    for ip in set(KNOWN_IPS) & set(KNOWN_ASNS):
        out = enrich_event({"source_ip": ip}, **enrichers)
        assert out["geo_country"] == KNOWN_IPS[ip][0]
        assert out["asn_number"] == KNOWN_ASNS[ip][0]