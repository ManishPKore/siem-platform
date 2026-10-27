"""Tests for enrichment/pipeline.py (combined enrich_event)."""

import logging

import pytest

from enrichment import ASNEnricher, GeoIPEnricher, IPReputationEnricher, enrich_event
from enrichment.asn import ENV_DB_PATH as ASN_ENV
from enrichment.geoip import ENV_DB_PATH as GEO_ENV
from enrichment.ip_reputation import ENV_BLOCKLIST_PATH
from enrichment.pipeline import (
    ENRICHMENT_FIELDS,
    REPUTATION_FIELDS,
    reset_default_enrichers,
)
from tests.enrichment.conftest import KNOWN_ASNS, KNOWN_IPS, UNKNOWN_PUBLIC_IP

REPUTATION_NONE = {
    "reputation_score": None,
    "is_known_threat": False,
    "threat_categories": [],
}


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


class _Session:
    """Mocked AbuseIPDB: ip -> (score, categories); everything else is clean."""

    def __init__(self, scores=None):
        self.scores = scores or {}
        self.calls = []

    def get(self, url, **kwargs):
        ip = kwargs["params"]["ipAddress"]
        self.calls.append(ip)
        return _Response(*self.scores.get(ip, (0, ())))

    def close(self):
        pass


@pytest.fixture
def session():
    return _Session({"81.2.69.142": (95, (18, 22))})


@pytest.fixture
def enrichers(city_db, asn_db, session, tmp_path):
    with GeoIPEnricher(city_db) as geo, ASNEnricher(asn_db) as asn, IPReputationEnricher(
        api_key="test-key", session=session, blocklist_path=tmp_path / "none.txt"
    ) as reputation:
        yield {"geoip": geo, "asn": asn, "reputation": reputation}


def test_acceptance_adds_geo_asn_and_reputation_fields_in_one_call(enrichers):
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
        "reputation_score": 0,
        "is_known_threat": False,
        "threat_categories": [],
    }


def test_a_malicious_ip_gets_all_three_kinds_of_enrichment(enrichers):
    out = enrich_event({"source_ip": "81.2.69.142"}, **enrichers)
    assert (out["geo_country"], out["geo_city"]) == ("GB", "London")
    assert out["asn_number"] == KNOWN_ASNS["81.2.69.142"][0]
    assert out["reputation_score"] == 95
    assert out["is_known_threat"] is True
    assert out["threat_categories"] == ["brute_force", "ssh"]


def test_a_blocklisted_ip_is_flagged_without_an_api_call(
    city_db, asn_db, session, tmp_path
):
    blocklist = tmp_path / "bad.txt"
    blocklist.write_text("8.8.8.8\n")
    with GeoIPEnricher(city_db) as geo, ASNEnricher(asn_db) as asn, IPReputationEnricher(
        api_key="test-key", session=session, blocklist_path=blocklist
    ) as reputation:
        out = enrich_event(
            {"source_ip": "8.8.8.8"}, geoip=geo, asn=asn, reputation=reputation
        )
    assert out["is_known_threat"] is True
    assert out["reputation_score"] == 100
    assert out["threat_categories"] == ["local_blocklist"]
    assert session.calls == []


def test_every_enrichment_field_is_always_present(enrichers):
    for ip in ("8.8.8.8", "10.0.0.1", UNKNOWN_PUBLIC_IP, "garbage", None):
        out = enrich_event({"source_ip": ip}, **enrichers)
        assert set(ENRICHMENT_FIELDS) <= set(out)
    assert set(REPUTATION_FIELDS) <= set(ENRICHMENT_FIELDS)


def test_private_ip_is_not_sent_to_the_reputation_api(enrichers, session):
    out = enrich_event({"source_ip": "192.168.1.1"}, **enrichers)
    assert out["geo_is_private"] is True
    assert out["geo_country"] is None
    assert out["asn_number"] is None and out["asn_org"] is None
    assert {f: out[f] for f in REPUTATION_FIELDS} == REPUTATION_NONE
    assert session.calls == []


def test_invalid_and_missing_ip_do_not_raise(enrichers):
    bad = enrich_event({"source_ip": "not_an_ip"}, **enrichers)
    missing = enrich_event({"event_id": "x"}, **enrichers)
    for out in (bad, missing):
        nullable = set(ENRICHMENT_FIELDS) - {"is_known_threat", "threat_categories"}
        assert all(out[f] is None for f in nullable)
        assert out["is_known_threat"] is False
        assert out["threat_categories"] == []


def test_input_is_not_mutated_and_other_fields_survive(enrichers):
    event = {"source_ip": "8.8.8.8", "username": "alice", "nested": {"a": 1}}
    snapshot = {"source_ip": "8.8.8.8", "username": "alice", "nested": {"a": 1}}
    out = enrich_event(event, **enrichers)
    assert event == snapshot
    assert out["username"] == "alice" and out["nested"] == {"a": 1}
    assert out is not event


def test_enriching_twice_is_idempotent(enrichers):
    once = enrich_event({"source_ip": "81.2.69.142"}, **enrichers)
    assert enrich_event(once, **enrichers) == once


def test_stale_enrichment_fields_are_overwritten(enrichers):
    out = enrich_event(
        {
            "source_ip": "8.8.8.8",
            "asn_org": "STALE",
            "is_known_threat": True,
            "reputation_score": 99,
            "threat_categories": ["stale"],
        },
        **enrichers,
    )
    assert out["asn_org"] == "GOOGLE"
    assert out["is_known_threat"] is False and out["reputation_score"] == 0
    assert out["threat_categories"] == []


def test_each_event_gets_its_own_categories_list(enrichers):
    first = enrich_event({"source_ip": "81.2.69.142"}, **enrichers)
    first["threat_categories"].append("tampered")
    second = enrich_event({"source_ip": "81.2.69.142"}, **enrichers)
    assert second["threat_categories"] == ["brute_force", "ssh"]


def test_custom_ip_field(enrichers):
    out = enrich_event({"client_ip": "8.8.8.8"}, ip_field="client_ip", **enrichers)
    assert out["asn_number"] == 15169 and out["geo_country"] == "US"
    assert out["reputation_score"] == 0


def test_accepts_any_mapping(enrichers):
    from types import MappingProxyType

    out = enrich_event(MappingProxyType({"source_ip": "8.8.8.8"}), **enrichers)
    assert out["asn_org"] == "GOOGLE"


@pytest.mark.parametrize("bad", [None, "8.8.8.8", ["8.8.8.8"], 5, object()])
def test_non_mapping_event_is_a_type_error(bad, enrichers):
    with pytest.raises(TypeError, match="mapping"):
        enrich_event(bad, **enrichers)


class Exploding:
    def enrich(self, ip):
        raise RuntimeError("boom")


def test_one_failing_enricher_does_not_lose_the_others(city_db, asn_db, session, caplog):
    with GeoIPEnricher(city_db) as geo, ASNEnricher(asn_db) as asn, IPReputationEnricher(
        api_key="test-key", session=session
    ) as reputation, caplog.at_level(logging.ERROR, logger="enrichment.pipeline"):
        # ASN explodes: geo and reputation survive
        out = enrich_event(
            {"source_ip": "8.8.8.8"}, geoip=geo, asn=Exploding(), reputation=reputation
        )
        assert out["geo_country"] == "US" and out["reputation_score"] == 0
        assert out["asn_number"] is None and out["asn_org"] is None
        assert any("ASN enrichment failed" in r.getMessage() for r in caplog.records)

        # GeoIP explodes: ASN and reputation survive
        out = enrich_event(
            {"source_ip": "8.8.8.8"}, geoip=Exploding(), asn=asn, reputation=reputation
        )
        assert out["asn_number"] == 15169 and out["reputation_score"] == 0
        assert out["geo_country"] is None and out["geo_is_private"] is None

        # reputation explodes: geo and ASN survive, safe defaults for the rest
        out = enrich_event(
            {"source_ip": "8.8.8.8"}, geoip=geo, asn=asn, reputation=Exploding()
        )
        assert out["geo_country"] == "US" and out["asn_number"] == 15169
        assert {f: out[f] for f in REPUTATION_FIELDS} == REPUTATION_NONE
        assert any("IP reputation enrichment failed" in r.getMessage() for r in caplog.records)


def test_missing_databases_and_api_key_degrade_to_nulls(tmp_path):
    geo = GeoIPEnricher(tmp_path / "a.mmdb")
    asn = ASNEnricher(tmp_path / "b.mmdb")
    reputation = IPReputationEnricher(api_key="", blocklist_path=tmp_path / "c.txt")
    out = enrich_event(
        {"source_ip": "8.8.8.8"}, geoip=geo, asn=asn, reputation=reputation
    )
    assert out["geo_is_private"] is False  # still classified without a DB
    assert out["geo_country"] is None and out["asn_number"] is None
    assert {f: out[f] for f in REPUTATION_FIELDS} == REPUTATION_NONE


def test_default_enrichers_use_env_paths_and_are_shared(
    monkeypatch, city_db, asn_db, tmp_path
):
    blocklist = tmp_path / "bad.txt"
    blocklist.write_text("81.2.69.142\n")
    monkeypatch.setenv(GEO_ENV, city_db)
    monkeypatch.setenv(ASN_ENV, asn_db)
    monkeypatch.setenv(ENV_BLOCKLIST_PATH, str(blocklist))
    reset_default_enrichers()
    try:
        first = enrich_event({"source_ip": "8.8.8.8"})
        second = enrich_event({"source_ip": "81.2.69.142"})
        assert first["geo_country"] == "US" and first["asn_number"] == 15169
        assert first["is_known_threat"] is False  # no API key: blocklist only
        assert second["geo_country"] == "GB"
        assert second["asn_number"] == KNOWN_ASNS["81.2.69.142"][0]
        assert second["is_known_threat"] is True  # from the env-configured blocklist

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