"""Single-call event enrichment: GeoIP + ASN + IP reputation in one
``enrich_event(event)``.

For plain-Python callers (scripts, replay tools, the API layer, tests). The
Spark stream uses the vectorized equivalents in
``enrichment.spark_enrichment``; both produce the same column names, which
tests/enrichment/test_enrichment_contract.py pins.

Importing this module never pulls in PySpark.

Fields added to the event (all always present, None when unknown):

    geo_country, geo_city, geo_latitude, geo_longitude, geo_is_private,
    asn_number, asn_org,
    reputation_score, is_known_threat, threat_categories
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Mapping, Optional

from enrichment.asn import ASNEnricher
from enrichment.geoip import GeoIPEnricher
from enrichment.ip_reputation import IPReputationEnricher

logger = logging.getLogger(__name__)

DEFAULT_IP_FIELD = "source_ip"

# GeoIPEnricher.enrich() key -> event field (same names as the Spark stream)
GEO_FIELD_MAP: dict[str, str] = {
    "country": "geo_country",
    "city": "geo_city",
    "latitude": "geo_latitude",
    "longitude": "geo_longitude",
    "is_private": "geo_is_private",
}
# ASNEnricher.enrich() keys are already the event field names.
ASN_FIELDS: tuple[str, ...] = ("asn_number", "asn_org")

# IPReputationEnricher.enrich() keys are already the event field names.
REPUTATION_FIELDS: tuple[str, ...] = (
    "reputation_score",
    "is_known_threat",
    "threat_categories",
)
# What an event gets when the reputation enricher itself fails.
_REPUTATION_DEFAULTS: dict[str, Any] = {
    "reputation_score": None,
    "is_known_threat": False,
    "threat_categories": [],
}

ENRICHMENT_FIELDS: tuple[str, ...] = (
    *GEO_FIELD_MAP.values(),
    *ASN_FIELDS,
    *REPUTATION_FIELDS,
)

_defaults: dict[str, Any] = {}
_lock = threading.Lock()


def _default(name: str, factory) -> Any:
    """Lazily build one process-wide enricher so the Reader opens only once."""
    enricher = _defaults.get(name)
    if enricher is None:
        with _lock:
            enricher = _defaults.get(name)
            if enricher is None:
                enricher = factory()
                _defaults[name] = enricher
    return enricher


def reset_default_enrichers() -> None:
    """Close and forget the shared enrichers (e.g. after replacing the DBs)."""
    with _lock:
        for enricher in _defaults.values():
            enricher.close()
        _defaults.clear()


def enrich_event(
    event: Mapping[str, Any],
    *,
    geoip: Optional[GeoIPEnricher] = None,
    asn: Optional[ASNEnricher] = None,
    reputation: Optional[IPReputationEnricher] = None,
    ip_field: str = DEFAULT_IP_FIELD,
) -> dict[str, Any]:
    """Return a copy of ``event`` with GeoIP, ASN and reputation fields added.

    Args:
        event: Mapping with the IP to look up under ``ip_field``.
        geoip / asn / reputation: Enrichers to use. Default: shared
            process-wide instances configured from ``GEOIP_DB_PATH``,
            ``ASN_DB_PATH``, ``ABUSEIPDB_API_KEY`` and ``KNOWN_BAD_IPS_PATH``.
        ip_field: Key holding the IP address (default ``source_ip``).

    The input is never mutated, and existing enrichment fields are
    overwritten (so enriching twice is idempotent). A missing database or API
    key, a private / invalid / absent IP, or a failure in one enricher yields
    null fields (``is_known_threat`` False, ``threat_categories`` []); it never
    raises and never costs another enricher's result.

    Raises:
        TypeError: if ``event`` is not a mapping (a programming error).
    """
    if not isinstance(event, Mapping):
        raise TypeError(
            f"event must be a mapping, got {type(event).__name__}"
        )

    geoip = geoip if geoip is not None else _default("geoip", GeoIPEnricher)
    asn = asn if asn is not None else _default("asn", ASNEnricher)
    reputation = (
        reputation
        if reputation is not None
        else _default("reputation", IPReputationEnricher)
    )

    ip = event.get(ip_field)
    enriched = dict(event)

    geo = _safe_enrich(geoip, ip, "GeoIP")
    for key, field in GEO_FIELD_MAP.items():
        enriched[field] = geo.get(key)

    asn_result = _safe_enrich(asn, ip, "ASN")
    for field in ASN_FIELDS:
        enriched[field] = asn_result.get(field)

    reputation_result = _safe_enrich(reputation, ip, "IP reputation")
    for field in REPUTATION_FIELDS:
        value = reputation_result.get(field, _REPUTATION_DEFAULTS[field])
        enriched[field] = list(value) if field == "threat_categories" else value

    return enriched


def _safe_enrich(enricher: Any, ip: Any, label: str) -> Mapping[str, Any]:
    # The enrichers already swallow their own errors; this is the last line of
    # defence so one misbehaving enricher can't discard the other's result.
    try:
        return enricher.enrich(ip)
    except Exception:
        logger.exception("%s enrichment failed for %r", label, str(ip)[:64])
        return {}