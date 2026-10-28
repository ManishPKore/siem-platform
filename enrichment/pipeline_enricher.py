"""Unified enrichment stage: GeoIP + ASN + IP reputation behind one object.

    normalizer -> [ PipelineEnricher ] -> rules engine / sinks

``PipelineEnricher`` composes the three enrichers so the Spark pipeline makes
one pass over each event (one UDF, see ``enrichment.spark_enrichment``)
instead of three, and so failure handling, private-IP handling and batching
live in exactly one place.

Output fields (stream column names; every one is always present):

    geo_country, geo_city, geo_latitude, geo_longitude, geo_is_private,
    asn_number, asn_org,
    reputation_score, is_known_threat, threat_categories

Guarantees
    * Never raises. A failing enricher yields null fields for that enricher
      only (``is_known_threat`` False, ``threat_categories`` []), never for
      the others, and never an exception in the streaming job.
    * Only public IPs are looked up. Private / loopback / reserved / invalid
      IPs skip the databases and the AbuseIPDB API entirely. (The local
      blocklist is still consulted, so a known-compromised internal host can
      be flagged; see ``enrichment.ip_reputation``.)
    * ``enrich_many`` is the batch path used by the Spark UDF: it enriches
      each *distinct* IP once per batch (attack traffic repeats IPs a lot)
      and prefetches AbuseIPDB results for all the new IPs concurrently, so
      the average per-event cost is dominated by in-memory lookups, not by
      network round trips.

Caching
    The enrichers cache per instance: GeoIP/ASN in an LRU, reputation in a
    1-hour TTL cache. Under Spark the instance lives in each Python worker
    process (``enrichment.spark_enrichment.get_pipeline_enricher``) and
    survives across micro-batches and partitions processed by that worker, so
    a broadcast variable is not needed: the MMDB readers cannot be pickled
    anyway, and per-worker caches are what keeps repeat IPs cheap. The cost
    is that N workers each warm their own cache and spend from the same
    AbuseIPDB quota (see ``enrichment.ip_reputation``).
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Iterable, Optional, Union

from enrichment.asn import ASNEnricher
from enrichment.asn import resolve_db_path as resolve_asn_db_path
from enrichment.geoip import GeoIPEnricher
from enrichment.geoip import resolve_db_path as resolve_geoip_db_path
from enrichment.ip_reputation import (
    DEFAULT_PREFETCH_DEADLINE_SECONDS,
    DEFAULT_PREFETCH_WORKERS,
    IPReputationEnricher,
    api_key_configured,
    resolve_blocklist_path,
)
from enrichment.ip_utils import is_non_public, parse_ip

logger = logging.getLogger(__name__)

# GeoIPEnricher.enrich() key -> output field
GEO_FIELD_MAP: dict[str, str] = {
    "country": "geo_country",
    "city": "geo_city",
    "latitude": "geo_latitude",
    "longitude": "geo_longitude",
    "is_private": "geo_is_private",
}
ASN_FIELDS: tuple[str, ...] = ("asn_number", "asn_org")
REPUTATION_FIELDS: tuple[str, ...] = (
    "reputation_score",
    "is_known_threat",
    "threat_categories",
)
ENRICHMENT_FIELDS: tuple[str, ...] = (
    *GEO_FIELD_MAP.values(),
    *ASN_FIELDS,
    *REPUTATION_FIELDS,
)

# Log the first few enricher failures, then only every Nth, so a systemic
# failure (say a corrupt database) cannot flood the logs once per event.
_LOG_FIRST_N = 20
_LOG_EVERY_NTH = 1000


def null_enrichment() -> dict[str, Any]:
    """What an event gets when nothing could be (or should be) looked up."""
    result: dict[str, Any] = {field: None for field in ENRICHMENT_FIELDS}
    result["is_known_threat"] = False
    result["threat_categories"] = []
    return result


class PipelineEnricher:
    """Compose GeoIP, ASN and IP-reputation enrichment.

    Args:
        geoip / asn / reputation: Pre-built enrichers (dependency injection,
            used by tests). Any omitted enricher is built from its own
            configuration (``GEOIP_DB_PATH``, ``ASN_DB_PATH``,
            ``ABUSEIPDB_API_KEY``, ``KNOWN_BAD_IPS_PATH``) and owned (closed)
            by this object.
        geoip_db_path / asn_db_path / blocklist_path: Override those paths
            when the enrichers are built here.
        prefetch_workers: Concurrency of the batch AbuseIPDB prefetch.
        prefetch_deadline_seconds: Longest a batch waits for those lookups.
            Afterwards the batch is enriched from the cache only, so a slow
            or hanging API can never stall the stream; IPs whose lookup did
            not finish are simply not assessed in this batch (they are
            retried in the next one, and finished lookups still land in the
            cache).
    """

    def __init__(
        self,
        *,
        geoip: Optional[GeoIPEnricher] = None,
        asn: Optional[ASNEnricher] = None,
        reputation: Optional[IPReputationEnricher] = None,
        geoip_db_path: Optional[Union[str, Path]] = None,
        asn_db_path: Optional[Union[str, Path]] = None,
        blocklist_path: Optional[Union[str, Path]] = None,
        prefetch_workers: int = DEFAULT_PREFETCH_WORKERS,
        prefetch_deadline_seconds: float = DEFAULT_PREFETCH_DEADLINE_SECONDS,
    ) -> None:
        if prefetch_workers < 1:
            raise ValueError("prefetch_workers must be >= 1")
        if prefetch_deadline_seconds <= 0:
            raise ValueError("prefetch_deadline_seconds must be > 0")

        self._owned: list[Any] = []
        if geoip is None:
            geoip = GeoIPEnricher(geoip_db_path)
            self._owned.append(geoip)
        if asn is None:
            asn = ASNEnricher(asn_db_path)
            self._owned.append(asn)
        if reputation is None:
            reputation = IPReputationEnricher(blocklist_path=blocklist_path)
            self._owned.append(reputation)

        self._geoip = geoip
        self._asn = asn
        self._reputation = reputation
        self._prefetch_workers = prefetch_workers
        self._prefetch_deadline = prefetch_deadline_seconds

        self._lock = threading.Lock()
        self._stats = {
            "events": 0,
            "distinct_ips": 0,
            "prefetched": 0,
            "failures_geoip": 0,
            "failures_asn": 0,
            "failures_reputation": 0,
        }

    # ------------------------------------------------------------------ public
    @property
    def stats(self) -> dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def enrich(self, ip: Any) -> dict[str, Any]:
        """Enrich one IP. Never raises. Returns every field in ENRICHMENT_FIELDS."""
        result = self._enrich_one(ip, network=True)
        with self._lock:
            self._stats["events"] += 1
            self._stats["distinct_ips"] += 1
        return result

    def enrich_many(self, ips: Iterable[Any]) -> list[dict[str, Any]]:
        """Enrich a batch, in order. Never raises.

        Each distinct IP is enriched once per call. AbuseIPDB lookups for the
        new public IPs run concurrently first, within a deadline
        (``IPReputationEnricher.prefetch``); everything after that is
        in-memory, so per-event cost does not depend on the network.
        Every returned dict is independent (safe to mutate).
        """
        values = list(ips)
        distinct: dict[Any, None] = dict.fromkeys(values)

        prefetched = 0
        try:
            prefetched = self._reputation.prefetch(
                (ip for ip in distinct if isinstance(ip, str)),
                max_workers=self._prefetch_workers,
                deadline_seconds=self._prefetch_deadline,
            )
        except Exception:  # noqa: BLE001 - prefetch is an optimisation only
            self._record_failure("reputation", "prefetch")

        # Cache-only from here on: the network part of this batch is over.
        enriched = {ip: self._enrich_one(ip, network=False) for ip in distinct}

        with self._lock:
            self._stats["events"] += len(values)
            self._stats["distinct_ips"] += len(distinct)
            self._stats["prefetched"] += prefetched

        return [_copy(enriched[ip]) for ip in values]

    def close(self) -> None:
        for enricher in self._owned:
            try:
                enricher.close()
            except Exception:  # noqa: BLE001
                logger.exception("Closing %s failed", type(enricher).__name__)
        self._owned.clear()

    def __enter__(self) -> "PipelineEnricher":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ---------------------------------------------------------------- internals
    def _enrich_one(self, ip: Any, *, network: bool) -> dict[str, Any]:
        result = null_enrichment()

        addr = parse_ip(ip)
        public = addr is not None and not is_non_public(addr)
        lookup_ip = str(addr) if addr is not None else ip

        # GeoIP also classifies the address (geo_is_private) and warns about
        # invalid input; ASN only does database work for public IPs.
        geo = self._call("geoip", self._geoip, lookup_ip)
        for key, field in GEO_FIELD_MAP.items():
            if key in geo:
                result[field] = geo[key]

        if public:
            asn = self._call("asn", self._asn, lookup_ip)
            for field in ASN_FIELDS:
                if field in asn:
                    result[field] = asn[field]

        # Reputation runs for every parseable address: the local blocklist
        # applies to private hosts too, and the enricher itself never sends a
        # non-public IP to the API.
        if addr is not None:
            reputation = self._call(
                "reputation",
                self._reputation,
                lookup_ip,
                method="enrich" if network else "enrich_cached",
            )
            for field in REPUTATION_FIELDS:
                if field in reputation:
                    value = reputation[field]
                    result[field] = (
                        list(value) if field == "threat_categories" else value
                    )
        return result

    def _call(
        self, label: str, enricher: Any, ip: Any, *, method: str = "enrich"
    ) -> dict[str, Any]:
        try:
            result = getattr(enricher, method)(ip)
            return result if isinstance(result, dict) else {}
        except Exception:  # noqa: BLE001 - one enricher must not sink the batch
            self._record_failure(label, ip)
            return {}

    def _record_failure(self, label: str, ip: Any) -> None:
        with self._lock:
            self._stats[f"failures_{label}"] += 1
            n = self._stats[f"failures_{label}"]
        if n <= _LOG_FIRST_N or n % _LOG_EVERY_NTH == 0:
            logger.exception(
                "%s enrichment failed for %r (failures so far: %d); "
                "emitting null %s fields",
                label,
                str(ip)[:64],
                n,
                label,
            )


def _copy(result: dict[str, Any]) -> dict[str, Any]:
    copied = dict(result)
    copied["threat_categories"] = list(result["threat_categories"])
    return copied


def startup_warnings(
    geoip_db_path: Optional[Union[str, Path]] = None,
    asn_db_path: Optional[Union[str, Path]] = None,
    blocklist_path: Optional[Union[str, Path]] = None,
) -> list[str]:
    """Human-readable warnings about a degraded enrichment setup.

    Meant for the driver to log once at startup: the pipeline still runs in
    every one of these cases, with the affected fields null.
    """
    warnings: list[str] = []
    geoip = resolve_geoip_db_path(geoip_db_path)
    if not geoip.is_file():
        warnings.append(
            f"GeoIP database not found at {geoip}: country, city and location "
            "will be null (see README 'GeoIP Database Setup')"
        )
    asn = resolve_asn_db_path(asn_db_path)
    if not asn.is_file():
        warnings.append(
            f"ASN database not found at {asn}: asn_number and asn_org will be "
            "null (see README 'ASN Database Setup')"
        )
    if not api_key_configured():
        warnings.append(
            "ABUSEIPDB_API_KEY is not set: IP reputation uses the local "
            f"blocklist only ({resolve_blocklist_path(blocklist_path)}); see "
            "README 'Threat Intelligence Setup'"
        )
    return warnings