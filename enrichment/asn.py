"""ASN enrichment backed by a local MaxMind GeoLite2-ASN database.

Maps a source IP to its Autonomous System Number and organization name, which
tells an analyst *what kind of network* traffic came from (a cloud provider
such as DIGITALOCEAN or AMAZON, a residential ISP, a hosting company, ...).

Same design as ``enrichment.geoip``: lookups are local, memory-mapped file
reads (not network calls); the database ``Reader`` is opened once per
``ASNEnricher`` instance and reused for every event, and repeated IPs are
additionally served from an in-process LRU cache.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional, Union

import geoip2.database
import geoip2.errors
from maxminddb import InvalidDatabaseError

from enrichment.geoip import REPO_ROOT
from enrichment.ip_utils import is_non_public, parse_ip

logger = logging.getLogger(__name__)

ENV_DB_PATH = "ASN_DB_PATH"
DEFAULT_DB_PATH = REPO_ROOT / "data" / "GeoLite2-ASN.mmdb"

ASN_NUMBER_KEY = "asn_number"
ASN_ORG_KEY = "asn_org"

_NULL_ASN: dict[str, Any] = {ASN_NUMBER_KEY: None, ASN_ORG_KEY: None}

# A flood of malformed IPs must not flood the logs: log the first N, then
# only every Nth.
_WARN_FIRST_N = 50
_WARN_EVERY_NTH = 1000


def resolve_db_path(db_path: Optional[Union[str, Path]] = None) -> Path:
    """Explicit argument > $ASN_DB_PATH > <repo>/data/GeoLite2-ASN.mmdb.

    Relative paths (e.g. ``ASN_DB_PATH=data/GeoLite2-ASN.mmdb`` from
    .env.example) are anchored at the repo root, not the process's working
    directory: Spark workers do not run from the repo root.
    """
    path = Path(db_path or os.getenv(ENV_DB_PATH) or DEFAULT_DB_PATH)
    return path if path.is_absolute() else REPO_ROOT / path


class ASNEnricher:
    """Resolve an IP address to its ASN number and organization.

    Args:
        db_path: Path to GeoLite2-ASN.mmdb (see ``resolve_db_path``).
        reader: Pre-built reader (dependency injection, used by tests). Any
            object with an ``asn(ip)`` method and, optionally, ``close()``.
        cache_size: LRU entries for repeated IPs (0 disables caching).
        strict: If True, raise when the database cannot be opened or is not
            an ASN database. If False (default) the enricher degrades
            gracefully: every lookup returns null fields, so a missing
            database never takes the streaming pipeline down.
    """

    def __init__(
        self,
        db_path: Optional[Union[str, Path]] = None,
        *,
        reader: Optional[Any] = None,
        cache_size: int = 10_000,
        strict: bool = False,
    ) -> None:
        self._invalid_count = 0
        self._reader = reader
        self._owns_reader = False

        if reader is None:
            self._reader = self._open_reader(resolve_db_path(db_path), strict)
            self._owns_reader = self._reader is not None

        self._lookup = (
            lru_cache(maxsize=cache_size)(self._lookup_uncached)
            if cache_size > 0
            else self._lookup_uncached
        )

    # ------------------------------------------------------------------ setup
    @staticmethod
    def _open_reader(path: Path, strict: bool) -> Optional[geoip2.database.Reader]:
        reader: Optional[geoip2.database.Reader] = None
        try:
            reader = geoip2.database.Reader(str(path))
            # Fail fast on a misconfigured path (e.g. ASN_DB_PATH pointing at
            # the City database) instead of failing on every single lookup.
            db_type = reader.metadata().database_type
            if "ASN" not in db_type:
                raise InvalidDatabaseError(
                    f"{path} is a {db_type!r} database, expected an ASN database"
                )
            logger.info("ASN database loaded from %s", path)
            return reader
        except (FileNotFoundError, InvalidDatabaseError, OSError) as exc:
            if reader is not None:
                reader.close()
            if strict:
                raise
            logger.error(
                "ASN database unavailable at %s (%s). IPs will not be "
                "enriched with ASN data. See README.md ('ASN Database Setup').",
                path,
                exc,
            )
            return None

    @property
    def database_loaded(self) -> bool:
        return self._reader is not None

    # ------------------------------------------------------------------ public
    def enrich(self, ip: str) -> dict[str, Any]:
        """Return ASN metadata for ``ip``. Never raises.

        Keys: ``asn_number`` (int) and ``asn_org`` (str).

        * Private / loopback / link-local / reserved / multicast:
          both None. No database access.
        * Invalid input: both None + a (rate-limited) warning.
        * Public but not in the database (or database missing): both None.
        """
        addr = parse_ip(ip)
        if addr is None:
            self._warn_invalid(ip)
            return dict(_NULL_ASN)

        if is_non_public(addr):
            return dict(_NULL_ASN)

        # Copy: the cached dict must never be mutated by a caller.
        return dict(self._lookup(str(addr)))

    def close(self) -> None:
        if self._owns_reader and self._reader is not None:
            self._reader.close()
            self._reader = None
        cache_clear = getattr(self._lookup, "cache_clear", None)
        if cache_clear is not None:
            cache_clear()

    def __enter__(self) -> "ASNEnricher":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ---------------------------------------------------------------- internals
    def _lookup_uncached(self, ip: str) -> dict[str, Any]:
        reader = self._reader
        if reader is None:
            return dict(_NULL_ASN)
        try:
            resp = reader.asn(ip)
        except geoip2.errors.AddressNotFoundError:
            return dict(_NULL_ASN)
        except Exception:  # corrupt DB, wrong DB type, ... never break the stream
            logger.exception("ASN lookup failed for %s", ip)
            return dict(_NULL_ASN)

        return {
            ASN_NUMBER_KEY: resp.autonomous_system_number,
            ASN_ORG_KEY: resp.autonomous_system_organization,
        }

    def _warn_invalid(self, value: Any) -> None:
        self._invalid_count += 1
        n = self._invalid_count
        if n <= _WARN_FIRST_N or n % _WARN_EVERY_NTH == 0:
            logger.warning(
                "ASN: invalid IP address %r (invalid inputs so far: %d)",
                str(value)[:64],
                n,
            )