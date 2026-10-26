"""GeoIP enrichment backed by a local MaxMind GeoLite2-City database.

Lookups are local, memory-mapped file reads (not network calls). The database
``Reader`` is opened once per ``GeoIPEnricher`` instance and reused for every
event; repeated IPs are additionally served from an in-process LRU cache.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional, Union

import geoip2.database
import geoip2.errors
from maxminddb import InvalidDatabaseError

from enrichment.ip_utils import is_non_public, parse_ip

logger = logging.getLogger(__name__)

ENV_DB_PATH = "GEOIP_DB_PATH"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = REPO_ROOT / "data" / "GeoLite2-City.mmdb"

_NULL_GEO: dict[str, Any] = {
    "country": None,
    "city": None,
    "latitude": None,
    "longitude": None,
}

# A flood of malformed IPs must not flood the logs: log the first N, then
# only every Nth.
_WARN_FIRST_N = 50
_WARN_EVERY_NTH = 1000


def resolve_db_path(db_path: Optional[Union[str, Path]] = None) -> Path:
    """Explicit argument > $GEOIP_DB_PATH > <repo>/data/GeoLite2-City.mmdb.

    Relative paths (e.g. ``GEOIP_DB_PATH=data/GeoLite2-City.mmdb`` from
    .env.example) are anchored at the repo root, not the process's working
    directory: Spark workers do not run from the repo root.
    """
    path = Path(db_path or os.getenv(ENV_DB_PATH) or DEFAULT_DB_PATH)
    return path if path.is_absolute() else REPO_ROOT / path


class GeoIPEnricher:
    """Resolve an IP address to country / city / coordinates.

    Args:
        db_path: Path to GeoLite2-City.mmdb (see ``resolve_db_path``).
        reader: Pre-built reader (dependency injection, used by tests).
        cache_size: LRU entries for repeated IPs (0 disables caching).
        precision: Decimal places kept for latitude / longitude.
        strict: If True, raise when the database cannot be opened. If False
            (default) the enricher degrades gracefully: private IPs still
            work and public IPs get null geo fields, so a missing database
            never takes the streaming pipeline down.
    """

    def __init__(
        self,
        db_path: Optional[Union[str, Path]] = None,
        *,
        reader: Optional[Any] = None,
        cache_size: int = 10_000,
        precision: int = 2,
        strict: bool = False,
    ) -> None:
        self._precision = precision
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
        try:
            reader = geoip2.database.Reader(str(path))
            logger.info("GeoIP database loaded from %s", path)
            return reader
        except (FileNotFoundError, InvalidDatabaseError, OSError) as exc:
            if strict:
                raise
            logger.error(
                "GeoIP database unavailable at %s (%s). Public IPs will not be "
                "enriched. See README.md ('GeoIP Database Setup').",
                path,
                exc,
            )
            return None

    @property
    def database_loaded(self) -> bool:
        return self._reader is not None

    # ------------------------------------------------------------------ public
    def enrich(self, ip: str) -> dict[str, Any]:
        """Return geo metadata for ``ip``. Never raises.

        Keys: country (ISO code), city, latitude, longitude, is_private.

        * Private / loopback / link-local / reserved / multicast:
          geo fields None, ``is_private`` True. No database access.
        * Invalid input: every field None (``is_private`` too) + a warning.
        * Public but not in the database (or database missing):
          geo fields None, ``is_private`` False.
        """
        addr = self._parse(ip)
        if addr is None:
            self._warn_invalid(ip)
            return {**_NULL_GEO, "is_private": None}

        if self._is_non_public(addr):
            return {**_NULL_GEO, "is_private": True}

        return {**self._lookup(str(addr)), "is_private": False}

    def close(self) -> None:
        if self._owns_reader and self._reader is not None:
            self._reader.close()
            self._reader = None

    def __enter__(self) -> "GeoIPEnricher":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ---------------------------------------------------------------- internals
    @staticmethod
    def _parse(
        ip: Any,
    ) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
        return parse_ip(ip)

    @staticmethod
    def _is_non_public(
        addr: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
    ) -> bool:
        return is_non_public(addr)

    def _lookup_uncached(self, ip: str) -> dict[str, Any]:
        if self._reader is None:
            return dict(_NULL_GEO)
        try:
            resp = self._reader.city(ip)
        except geoip2.errors.AddressNotFoundError:
            return dict(_NULL_GEO)
        except Exception:  # corrupt DB, wrong DB type, ... never break the stream
            logger.exception("GeoIP lookup failed for %s", ip)
            return dict(_NULL_GEO)

        lat, lon = resp.location.latitude, resp.location.longitude
        return {
            "country": resp.country.iso_code,
            "city": resp.city.name,
            "latitude": round(lat, self._precision) if lat is not None else None,
            "longitude": round(lon, self._precision) if lon is not None else None,
        }

    def _warn_invalid(self, value: Any) -> None:
        self._invalid_count += 1
        n = self._invalid_count
        if n <= _WARN_FIRST_N or n % _WARN_EVERY_NTH == 0:
            logger.warning(
                "GeoIP: invalid IP address %r (invalid inputs so far: %d)",
                str(value)[:64],
                n,
            )