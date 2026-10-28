"""ASN enrichment backed by a local MaxMind GeoLite2-ASN database.

Maps a source IP to its Autonomous System Number and organization name.

Database lookups are local. The database reader is opened once per
ASNEnricher instance and reused for every event. Repeated IPs are served
from an in-process LRU cache.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional, Union

import geoip2.database
import geoip2.errors
import maxminddb
from maxminddb import InvalidDatabaseError

from enrichment.geoip import REPO_ROOT
from enrichment.ip_utils import is_non_public, parse_ip

logger = logging.getLogger(__name__)

ENV_DB_PATH = "ASN_DB_PATH"
DEFAULT_DB_PATH = REPO_ROOT / "data" / "GeoLite2-ASN.mmdb"

ASN_NUMBER_KEY = "asn_number"
ASN_ORG_KEY = "asn_org"

_NULL_ASN: dict[str, Any] = {
    ASN_NUMBER_KEY: None,
    ASN_ORG_KEY: None,
}

# Rate-limit warnings for malformed IP addresses.
_WARN_FIRST_N = 50
_WARN_EVERY_NTH = 1000


def resolve_db_path(
    db_path: Optional[Union[str, Path]] = None,
) -> Path:
    """Resolve the ASN database path.

    Priority:
        1. Explicit db_path argument.
        2. ASN_DB_PATH environment variable.
        3. Default repository data directory.

    Relative paths are anchored at the repository root.
    """
    path = Path(db_path or os.getenv(ENV_DB_PATH) or DEFAULT_DB_PATH)

    if path.is_absolute():
        return path

    return REPO_ROOT / path


class ASNEnricher:
    """Resolve an IP address to its ASN number and organization.

    Args:
        db_path: Path to the GeoLite2-ASN database.
        reader: Optional pre-built reader, primarily for dependency injection
            in tests. It must provide an asn(ip) method and may provide close().
        cache_size: Maximum number of cached lookups. Zero disables caching.
        strict: If True, raise an exception when the database cannot be opened
            or is not an ASN database. Otherwise, degrade gracefully.
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
            self._reader = self._open_reader(
                resolve_db_path(db_path),
                strict,
            )
            self._owns_reader = self._reader is not None

        if cache_size > 0:
            self._lookup = lru_cache(maxsize=cache_size)(
                self._lookup_uncached
            )
        else:
            self._lookup = self._lookup_uncached

    # ------------------------------------------------------------------
    # Database setup
    # ------------------------------------------------------------------

    @staticmethod
    def _open_reader(
        path: Path,
        strict: bool,
    ) -> Optional[geoip2.database.Reader]:
        """Open and validate the ASN database.

        MODE_FILE is explicitly selected to avoid the incorrect signed
        interpretation of some unsigned 32-bit ASN values observed with
        MODE_AUTO in the current environment.
        """
        reader: Optional[geoip2.database.Reader] = None

        try:
            reader = geoip2.database.Reader(
                str(path),
                mode=maxminddb.MODE_FILE,
            )

            # Fail early if the supplied database is not an ASN database.
            db_type = reader.metadata().database_type

            if "ASN" not in db_type:
                raise InvalidDatabaseError(
                    f"{path} is a {db_type!r} database; "
                    "expected an ASN database."
                )

            logger.info("ASN database loaded from %s", path)
            return reader

        except (
            FileNotFoundError,
            InvalidDatabaseError,
            OSError,
        ) as exc:
            if reader is not None:
                reader.close()

            if strict:
                raise

            logger.error(
                "ASN database unavailable at %s (%s). "
                "IP addresses will not be enriched with ASN data. "
                "See README.md ('ASN Database Setup').",
                path,
                exc,
            )
            return None

    @property
    def database_loaded(self) -> bool:
        """Return whether the ASN database loaded successfully."""
        return self._reader is not None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich(self, ip: str) -> dict[str, Any]:
        """Return ASN metadata for an IP address.

        Returns:
            A dictionary containing:
                - asn_number: ASN integer or None.
                - asn_org: Organization name or None.

        Private, loopback, link-local, reserved, and multicast addresses
        return null fields without querying the database.

        Invalid addresses return null fields and produce rate-limited
        warnings. Missing database entries also return null fields.
        """
        addr = parse_ip(ip)

        if addr is None:
            self._warn_invalid(ip)
            return dict(_NULL_ASN)

        if is_non_public(addr):
            return dict(_NULL_ASN)

        # Return a copy so callers cannot mutate the cached dictionary.
        return dict(self._lookup(str(addr)))

    def close(self) -> None:
        """Close the owned reader and clear cached lookups."""
        if self._owns_reader and self._reader is not None:
            self._reader.close()
            self._reader = None

        cache_clear = getattr(self._lookup, "cache_clear", None)

        if cache_clear is not None:
            cache_clear()

    def __enter__(self) -> "ASNEnricher":
        """Support use as a context manager."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close resources when leaving a context manager."""
        self.close()

    # ------------------------------------------------------------------
    # Internal lookup and logging
    # ------------------------------------------------------------------

    def _lookup_uncached(self, ip: str) -> dict[str, Any]:
        """Perform an uncached ASN lookup."""
        reader = self._reader

        if reader is None:
            return dict(_NULL_ASN)

        try:
            response = reader.asn(ip)

        except geoip2.errors.AddressNotFoundError:
            return dict(_NULL_ASN)

        except Exception:
            # Database errors must not interrupt the streaming pipeline.
            logger.exception("ASN lookup failed for %s", ip)
            return dict(_NULL_ASN)

        return {
            ASN_NUMBER_KEY: response.autonomous_system_number,
            ASN_ORG_KEY: response.autonomous_system_organization,
        }

    def _warn_invalid(self, value: Any) -> None:
        """Log invalid IP addresses without flooding the logs."""
        self._invalid_count += 1
        count = self._invalid_count

        if count <= _WARN_FIRST_N or count % _WARN_EVERY_NTH == 0:
            logger.warning(
                "ASN: invalid IP address %r "
                "(invalid inputs so far: %d)",
                str(value)[:64],
                count,
            )
