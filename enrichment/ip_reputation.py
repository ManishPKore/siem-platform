"""IP reputation enrichment: AbuseIPDB lookups with a local blocklist fallback.

Answers "is this source IP a known bad actor?" for analyst triage and for
detection rules. Three fields describe the answer:

    reputation_score   int 0-100 (AbuseIPDB "abuse confidence"), or None when
                       the IP was not assessed (private IP, no API key, API
                       unavailable). None is deliberately not 0: 0 means
                       "assessed and clean".
    is_known_threat    bool. True for any local-blocklist hit, or when the
                       score is >= the threat threshold (default 50).
    threat_categories  list[str], e.g. ["brute_force", "ssh"], most-reported
                       first. ["local_blocklist"] for blocklist hits.

Lookup order for ``enrich(ip)`` (cheapest and most authoritative first):

    1. Local blocklist (data/known_bad_ips.txt). Always wins, applies to any
       address (including a known-compromised private host), costs no API
       call, and is re-checked on every call, so a newly blocklisted IP takes
       effect immediately even if the API result for it is cached as clean.
    2. Private / loopback / reserved / multicast addresses are never sent to
       the API (rate-limit awareness) and are reported as not assessed.
    3. In-process cache (default TTL 1 hour).
    4. AbuseIPDB CHECK endpoint (https://docs.abuseipdb.com/#check-endpoint).

Design notes
    * ``enrich`` never raises. A missing key, an outage, a rate limit or a
      malformed response degrades to "blocklist only" instead of breaking the
      streaming pipeline.
    * Free tier = 1000 checks/day. The enricher keeps a local daily budget
      (UTC day, like AbuseIPDB's reset) and honours HTTP 429 / Retry-After and
      the X-RateLimit-* headers, so it stops calling instead of burning
      requests that will be rejected.
    * Degraded answers are never cached; only real API results are, so the
      enricher recovers as soon as the API does.
    * After several consecutive failures the API is paused for a short
      cooldown, so an outage costs a few timeouts, not one per event.
    * The API key is sent in the ``Key`` header (as AbuseIPDB recommends),
      never in the URL, never logged, never in ``repr``. Redirects are not
      followed, so the header can't be forwarded to another host. Errors are
      logged by exception class name only.
    * State (cache, budget, cooldown) is per ``IPReputationEnricher`` instance,
      i.e. per Python worker process under Spark. Several workers therefore
      each spend from the same account quota; the server-side 429 handling is
      the real backstop. Keep the worker count in mind with the free tier.

Configuration (environment variables; constructor arguments win)
    ABUSEIPDB_API_KEY            API key. Unset/blank = blocklist only + warning.
    KNOWN_BAD_IPS_PATH           default <repo>/data/known_bad_ips.txt
    ABUSEIPDB_THREAT_THRESHOLD   0-100, default 50 (score >= this is a threat)
    ABUSEIPDB_DAILY_LIMIT        local daily call budget, default 1000
"""

from __future__ import annotations

import ipaddress
import logging
import os
import threading
import time
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Any, Callable, Optional, Union

import requests

from enrichment.geoip import REPO_ROOT
from enrichment.ip_utils import IPAddress, is_non_public, parse_ip

logger = logging.getLogger(__name__)

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

ENV_API_KEY = "ABUSEIPDB_API_KEY"
ENV_BLOCKLIST_PATH = "KNOWN_BAD_IPS_PATH"
ENV_THREAT_THRESHOLD = "ABUSEIPDB_THREAT_THRESHOLD"
ENV_DAILY_LIMIT = "ABUSEIPDB_DAILY_LIMIT"

DEFAULT_BLOCKLIST_PATH = REPO_ROOT / "data" / "known_bad_ips.txt"
DEFAULT_THREAT_THRESHOLD = 50
DEFAULT_CACHE_TTL_SECONDS = 3600.0  # 1 hour
DEFAULT_CACHE_MAX_ENTRIES = 10_000
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_AGE_DAYS = 30
DEFAULT_DAILY_LIMIT = 1000  # AbuseIPDB free tier: 1,000 checks/day
DEFAULT_FAILURE_THRESHOLD = 3
DEFAULT_FAILURE_COOLDOWN_SECONDS = 60.0
DEFAULT_BLOCKLIST_RELOAD_SECONDS = 30.0

AUTH_FAILURE_COOLDOWN_SECONDS = 3600.0
RATE_LIMIT_DEFAULT_WAIT_SECONDS = 3600.0
MAX_BLOCK_SECONDS = 86400.0

BLOCKLIST_SCORE = 100
BLOCKLIST_CATEGORY = "local_blocklist"

REPUTATION_SCORE_KEY = "reputation_score"
IS_KNOWN_THREAT_KEY = "is_known_threat"
THREAT_CATEGORIES_KEY = "threat_categories"

# https://www.abuseipdb.com/categories
CATEGORY_NAMES: dict[int, str] = {
    1: "dns_compromise",
    2: "dns_poisoning",
    3: "fraud_orders",
    4: "ddos_attack",
    5: "ftp_brute_force",
    6: "ping_of_death",
    7: "phishing",
    8: "fraud_voip",
    9: "open_proxy",
    10: "web_spam",
    11: "email_spam",
    12: "blog_spam",
    13: "vpn_ip",
    14: "port_scan",
    15: "hacking",
    16: "sql_injection",
    17: "spoofing",
    18: "brute_force",
    19: "bad_web_bot",
    20: "exploited_host",
    21: "web_app_attack",
    22: "ssh",
    23: "iot_targeted",
}

# A flood of malformed IPs must not flood the logs: log the first N, then
# only every Nth.
_WARN_FIRST_N = 50
_WARN_EVERY_NTH = 1000

_UNSET: Any = object()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def resolve_blocklist_path(path: Optional[Union[str, Path]] = None) -> Path:
    """Explicit argument > $KNOWN_BAD_IPS_PATH > <repo>/data/known_bad_ips.txt.

    Relative paths are anchored at the repo root, not the working directory:
    Spark workers do not run from the repo root.
    """
    resolved = Path(path or os.getenv(ENV_BLOCKLIST_PATH) or DEFAULT_BLOCKLIST_PATH)
    return resolved if resolved.is_absolute() else REPO_ROOT / resolved


def api_key_configured() -> bool:
    """True if ABUSEIPDB_API_KEY is set to a non-blank value."""
    return bool((os.getenv(ENV_API_KEY) or "").strip())


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        value = None  # type: ignore[assignment]
    if value is None or not minimum <= value <= maximum:
        logger.warning(
            "%s=%r is not an integer between %d and %d; using the default (%d)",
            name,
            raw[:32],
            minimum,
            maximum,
            default,
        )
        return default
    return value


def _unassessed() -> dict[str, Any]:
    return {
        REPUTATION_SCORE_KEY: None,
        IS_KNOWN_THREAT_KEY: False,
        THREAT_CATEGORIES_KEY: [],
    }


def _blocklist_hit() -> dict[str, Any]:
    return {
        REPUTATION_SCORE_KEY: BLOCKLIST_SCORE,
        IS_KNOWN_THREAT_KEY: True,
        THREAT_CATEGORIES_KEY: [BLOCKLIST_CATEGORY],
    }


# --------------------------------------------------------------------------- #
# TTL cache
# --------------------------------------------------------------------------- #


class TTLCache:
    """Small thread-safe dict with a per-entry time-to-live and a size bound.

    Every entry gets the same TTL, so insertion order is also expiry order:
    expired entries are always at the front and are purged in O(1) amortised.
    When full, the oldest entry is evicted. ``clock`` is injectable for tests.
    """

    def __init__(
        self,
        ttl_seconds: float,
        max_entries: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        if max_entries <= 0:
            raise ValueError("max_entries must be > 0")
        self._ttl = float(ttl_seconds)
        self._max_entries = max_entries
        self._clock = clock
        self._data: "OrderedDict[str, tuple[float, Any]]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str, default: Any = None) -> Any:
        now = self._clock()
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return default
            expires_at, value = entry
            if expires_at <= now:
                del self._data[key]
                return default
            return value

    def set(self, key: str, value: Any) -> None:
        now = self._clock()
        with self._lock:
            self._data.pop(key, None)  # re-insert at the end: keeps expiry order
            self._data[key] = (now + self._ttl, value)
            self._purge_expired(now)
            while len(self._data) > self._max_entries:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def _purge_expired(self, now: float) -> None:
        while self._data:
            key, (expires_at, _) = next(iter(self._data.items()))
            if expires_at > now:
                break
            del self._data[key]


# --------------------------------------------------------------------------- #
# Local blocklist
# --------------------------------------------------------------------------- #


class _Snapshot:
    __slots__ = ("addresses", "networks")

    def __init__(
        self,
        addresses: frozenset,
        networks: tuple,
    ) -> None:
        self.addresses = addresses
        self.networks = networks


def parse_blocklist(text: str) -> tuple[set, list, list[int]]:
    """Parse blocklist text into (addresses, networks, invalid_line_numbers).

    Format: one IP or CIDR range per line (IPv4 or IPv6). ``#`` starts a
    comment (whole-line or trailing); blank lines are ignored. A /32 or /128
    is stored as a plain address.
    """
    addresses: set = set()
    networks: list = []
    invalid: list[int] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        token = raw.split("#", 1)[0].strip()
        if not token:
            continue
        addr = parse_ip(token)
        if addr is not None:
            addresses.add(addr)
            continue
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            invalid.append(lineno)
            continue
        if network.prefixlen == network.max_prefixlen:
            addresses.add(network.network_address)
        else:
            networks.append(network)
    return addresses, networks, invalid


class Blocklist:
    """IPs / CIDR ranges loaded from a text file, hot-reloaded when it changes.

    The file is re-checked (one ``stat``) at most every ``reload_interval``
    seconds, so analysts can add an IP while a long-running Spark job is up.
    Lookups read an immutable snapshot, so a reload never blocks or tears a
    lookup. A missing file is an empty blocklist; an unreadable one keeps the
    previous snapshot.
    """

    def __init__(
        self,
        path: Union[str, Path],
        *,
        reload_interval: float = DEFAULT_BLOCKLIST_RELOAD_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._path = Path(path)
        self._reload_interval = reload_interval
        self._clock = clock
        self._lock = threading.Lock()
        self._snapshot = _Snapshot(frozenset(), ())
        self._signature: Optional[tuple[int, int]] = None
        self._missing_logged = False
        self._next_check = 0.0
        with self._lock:
            self._reload()
            self._next_check = self._clock() + self._reload_interval

    @property
    def path(self) -> Path:
        return self._path

    def __len__(self) -> int:
        snapshot = self._snapshot
        return len(snapshot.addresses) + len(snapshot.networks)

    def contains(self, addr: IPAddress) -> bool:
        self._maybe_reload()
        snapshot = self._snapshot
        if addr in snapshot.addresses:
            return True
        return any(
            addr.version == network.version and addr in network
            for network in snapshot.networks
        )

    # ---------------------------------------------------------------- internals
    def _maybe_reload(self) -> None:
        if self._clock() < self._next_check:
            return
        with self._lock:
            now = self._clock()
            if now < self._next_check:  # another thread just did it
                return
            self._next_check = now + self._reload_interval
            self._reload()

    def _reload(self) -> None:
        try:
            stat = self._path.stat()
        except FileNotFoundError:
            if self._signature is not None:
                logger.warning(
                    "IP blocklist %s was removed; blocklist is now empty", self._path
                )
                self._snapshot = _Snapshot(frozenset(), ())
                self._signature = None
            elif not self._missing_logged:
                logger.warning(
                    "IP blocklist not found at %s; no local blocklist entries "
                    "(see README 'Threat Intelligence Setup')",
                    self._path,
                )
            self._missing_logged = True
            return
        except OSError as exc:
            logger.warning(
                "Cannot stat IP blocklist %s (%s); keeping previous entries",
                self._path,
                type(exc).__name__,
            )
            return

        self._missing_logged = False
        signature = (stat.st_mtime_ns, stat.st_size)
        if signature == self._signature:
            return

        try:
            text = self._path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            logger.warning(
                "Cannot read IP blocklist %s (%s); keeping previous entries",
                self._path,
                type(exc).__name__,
            )
            return

        addresses, networks, invalid = parse_blocklist(text)
        self._snapshot = _Snapshot(frozenset(addresses), tuple(networks))
        self._signature = signature
        logger.info(
            "IP blocklist loaded from %s: %d address(es), %d network(s)",
            self._path,
            len(addresses),
            len(networks),
        )
        if invalid:
            logger.warning(
                "IP blocklist %s: ignored %d invalid line(s) (first line numbers: %s)",
                self._path,
                len(invalid),
                ", ".join(str(n) for n in invalid[:5]),
            )


# --------------------------------------------------------------------------- #
# Enricher
# --------------------------------------------------------------------------- #


class IPReputationEnricher:
    """Resolve an IP address to reputation score / threat flag / categories.

    Args:
        api_key: AbuseIPDB API key. ``None`` (default) reads
            $ABUSEIPDB_API_KEY; an empty string explicitly disables the API.
            Without a key the enricher runs on the local blocklist only and
            logs a warning once at construction.
        blocklist_path: See ``resolve_blocklist_path``.
        session: A ``requests.Session``-like object (dependency injection,
            used by tests). If omitted one is created, and closed by
            ``close()``.
        threat_threshold: Score at or above which ``is_known_threat`` is True
            (default 50, or $ABUSEIPDB_THREAT_THRESHOLD).
        cache_ttl: Seconds an API result is reused (default 3600).
        cache_size: Max cached IPs.
        timeout: HTTP timeout per call in seconds.
        max_age_days: AbuseIPDB report window (1-365, default 30).
        fetch_categories: Ask for per-report detail (``verbose``) so
            ``threat_categories`` can be filled in. Costs a larger response
            for heavily reported IPs; turn off to keep payloads light.
        daily_limit: Local per-UTC-day call budget (default 1000, or
            $ABUSEIPDB_DAILY_LIMIT). ``None`` disables the local budget (the
            server-side 429 handling still applies).
        failure_threshold / failure_cooldown: After this many consecutive
            failures the API is paused for this many seconds.
        blocklist_reload_seconds: How often the blocklist file is re-checked.
        clock / wall_clock: Monotonic and epoch time sources (for tests).
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        blocklist_path: Optional[Union[str, Path]] = None,
        session: Optional[Any] = None,
        threat_threshold: Optional[int] = None,
        cache_ttl: float = DEFAULT_CACHE_TTL_SECONDS,
        cache_size: int = DEFAULT_CACHE_MAX_ENTRIES,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_age_days: int = DEFAULT_MAX_AGE_DAYS,
        fetch_categories: bool = True,
        daily_limit: Optional[int] = _UNSET,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        failure_cooldown: float = DEFAULT_FAILURE_COOLDOWN_SECONDS,
        blocklist_reload_seconds: float = DEFAULT_BLOCKLIST_RELOAD_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if threat_threshold is None:
            threat_threshold = _env_int(
                ENV_THREAT_THRESHOLD, DEFAULT_THREAT_THRESHOLD, minimum=0, maximum=100
            )
        if daily_limit is _UNSET:
            daily_limit = _env_int(
                ENV_DAILY_LIMIT, DEFAULT_DAILY_LIMIT, minimum=1, maximum=10_000_000
            )
        if not 0 <= threat_threshold <= 100:
            raise ValueError("threat_threshold must be between 0 and 100")
        if timeout <= 0:
            raise ValueError("timeout must be > 0")
        if not 1 <= max_age_days <= 365:
            raise ValueError("max_age_days must be between 1 and 365")
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if failure_cooldown < 0:
            raise ValueError("failure_cooldown must be >= 0")
        if daily_limit is not None and daily_limit < 1:
            raise ValueError("daily_limit must be >= 1 (or None for no local limit)")

        self._threshold = threat_threshold
        self._timeout = timeout
        self._max_age_days = max_age_days
        self._fetch_categories = fetch_categories
        self._daily_limit = daily_limit
        self._failure_threshold = failure_threshold
        self._failure_cooldown = failure_cooldown
        self._clock = clock
        self._wall_clock = wall_clock

        self._cache = TTLCache(cache_ttl, cache_size, clock=clock)
        self._blocklist = Blocklist(
            resolve_blocklist_path(blocklist_path),
            reload_interval=blocklist_reload_seconds,
            clock=clock,
        )

        if api_key is None:
            api_key = os.getenv(ENV_API_KEY)
        api_key = (api_key or "").strip()
        self._api_key: Optional[str] = api_key or None

        self._owns_session = False
        self._session = None
        if self._api_key is None:
            logger.warning(
                "%s is not set: IP reputation will use the local blocklist only "
                "(%s). Get a free API key at https://www.abuseipdb.com/register",
                ENV_API_KEY,
                self._blocklist.path,
            )
        else:
            if session is None:
                session = requests.Session()
                self._owns_session = True
            self._session = session
            logger.info(
                "AbuseIPDB reputation lookups enabled (cache TTL %ds, "
                "threat threshold %d, daily budget %s)",
                int(cache_ttl),
                self._threshold,
                self._daily_limit if self._daily_limit is not None else "unlimited",
            )

        self._lock = threading.Lock()
        self._blocked_until = 0.0
        self._consecutive_failures = 0
        self._budget_day: Optional[int] = None
        self._calls_today = 0
        self._budget_warned = False
        self._invalid_count = 0
        self._counters = {"api_calls": 0, "cache_hits": 0, "blocklist_hits": 0}

    # ------------------------------------------------------------------ public
    @property
    def api_enabled(self) -> bool:
        return self._api_key is not None and self._session is not None

    @property
    def blocklist_size(self) -> int:
        return len(self._blocklist)

    @property
    def stats(self) -> dict[str, int]:
        """Counters for observability: API calls made, cache and blocklist hits."""
        with self._lock:
            return {**self._counters, "cache_size": len(self._cache)}

    def enrich(self, ip: str) -> dict[str, Any]:
        """Return reputation metadata for ``ip``. Never raises.

        Keys: ``reputation_score`` (int 0-100 or None), ``is_known_threat``
        (bool), ``threat_categories`` (list[str]).

        * In the local blocklist: score 100, threat, ["local_blocklist"],
          no API call.
        * Private / loopback / link-local / reserved / multicast: not
          assessed (score None, not a threat). Never sent to the API.
        * Invalid input: not assessed + a (rate-limited) warning.
        * Public IP: cached or fresh AbuseIPDB result; if the API is
          unavailable, not assessed.
        """
        addr = parse_ip(ip)
        if addr is None:
            self._warn_invalid(ip)
            return _unassessed()

        if self._blocklist.contains(addr):
            self._bump("blocklist_hits")
            return _blocklist_hit()

        if is_non_public(addr) or not self.api_enabled:
            return _unassessed()

        key = str(addr)
        cached = self._cache.get(key)
        if cached is not None:
            self._bump("cache_hits")
            return self._public(cached)

        result = self._query_api(key)
        if result is None:
            return _unassessed()
        self._cache.set(key, result)
        return self._public(result)

    def close(self) -> None:
        session, self._session = self._session, None
        if self._owns_session and session is not None:
            session.close()
        self._cache.clear()

    def __enter__(self) -> "IPReputationEnricher":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __repr__(self) -> str:  # never include the API key
        return (
            f"IPReputationEnricher(api_enabled={self.api_enabled}, "
            f"blocklist_entries={self.blocklist_size})"
        )

    # ---------------------------------------------------------------- internals
    @staticmethod
    def _public(result: dict[str, Any]) -> dict[str, Any]:
        """Fresh copy so callers can never mutate a cached entry."""
        return {
            REPUTATION_SCORE_KEY: result[REPUTATION_SCORE_KEY],
            IS_KNOWN_THREAT_KEY: result[IS_KNOWN_THREAT_KEY],
            THREAT_CATEGORIES_KEY: list(result[THREAT_CATEGORIES_KEY]),
        }

    def _bump(self, counter: str) -> None:
        with self._lock:
            self._counters[counter] += 1

    def _query_api(self, ip: str) -> Optional[dict[str, Any]]:
        if not self._reserve_call():
            return None

        params: dict[str, Any] = {"ipAddress": ip, "maxAgeInDays": self._max_age_days}
        if self._fetch_categories:
            params["verbose"] = ""

        try:
            response = self._session.get(  # type: ignore[union-attr]
                ABUSEIPDB_CHECK_URL,
                headers={"Key": self._api_key, "Accept": "application/json"},
                params=params,
                timeout=self._timeout,
                allow_redirects=False,  # never forward the Key header elsewhere
            )
        except Exception as exc:  # noqa: BLE001 - never break the stream
            self._record_failure(f"request failed ({type(exc).__name__})")
            return None

        status = getattr(response, "status_code", None)
        if status == 200:
            return self._parse_success(response)
        if status == 429:
            self._block_for(
                self._retry_after(response),
                "AbuseIPDB rate limit reached (HTTP 429)",
                level=logging.WARNING,
            )
            return None
        if status in (401, 403):
            self._block_for(
                AUTH_FAILURE_COOLDOWN_SECONDS,
                f"AbuseIPDB rejected the API key (HTTP {status}); check {ENV_API_KEY}",
                level=logging.ERROR,
            )
            return None
        self._record_failure(f"HTTP {status}")
        return None

    def _reserve_call(self) -> bool:
        """Claim one API call from the cooldown and the daily budget."""
        with self._lock:
            if self._clock() < self._blocked_until:
                return False
            if self._daily_limit is not None:
                day = int(self._wall_clock() // 86400)
                if day != self._budget_day:
                    self._budget_day = day
                    self._calls_today = 0
                    self._budget_warned = False
                if self._calls_today >= self._daily_limit:
                    if not self._budget_warned:
                        self._budget_warned = True
                        logger.warning(
                            "AbuseIPDB daily budget of %d call(s) used up; using "
                            "the local blocklist only until the UTC day rolls over",
                            self._daily_limit,
                        )
                    return False
                self._calls_today += 1
            self._counters["api_calls"] += 1
            return True

    def _parse_success(self, response: Any) -> Optional[dict[str, Any]]:
        try:
            data = response.json()["data"]
            score = max(0, min(100, int(data["abuseConfidenceScore"])))
            categories = (
                self._extract_categories(data.get("reports"))
                if self._fetch_categories
                else []
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            self._record_failure("malformed response")
            return None

        with self._lock:
            self._consecutive_failures = 0
        self._note_rate_limit_headers(response)
        return {
            REPUTATION_SCORE_KEY: score,
            IS_KNOWN_THREAT_KEY: score >= self._threshold,
            THREAT_CATEGORIES_KEY: tuple(categories),
        }

    @staticmethod
    def _extract_categories(reports: Any) -> list[str]:
        """Union of report categories, most-reported first (ties by id)."""
        if not isinstance(reports, list):
            return []
        counts: Counter = Counter()
        for report in reports:
            ids = report.get("categories") if isinstance(report, dict) else None
            if not isinstance(ids, list):
                continue
            for category_id in ids:
                if isinstance(category_id, int) and not isinstance(category_id, bool):
                    counts[category_id] += 1
        ordered = sorted(counts, key=lambda cid: (-counts[cid], cid))
        return [CATEGORY_NAMES.get(cid, f"category_{cid}") for cid in ordered]

    def _note_rate_limit_headers(self, response: Any) -> None:
        """Pause calls when AbuseIPDB says the daily quota is used up."""
        headers = getattr(response, "headers", None) or {}
        try:
            remaining = int(headers.get("X-RateLimit-Remaining"))
        except (TypeError, ValueError):
            return
        if remaining > 0:
            return
        try:
            wait = float(headers.get("X-RateLimit-Reset")) - self._wall_clock()
        except (TypeError, ValueError):
            wait = RATE_LIMIT_DEFAULT_WAIT_SECONDS
        self._block_for(
            wait,
            "AbuseIPDB daily quota used up (X-RateLimit-Remaining=0)",
            level=logging.WARNING,
        )

    @staticmethod
    def _retry_after(response: Any) -> float:
        headers = getattr(response, "headers", None) or {}
        try:
            return float(headers.get("Retry-After"))
        except (TypeError, ValueError):
            return RATE_LIMIT_DEFAULT_WAIT_SECONDS

    def _block_for(self, seconds: float, reason: str, *, level: int) -> None:
        seconds = max(1.0, min(float(seconds), MAX_BLOCK_SECONDS))
        with self._lock:
            self._blocked_until = max(self._blocked_until, self._clock() + seconds)
            self._consecutive_failures = 0
        logger.log(
            level, "%s; using the local blocklist only for %d s", reason, int(seconds)
        )

    def _record_failure(self, reason: str) -> None:
        with self._lock:
            self._consecutive_failures += 1
            tripped = self._consecutive_failures >= self._failure_threshold
            if tripped:
                self._blocked_until = max(
                    self._blocked_until, self._clock() + self._failure_cooldown
                )
                self._consecutive_failures = 0
        if tripped:
            logger.warning(
                "AbuseIPDB unavailable (%s); using the local blocklist only for %d s",
                reason,
                int(self._failure_cooldown),
            )
        else:
            logger.warning("AbuseIPDB lookup failed (%s)", reason)

    def _warn_invalid(self, value: Any) -> None:
        self._invalid_count += 1
        n = self._invalid_count
        if n <= _WARN_FIRST_N or n % _WARN_EVERY_NTH == 0:
            logger.warning(
                "IP reputation: invalid IP address %r (invalid inputs so far: %d)",
                str(value)[:64],
                n,
            )