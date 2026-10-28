"""Unit tests for enrichment/ip_reputation.py.

The AbuseIPDB API is always mocked (``FakeSession``): these tests never touch
the network, and the autouse fixture in conftest.py removes any real
ABUSEIPDB_API_KEY from the environment.
"""

import logging
import os
import threading

import pytest
import requests

import enrichment.ip_reputation as module
from enrichment.ip_reputation import (
    ABUSEIPDB_CHECK_URL,
    BLOCKLIST_CATEGORY,
    ENV_API_KEY,
    ENV_BLOCKLIST_PATH,
    ENV_DAILY_LIMIT,
    ENV_THREAT_THRESHOLD,
    Blocklist,
    IPReputationEnricher,
    TTLCache,
    parse_blocklist,
    resolve_blocklist_path,
)
from enrichment.geoip import REPO_ROOT
from enrichment.ip_utils import parse_ip

API_KEY = "test-key-SECRET-123"
MALICIOUS_IP = "45.155.205.233"
GOOGLE_DNS = "8.8.8.8"
LOGGER = "enrichment.ip_reputation"
WALL_START = 1_700_006_400.0  # exactly 00:00:00 UTC on some day

UNASSESSED = {"reputation_score": None, "is_known_threat": False, "threat_categories": []}


# --------------------------------------------------------------------------- #
# Test doubles
# --------------------------------------------------------------------------- #


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeResponse:
    def __init__(self, status=200, payload=None, headers=None, bad_json=False):
        self.status_code = status
        self.headers = headers or {}
        self._payload = payload
        self._bad_json = bad_json

    def json(self):
        if self._bad_json:
            raise ValueError("not json")
        return self._payload


def reports(*category_lists):
    return [{"categories": list(c), "comment": "x"} for c in category_lists]


def abuse(score, *category_lists, **kwargs):
    data = {"ipAddress": "x", "abuseConfidenceScore": score}
    if category_lists:
        data["reports"] = reports(*category_lists)
    return FakeResponse(payload={"data": data}, **kwargs)


class FakeSession:
    """Scripted stand-in for requests.Session (only .get / .close are used)."""

    def __init__(self, *responses, handler=None):
        self._responses = list(responses)
        self._handler = handler
        self.calls = []
        self.closed = False

    @property
    def call_count(self):
        return len(self.calls)

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self._handler is not None:
            item = self._handler(kwargs["params"]["ipAddress"])
        elif self._responses:
            item = self._responses.pop(0)
        else:
            raise AssertionError("unexpected AbuseIPDB call")
        if isinstance(item, Exception):
            raise item
        return item

    def close(self):
        self.closed = True


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def wall():
    return FakeClock(WALL_START)


@pytest.fixture
def blocklist_file(tmp_path):
    path = tmp_path / "known_bad_ips.txt"

    def write(text):
        path.write_text(text, encoding="utf-8")
        return path

    write.path = path
    return write


@pytest.fixture
def make(clock, wall, tmp_path):
    """Build an enricher wired to fake time and a (by default empty) blocklist."""
    built = []

    def factory(session=None, **kwargs):
        kwargs.setdefault("api_key", API_KEY)
        kwargs.setdefault("blocklist_path", tmp_path / "no_blocklist.txt")
        kwargs.setdefault("clock", clock)
        kwargs.setdefault("wall_clock", wall)
        enricher = IPReputationEnricher(session=session, **kwargs)
        built.append(enricher)
        return enricher

    yield factory
    for enricher in built:
        enricher.close()


# --------------------------------------------------------------------------- #
# Acceptance criteria
# --------------------------------------------------------------------------- #


def test_acceptance_known_malicious_ip_is_a_threat_with_score_over_50(make):
    session = FakeSession(abuse(100, [18, 22], [18], [14, 18]))
    result = make(session).enrich(MALICIOUS_IP)

    assert result["is_known_threat"] is True
    assert result["reputation_score"] == 100
    assert result["reputation_score"] > 50
    assert result["threat_categories"] == ["brute_force", "port_scan", "ssh"]


def test_acceptance_google_dns_is_clean_with_score_zero(make):
    session = FakeSession(abuse(0))
    assert make(session).enrich(GOOGLE_DNS) == {
        "reputation_score": 0,
        "is_known_threat": False,
        "threat_categories": [],
    }


def test_acceptance_second_lookup_within_an_hour_uses_the_cache(make, clock):
    session = FakeSession(abuse(100, [18]))
    enricher = make(session)

    first = enricher.enrich(MALICIOUS_IP)
    clock.advance(3599)
    second = enricher.enrich(MALICIOUS_IP)

    assert session.call_count == 1
    assert first == second
    assert enricher.stats["cache_hits"] == 1


def test_cache_expires_after_one_hour(make, clock):
    session = FakeSession(abuse(10), abuse(90))
    enricher = make(session)

    assert enricher.enrich(MALICIOUS_IP)["reputation_score"] == 10
    clock.advance(3601)
    assert enricher.enrich(MALICIOUS_IP)["reputation_score"] == 90
    assert session.call_count == 2


def test_acceptance_without_api_key_uses_blocklist_only_and_warns(
    make, blocklist_file, caplog
):
    blocklist_file(f"{MALICIOUS_IP}\n")
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        enricher = make(session=None, api_key="", blocklist_path=blocklist_file.path)
        for _ in range(5):
            enricher.enrich(GOOGLE_DNS)

    warnings = [r for r in caplog.records if ENV_API_KEY in r.getMessage()]
    assert len(warnings) == 1  # once at startup, not once per lookup
    assert warnings[0].levelno == logging.WARNING

    assert enricher.api_enabled is False
    assert enricher.enrich(GOOGLE_DNS) == UNASSESSED
    threat = enricher.enrich(MALICIOUS_IP)
    assert threat["is_known_threat"] is True


def test_missing_key_in_environment_also_falls_back_and_warns(tmp_path, caplog):
    # conftest removes ABUSEIPDB_API_KEY for every test
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        enricher = IPReputationEnricher(blocklist_path=tmp_path / "none.txt")
    assert enricher.api_enabled is False
    assert any(ENV_API_KEY in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize(
    "entry,probe",
    [
        (MALICIOUS_IP, MALICIOUS_IP),
        ("2001:db8:bad::1", "2001:db8:bad::1"),
        ("203.0.113.0/24", "203.0.113.77"),
        ("2001:db8:bad::/48", "2001:db8:bad:1::5"),
        ("10.9.8.7", "10.9.8.7"),  # a known-compromised private host
        ("185.199.108.5/32", "185.199.108.5"),
        (MALICIOUS_IP, f"::ffff:{MALICIOUS_IP}"),  # IPv4-mapped form
    ],
)
def test_acceptance_blocklisted_ips_are_always_threats(
    make, blocklist_file, entry, probe
):
    blocklist_file(f"{entry}\n")
    session = FakeSession(abuse(0))  # even if the API would say "clean"
    enricher = make(session, blocklist_path=blocklist_file.path)

    assert enricher.enrich(probe) == {
        "reputation_score": 100,
        "is_known_threat": True,
        "threat_categories": [BLOCKLIST_CATEGORY],
    }
    assert session.call_count == 0  # authoritative: costs no API call


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",
        "172.16.5.4",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.10.10",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fc00::1",
        "fe80::1",
    ],
)
def test_acceptance_private_ips_never_reach_the_api(make, ip):
    session = FakeSession()  # any call raises AssertionError
    assert make(session).enrich(ip) == UNASSESSED
    assert session.call_count == 0


# --------------------------------------------------------------------------- #
# Request shape and secret hygiene
# --------------------------------------------------------------------------- #


def test_request_matches_the_abuseipdb_check_contract(make):
    session = FakeSession(abuse(0))
    make(session).enrich(GOOGLE_DNS)

    url, kwargs = session.calls[0]
    assert url == ABUSEIPDB_CHECK_URL == "https://api.abuseipdb.com/api/v2/check"
    assert kwargs["headers"] == {"Key": API_KEY, "Accept": "application/json"}
    assert kwargs["params"] == {
        "ipAddress": GOOGLE_DNS,
        "maxAgeInDays": 30,
        "verbose": "",
    }
    assert kwargs["timeout"] == 5.0
    assert kwargs["allow_redirects"] is False  # never forward the Key header
    assert API_KEY not in url


def test_categories_can_be_disabled_to_keep_payloads_light(make):
    session = FakeSession(abuse(80, [18]))
    result = make(session, fetch_categories=False).enrich(MALICIOUS_IP)
    assert "verbose" not in session.calls[0][1]["params"]
    assert result["threat_categories"] == []
    assert result["is_known_threat"] is True


def test_custom_window_and_timeout_are_sent(make):
    session = FakeSession(abuse(0))
    make(session, max_age_days=90, timeout=2.5).enrich(GOOGLE_DNS)
    kwargs = session.calls[0][1]
    assert kwargs["params"]["maxAgeInDays"] == 90
    assert kwargs["timeout"] == 2.5


def test_ipv6_is_sent_as_given(make):
    session = FakeSession(abuse(0))
    make(session).enrich("2001:4860:4860::8888")
    assert session.calls[0][1]["params"]["ipAddress"] == "2001:4860:4860::8888"


def test_ipv4_and_its_mapped_form_share_one_cache_entry(make):
    session = FakeSession(abuse(0))
    enricher = make(session)
    enricher.enrich(GOOGLE_DNS)
    enricher.enrich(f"::ffff:{GOOGLE_DNS}")
    assert session.call_count == 1
    assert session.calls[0][1]["params"]["ipAddress"] == GOOGLE_DNS


def test_api_key_is_read_from_the_environment_and_stripped(
    monkeypatch, tmp_path
):
    monkeypatch.setenv(ENV_API_KEY, f"  {API_KEY}\n")
    session = FakeSession(abuse(0))
    enricher = IPReputationEnricher(session=session, blocklist_path=tmp_path / "n.txt")
    assert enricher.api_enabled is True
    enricher.enrich(GOOGLE_DNS)
    assert session.calls[0][1]["headers"]["Key"] == API_KEY


def test_blank_key_in_the_environment_disables_the_api(monkeypatch, tmp_path):
    monkeypatch.setenv(ENV_API_KEY, "   ")
    enricher = IPReputationEnricher(blocklist_path=tmp_path / "n.txt")
    assert enricher.api_enabled is False


def test_explicit_empty_key_overrides_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv(ENV_API_KEY, API_KEY)
    enricher = IPReputationEnricher(api_key="", blocklist_path=tmp_path / "n.txt")
    assert enricher.api_enabled is False


def test_the_api_key_never_appears_in_logs_or_repr(make, caplog):
    leaky = requests.ConnectionError(f"boom while sending Key: {API_KEY}")
    session = FakeSession(
        leaky,
        FakeResponse(status=401),
        FakeResponse(status=429, headers={"Retry-After": "60"}),
        FakeResponse(payload={"unexpected": True}),
    )
    enricher = make(session, failure_threshold=100, failure_cooldown=0)

    with caplog.at_level(logging.DEBUG):
        enricher.enrich(MALICIOUS_IP)
        enricher._blocked_until = 0.0
        enricher.enrich(MALICIOUS_IP)
        enricher._blocked_until = 0.0
        enricher.enrich(MALICIOUS_IP)
        enricher._blocked_until = 0.0
        enricher.enrich(MALICIOUS_IP)

    assert session.call_count == 4
    assert API_KEY not in caplog.text
    assert API_KEY not in repr(enricher)
    assert API_KEY not in str(vars(enricher).get("_blocklist", ""))


# --------------------------------------------------------------------------- #
# Threat decision and result normalisation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "score,expected",
    [(0, False), (49, False), (50, True), (51, True), (100, True)],
)
def test_default_threshold_is_50(make, score, expected):
    result = make(FakeSession(abuse(score))).enrich(MALICIOUS_IP)
    assert result["reputation_score"] == score
    assert result["is_known_threat"] is expected


def test_threshold_is_configurable(make):
    assert make(FakeSession(abuse(75)), threat_threshold=80).enrich(MALICIOUS_IP)[
        "is_known_threat"
    ] is False
    assert make(FakeSession(abuse(75)), threat_threshold=75).enrich(MALICIOUS_IP)[
        "is_known_threat"
    ] is True


def test_threshold_from_environment(monkeypatch, make):
    monkeypatch.setenv(ENV_THREAT_THRESHOLD, "90")
    result = make(FakeSession(abuse(80))).enrich(MALICIOUS_IP)
    assert result["is_known_threat"] is False


def test_invalid_environment_values_fall_back_to_defaults_with_a_warning(
    monkeypatch, make, caplog
):
    monkeypatch.setenv(ENV_THREAT_THRESHOLD, "banana")
    monkeypatch.setenv(ENV_DAILY_LIMIT, "-5")
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        enricher = make(FakeSession(abuse(50)))
    assert enricher.enrich(MALICIOUS_IP)["is_known_threat"] is True  # default 50
    assert ENV_THREAT_THRESHOLD in caplog.text and ENV_DAILY_LIMIT in caplog.text


@pytest.mark.parametrize("raw,expected", [(150, 100), (-5, 0), ("73", 73)])
def test_score_is_clamped_to_0_100(make, raw, expected):
    assert make(FakeSession(abuse(raw))).enrich(MALICIOUS_IP)[
        "reputation_score"
    ] == expected


def test_categories_are_ranked_by_report_count_then_id(make):
    session = FakeSession(abuse(95, [22, 18], [18], [14], [22], [18, 14, 22]))
    result = make(session).enrich(MALICIOUS_IP)
    # 18 x3, 22 x3, 14 x2 -> ties broken by id: 18 before 22
    assert result["threat_categories"] == ["brute_force", "ssh", "port_scan"]


def test_unknown_and_malformed_categories_are_handled(make):
    data = {
        "abuseConfidenceScore": 90,
        "reports": [
            {"categories": [99, True, "18", None, 21]},
            {"categories": "nope"},
            {"no_categories": 1},
            "garbage",
        ],
    }
    result = make(FakeSession(FakeResponse(payload={"data": data}))).enrich(
        MALICIOUS_IP
    )
    assert result["threat_categories"] == ["web_app_attack", "category_99"]


def test_a_clean_ip_with_some_reports_still_lists_their_categories(make):
    result = make(FakeSession(abuse(10, [14]))).enrich(MALICIOUS_IP)
    assert result["is_known_threat"] is False
    assert result["threat_categories"] == ["port_scan"]


def test_missing_reports_means_no_categories(make):
    assert make(FakeSession(abuse(0))).enrich(GOOGLE_DNS)["threat_categories"] == []


def test_every_category_id_from_abuseipdb_has_a_name():
    assert sorted(module.CATEGORY_NAMES) == list(range(1, 24))
    assert len(set(module.CATEGORY_NAMES.values())) == 23


def test_result_has_exactly_the_three_documented_keys(make):
    enricher = make(FakeSession(abuse(0)))
    expected = {"reputation_score", "is_known_threat", "threat_categories"}
    assert set(enricher.enrich(GOOGLE_DNS)) == expected
    assert set(enricher.enrich("10.0.0.1")) == expected


def test_mutating_a_result_does_not_poison_the_cache(make):
    enricher = make(FakeSession(abuse(90, [18])))
    first = enricher.enrich(MALICIOUS_IP)
    first["threat_categories"].append("tampered")
    first["is_known_threat"] = False
    again = enricher.enrich(MALICIOUS_IP)
    assert again["threat_categories"] == ["brute_force"]
    assert again["is_known_threat"] is True


# --------------------------------------------------------------------------- #
# Invalid input
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "bad",
    ["not_an_ip", "", "   ", "999.1.1.1", "1.2.3", "8.8.8.8/24", None, 123, b"8.8.8.8"],
)
def test_invalid_input_is_not_assessed_and_never_calls_the_api(make, bad):
    session = FakeSession()
    assert make(session).enrich(bad) == UNASSESSED
    assert session.call_count == 0


def test_invalid_input_warnings_are_rate_limited(make, caplog):
    enricher = make(FakeSession())
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        for _ in range(5_000):
            enricher.enrich("garbage")
    invalid_warnings = [r for r in caplog.records if "invalid IP" in r.getMessage()]
    assert len(invalid_warnings) == 55  # first 50, then every 1000th


# --------------------------------------------------------------------------- #
# Failure handling: the API must never break the pipeline
# --------------------------------------------------------------------------- #


def test_timeout_degrades_to_not_assessed_and_is_not_cached(make):
    session = FakeSession(requests.Timeout("slow"), abuse(90, [18]))
    enricher = make(session)

    assert enricher.enrich(MALICIOUS_IP) == UNASSESSED
    recovered = enricher.enrich(MALICIOUS_IP)  # retried: degraded results aren't cached
    assert recovered["reputation_score"] == 90
    assert session.call_count == 2


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse(status=500),
        FakeResponse(status=503),
        FakeResponse(status=422, payload={"errors": [{"status": 422}]}),
        FakeResponse(status=302, headers={"Location": "http://evil.example"}),
        FakeResponse(bad_json=True),
        FakeResponse(payload={"no_data_key": 1}),
        FakeResponse(payload={"data": {"abuseConfidenceScore": "high"}}),
        FakeResponse(payload=None),
    ],
)
def test_bad_responses_degrade_gracefully(make, response):
    assert make(FakeSession(response)).enrich(MALICIOUS_IP) == UNASSESSED


def test_unexpected_exceptions_from_the_transport_are_contained(make):
    assert make(FakeSession(RuntimeError("boom"))).enrich(MALICIOUS_IP) == UNASSESSED


def test_repeated_failures_pause_the_api_then_it_recovers(make, clock):
    session = FakeSession(
        requests.ConnectionError(),
        requests.ConnectionError(),
        requests.ConnectionError(),
        abuse(80),
    )
    enricher = make(session)

    for _ in range(3):
        assert enricher.enrich(MALICIOUS_IP) == UNASSESSED
    assert session.call_count == 3

    clock.advance(30)  # inside the 60 s cooldown: no API traffic at all
    for _ in range(10):
        assert enricher.enrich(MALICIOUS_IP) == UNASSESSED
    assert session.call_count == 3

    clock.advance(31)  # cooldown over
    assert enricher.enrich(MALICIOUS_IP)["reputation_score"] == 80
    assert session.call_count == 4


def test_a_success_resets_the_failure_streak(make):
    session = FakeSession(
        FakeResponse(status=500),
        FakeResponse(status=500),
        abuse(0),
        FakeResponse(status=500),
        FakeResponse(status=500),
        abuse(0),
    )
    enricher = make(session)
    for ip in ("1.1.1.1", "1.0.0.1", "9.9.9.9", "8.8.4.4", "4.4.4.4", "5.5.5.5"):
        enricher.enrich(ip)
    assert session.call_count == 6  # never tripped the cooldown


def test_rate_limit_429_pauses_until_retry_after(make, clock, caplog):
    session = FakeSession(
        FakeResponse(status=429, headers={"Retry-After": "120"}), abuse(70)
    )
    enricher = make(session)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        assert enricher.enrich(MALICIOUS_IP) == UNASSESSED
    assert "rate limit" in caplog.text

    clock.advance(119)
    assert enricher.enrich(GOOGLE_DNS) == UNASSESSED
    assert session.call_count == 1  # still paused

    clock.advance(2)
    assert enricher.enrich(GOOGLE_DNS)["reputation_score"] == 70
    assert session.call_count == 2


def test_rate_limit_without_retry_after_waits_an_hour(make, clock):
    session = FakeSession(FakeResponse(status=429), abuse(0))
    enricher = make(session)
    enricher.enrich(MALICIOUS_IP)
    clock.advance(3599)
    enricher.enrich(GOOGLE_DNS)
    assert session.call_count == 1
    clock.advance(2)
    enricher.enrich(GOOGLE_DNS)
    assert session.call_count == 2


def test_remaining_quota_header_zero_pauses_until_reset(make, clock, wall):
    reset_at = wall.now + 300
    session = FakeSession(
        abuse(
            90,
            [18],
            headers={
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(reset_at)),
            },
        ),
        abuse(0),
    )
    enricher = make(session)

    first = enricher.enrich(MALICIOUS_IP)  # this response is still valid
    assert first["reputation_score"] == 90

    assert enricher.enrich(GOOGLE_DNS) == UNASSESSED  # paused: no call
    assert session.call_count == 1

    clock.advance(301)
    assert enricher.enrich(GOOGLE_DNS)["reputation_score"] == 0
    assert session.call_count == 2


def test_remaining_quota_header_above_zero_does_not_pause(make):
    session = FakeSession(
        abuse(0, headers={"X-RateLimit-Remaining": "999"}), abuse(0)
    )
    enricher = make(session)
    enricher.enrich(GOOGLE_DNS)
    enricher.enrich("1.1.1.1")
    assert session.call_count == 2


def test_rejected_api_key_pauses_for_an_hour_and_logs_an_error(make, clock, caplog):
    session = FakeSession(FakeResponse(status=401), abuse(0))
    enricher = make(session)

    with caplog.at_level(logging.ERROR, logger=LOGGER):
        assert enricher.enrich(GOOGLE_DNS) == UNASSESSED
    assert ENV_API_KEY in caplog.text and API_KEY not in caplog.text

    clock.advance(3000)
    enricher.enrich("1.1.1.1")
    assert session.call_count == 1
    clock.advance(700)
    enricher.enrich("1.1.1.1")
    assert session.call_count == 2


def test_blocklist_and_cache_keep_working_while_the_api_is_paused(
    make, blocklist_file, clock
):
    blocklist_file(f"{MALICIOUS_IP}\n")
    session = FakeSession(abuse(0), FakeResponse(status=429, headers={"Retry-After": "600"}))
    enricher = make(session, blocklist_path=blocklist_file.path)

    assert enricher.enrich(GOOGLE_DNS)["reputation_score"] == 0  # cached
    enricher.enrich("1.1.1.1")  # trips the 429 pause
    assert session.call_count == 2

    assert enricher.enrich(GOOGLE_DNS)["reputation_score"] == 0  # from cache
    assert enricher.enrich(MALICIOUS_IP)["is_known_threat"] is True  # blocklist
    assert enricher.enrich("9.9.9.9") == UNASSESSED  # paused
    assert session.call_count == 2


# --------------------------------------------------------------------------- #
# Daily budget (free tier: 1000 checks/day)
# --------------------------------------------------------------------------- #


def test_local_daily_budget_stops_calls_and_resets_at_utc_midnight(make, wall, caplog):
    session = FakeSession(handler=lambda ip: abuse(0))
    enricher = make(session, daily_limit=2)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        enricher.enrich("1.1.1.1")
        enricher.enrich("1.0.0.1")
        assert enricher.enrich("9.9.9.9") == UNASSESSED
        assert enricher.enrich("8.8.4.4") == UNASSESSED
    assert session.call_count == 2
    assert caplog.text.count("daily budget") == 1  # warned once, not per IP

    wall.advance(86400)  # next UTC day
    enricher.enrich("9.9.9.9")
    assert session.call_count == 3


def test_cached_ips_do_not_consume_the_budget(make):
    session = FakeSession(handler=lambda ip: abuse(0))
    enricher = make(session, daily_limit=1)
    for _ in range(50):
        enricher.enrich(GOOGLE_DNS)
    assert session.call_count == 1


def test_default_daily_limit_is_the_free_tier(make):
    assert module.DEFAULT_DAILY_LIMIT == 1000
    session = FakeSession(handler=lambda ip: abuse(0))
    enricher = make(session)
    for i in range(1, 1001):
        enricher.enrich(f"11.{i // 250}.{i % 250}.7")
    assert session.call_count == 1000
    enricher.enrich("12.12.12.12")
    assert session.call_count == 1000  # 1001st check is not attempted


def test_daily_limit_from_environment(monkeypatch, make):
    monkeypatch.setenv(ENV_DAILY_LIMIT, "1")
    session = FakeSession(handler=lambda ip: abuse(0))
    enricher = make(session)
    enricher.enrich("1.1.1.1")
    enricher.enrich("1.0.0.1")
    assert session.call_count == 1


def test_daily_limit_can_be_disabled(make):
    session = FakeSession(handler=lambda ip: abuse(0))
    enricher = make(session, daily_limit=None)
    for i in range(1, 1201):
        enricher.enrich(f"13.{i // 250}.{i % 250}.7")
    assert session.call_count == 1200


# --------------------------------------------------------------------------- #
# Blocklist
# --------------------------------------------------------------------------- #


def test_parse_blocklist_formats():
    text = (
        "# header comment\n"
        "\n"
        "1.2.3.4\n"
        "  5.6.7.8   # trailing comment\n"
        "10.0.0.0/8\n"
        "9.9.9.9/32\n"
        "2001:db8::1\n"
        "2001:db8:1::/48\n"
        "::ffff:4.4.4.4\n"
        "not an ip\n"
        "1.2.3.4.5\n"
        "300.1.1.1\n"
    )
    addresses, networks, invalid = parse_blocklist(text)
    assert addresses == {
        parse_ip("1.2.3.4"),
        parse_ip("5.6.7.8"),
        parse_ip("9.9.9.9"),
        parse_ip("2001:db8::1"),
        parse_ip("4.4.4.4"),
    }
    assert sorted(str(n) for n in networks) == ["10.0.0.0/8", "2001:db8:1::/48"]
    assert invalid == [10, 11, 12]


def test_parse_blocklist_handles_windows_line_endings():
    addresses, _, invalid = parse_blocklist("1.2.3.4\r\n5.6.7.8\r\n")
    assert len(addresses) == 2 and invalid == []


def test_blocklist_loads_a_file_with_a_utf8_bom(tmp_path):
    path = tmp_path / "bad.txt"
    path.write_bytes(b"\xef\xbb\xbf1.2.3.4\n")
    assert Blocklist(path).contains(parse_ip("1.2.3.4"))


def test_invalid_blocklist_lines_are_skipped_with_a_warning(
    make, blocklist_file, caplog
):
    blocklist_file("garbage\n1.2.3.4\nalso bad\n")
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        enricher = make(FakeSession(), blocklist_path=blocklist_file.path)
    assert enricher.blocklist_size == 1
    assert "2 invalid line(s)" in caplog.text
    assert enricher.enrich("1.2.3.4")["is_known_threat"] is True


def test_missing_blocklist_file_is_an_empty_blocklist_with_one_warning(
    tmp_path, caplog
):
    path = tmp_path / "absent.txt"
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        blocklist = Blocklist(path, reload_interval=0)
        for _ in range(5):
            assert blocklist.contains(parse_ip("1.2.3.4")) is False
    assert caplog.text.count("not found") == 1


def test_blocklist_hot_reloads_when_the_file_changes(blocklist_file, clock):
    blocklist_file("1.2.3.4\n")
    blocklist = Blocklist(blocklist_file.path, reload_interval=30, clock=clock)
    assert blocklist.contains(parse_ip("5.6.7.8")) is False

    blocklist_file("1.2.3.4\n5.6.7.8\n")
    assert blocklist.contains(parse_ip("5.6.7.8")) is False  # interval not elapsed
    clock.advance(31)
    assert blocklist.contains(parse_ip("5.6.7.8")) is True
    assert blocklist.contains(parse_ip("1.2.3.4")) is True


def test_blocklist_picks_up_a_file_created_after_startup(tmp_path, clock):
    path = tmp_path / "late.txt"
    blocklist = Blocklist(path, reload_interval=30, clock=clock)
    assert len(blocklist) == 0
    path.write_text("1.2.3.4\n")
    clock.advance(31)
    assert blocklist.contains(parse_ip("1.2.3.4")) is True


def test_removing_the_blocklist_file_empties_it(blocklist_file, clock):
    blocklist_file("1.2.3.4\n")
    blocklist = Blocklist(blocklist_file.path, reload_interval=30, clock=clock)
    assert blocklist.contains(parse_ip("1.2.3.4")) is True
    blocklist_file.path.unlink()
    clock.advance(31)
    assert blocklist.contains(parse_ip("1.2.3.4")) is False


def test_unreadable_blocklist_keeps_the_previous_entries(
    blocklist_file, clock, monkeypatch, caplog
):
    blocklist_file("1.2.3.4\n")
    blocklist = Blocklist(blocklist_file.path, reload_interval=30, clock=clock)

    blocklist_file("1.2.3.4\n5.6.7.8\n")

    def explode(self, *args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(type(blocklist_file.path), "read_text", explode)
    clock.advance(31)
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        assert blocklist.contains(parse_ip("1.2.3.4")) is True
    assert "PermissionError" in caplog.text


def test_a_newly_blocklisted_ip_overrides_a_cached_clean_result(
    make, blocklist_file, clock
):
    blocklist_file.path.write_text("# empty\n")
    session = FakeSession(abuse(0))
    enricher = make(session, blocklist_path=blocklist_file.path)

    assert enricher.enrich(MALICIOUS_IP)["is_known_threat"] is False  # cached clean
    blocklist_file(f"{MALICIOUS_IP}\n")
    clock.advance(31)

    result = enricher.enrich(MALICIOUS_IP)
    assert result["is_known_threat"] is True
    assert result["threat_categories"] == [BLOCKLIST_CATEGORY]
    assert session.call_count == 1


def test_blocklist_path_resolution(monkeypatch, tmp_path):
    monkeypatch.delenv(ENV_BLOCKLIST_PATH, raising=False)
    assert resolve_blocklist_path() == REPO_ROOT / "data" / "known_bad_ips.txt"

    # Use a real temporary path so the assertion is portable across Windows and Linux.
    env_path = tmp_path / "from_env.txt"
    monkeypatch.setenv(ENV_BLOCKLIST_PATH, str(env_path))
    assert resolve_blocklist_path() == env_path

    explicit = tmp_path / "x.txt"
    assert resolve_blocklist_path(explicit) == explicit
    monkeypatch.setenv(ENV_BLOCKLIST_PATH, "data/known_bad_ips.txt")
    monkeypatch.chdir(tmp_path)  # Spark workers don't run from the repo root
    assert resolve_blocklist_path() == REPO_ROOT / "data" / "known_bad_ips.txt"


def test_the_shipped_blocklist_template_is_valid_and_tracked():
    path = REPO_ROOT / "data" / "known_bad_ips.txt"
    assert path.is_file()
    addresses, networks, invalid = parse_blocklist(path.read_text(encoding="utf-8"))
    assert invalid == []
    gitignore = (REPO_ROOT / ".gitignore").read_text().splitlines()
    assert "!data/known_bad_ips.txt" in gitignore


# --------------------------------------------------------------------------- #
# TTLCache
# --------------------------------------------------------------------------- #


def test_ttl_cache_expires_entries(clock):
    cache = TTLCache(10, 100, clock=clock)
    cache.set("a", 1)
    clock.advance(9.9)
    assert cache.get("a") == 1
    clock.advance(0.2)
    assert cache.get("a") is None
    assert len(cache) == 0


def test_ttl_cache_evicts_the_oldest_when_full(clock):
    cache = TTLCache(100, 2, clock=clock)
    for key in ("a", "b", "c"):
        cache.set(key, key)
        clock.advance(1)
    assert cache.get("a") is None
    assert cache.get("b") == "b" and cache.get("c") == "c"


def test_ttl_cache_overwrite_refreshes_the_ttl(clock):
    cache = TTLCache(10, 100, clock=clock)
    cache.set("a", 1)
    clock.advance(8)
    cache.set("a", 2)
    clock.advance(8)
    assert cache.get("a") == 2


def test_ttl_cache_purges_expired_entries_on_write(clock):
    cache = TTLCache(10, 100, clock=clock)
    for key in "abc":
        cache.set(key, 1)
    clock.advance(11)
    cache.set("d", 1)
    assert len(cache) == 1


def test_ttl_cache_clear(clock):
    cache = TTLCache(10, 100, clock=clock)
    cache.set("a", 1)
    cache.clear()
    assert cache.get("a") is None


@pytest.mark.parametrize("ttl,size", [(0, 10), (-1, 10), (10, 0)])
def test_ttl_cache_rejects_invalid_settings(ttl, size):
    with pytest.raises(ValueError):
        TTLCache(ttl, size)


def test_enricher_cache_is_bounded(make):
    session = FakeSession(handler=lambda ip: abuse(0))
    enricher = make(session, cache_size=2, daily_limit=None)
    for ip in ("1.1.1.1", "1.0.0.1", "9.9.9.9", "1.1.1.1"):
        enricher.enrich(ip)
    assert session.call_count == 4  # "1.1.1.1" was evicted by the 3rd distinct IP


# --------------------------------------------------------------------------- #
# Lifecycle, configuration, concurrency
# --------------------------------------------------------------------------- #


def test_an_owned_session_is_closed_and_an_injected_one_is_not(
    monkeypatch, tmp_path
):
    created = FakeSession()
    monkeypatch.setattr(requests, "Session", lambda: created)
    owned = IPReputationEnricher(api_key=API_KEY, blocklist_path=tmp_path / "n.txt")
    owned.close()
    assert created.closed is True

    injected = FakeSession()
    IPReputationEnricher(
        api_key=API_KEY, session=injected, blocklist_path=tmp_path / "n.txt"
    ).close()
    assert injected.closed is False


def test_enriching_after_close_degrades_instead_of_crashing(make):
    session = FakeSession(abuse(0))
    enricher = make(session)
    enricher.close()
    assert enricher.enrich(GOOGLE_DNS) == UNASSESSED
    assert session.call_count == 0
    enricher.close()  # idempotent


def test_context_manager(tmp_path):
    session = FakeSession(abuse(0))
    with IPReputationEnricher(
        api_key=API_KEY, session=session, blocklist_path=tmp_path / "n.txt"
    ) as enricher:
        assert enricher.enrich(GOOGLE_DNS)["reputation_score"] == 0
    assert enricher.api_enabled is False


@pytest.mark.parametrize(
    "kwargs",
    [
        {"threat_threshold": -1},
        {"threat_threshold": 101},
        {"timeout": 0},
        {"max_age_days": 0},
        {"max_age_days": 366},
        {"failure_threshold": 0},
        {"failure_cooldown": -1},
        {"daily_limit": 0},
        {"cache_ttl": 0},
        {"cache_size": 0},
    ],
)
def test_invalid_constructor_arguments_raise(tmp_path, kwargs):
    with pytest.raises(ValueError):
        IPReputationEnricher(
            api_key=API_KEY, session=FakeSession(), blocklist_path=tmp_path / "n.txt", **kwargs
        )


def test_stats_count_api_calls_cache_and_blocklist_hits(make, blocklist_file):
    blocklist_file(f"{MALICIOUS_IP}\n")
    session = FakeSession(abuse(0))
    enricher = make(session, blocklist_path=blocklist_file.path)
    enricher.enrich(GOOGLE_DNS)
    enricher.enrich(GOOGLE_DNS)
    enricher.enrich(MALICIOUS_IP)
    assert enricher.stats == {
        "api_calls": 1,
        "cache_hits": 1,
        "blocklist_hits": 1,
        "cache_size": 1,
    }


def test_concurrent_lookups_are_safe(make):
    scores = {f"20.0.0.{i}": i % 100 for i in range(1, 41)}
    session = FakeSession(handler=lambda ip: abuse(scores[ip]))
    enricher = make(session, daily_limit=None)
    errors, mismatches = [], []

    def work():
        try:
            for ip, score in scores.items():
                if enricher.enrich(ip)["reputation_score"] != score:
                    mismatches.append(ip)
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]

    assert not errors and not mismatches
    assert 40 <= session.call_count <= 8 * 40  # duplicates in flight are fine
    assert enricher.stats["cache_hits"] > 0


# --------------------------------------------------------------------------- #
# Real HTTP round trip (loopback only): proves what actually goes on the wire
# --------------------------------------------------------------------------- #


@pytest.fixture
def local_abuseipdb(monkeypatch):
    """A tiny loopback server speaking the AbuseIPDB CHECK contract."""
    import json
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import parse_qs, urlparse

    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            url = urlparse(self.path)
            query = parse_qs(url.query, keep_blank_values=True)
            seen.append({"path": url.path, "query": query, "headers": dict(self.headers)})
            ip = query["ipAddress"][0]
            if ip == "1.1.1.1":
                body, status, extra = b'{"errors":[{"status":429}]}', 429, {"Retry-After": "90"}
            else:
                score = 100 if ip == MALICIOUS_IP else 0
                payload = {
                    "data": {
                        "ipAddress": ip,
                        "abuseConfidenceScore": score,
                        "reports": [{"categories": [18, 22]}] if score else [],
                    }
                }
                body, status, extra = json.dumps(payload).encode(), 200, {}
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for name, value in extra.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(
        module, "ABUSEIPDB_CHECK_URL", f"http://127.0.0.1:{server.server_port}/api/v2/check"
    )
    yield seen
    server.shutdown()
    server.server_close()


def test_real_http_request_and_response_round_trip(local_abuseipdb, tmp_path):
    with IPReputationEnricher(
        api_key=API_KEY, blocklist_path=tmp_path / "none.txt"
    ) as enricher:
        threat = enricher.enrich(MALICIOUS_IP)
        clean = enricher.enrich(GOOGLE_DNS)
        v6 = enricher.enrich("2001:4860:4860::8888")
        again = enricher.enrich(MALICIOUS_IP)  # cache: no second request

    assert threat == {
        "reputation_score": 100,
        "is_known_threat": True,
        "threat_categories": ["brute_force", "ssh"],
    }
    assert clean["reputation_score"] == 0 and clean["is_known_threat"] is False
    assert v6["reputation_score"] == 0
    assert again == threat
    assert len(local_abuseipdb) == 3

    first = local_abuseipdb[0]
    assert first["path"] == "/api/v2/check"
    assert first["headers"]["Key"] == API_KEY
    assert first["headers"]["Accept"] == "application/json"
    assert first["query"] == {
        "ipAddress": [MALICIOUS_IP],
        "maxAgeInDays": ["30"],
        "verbose": [""],
    }
    assert API_KEY not in first["path"]
    assert local_abuseipdb[2]["query"]["ipAddress"] == ["2001:4860:4860::8888"]


def test_real_http_429_is_honoured(local_abuseipdb, tmp_path, clock):
    with IPReputationEnricher(
        api_key=API_KEY, blocklist_path=tmp_path / "none.txt", clock=clock
    ) as enricher:
        assert enricher.enrich("1.1.1.1") == UNASSESSED  # server answers 429
        assert enricher.enrich(MALICIOUS_IP) == UNASSESSED  # paused: no request
    assert len(local_abuseipdb) == 1

# --------------------------------------------------------------------------- #
# prefetch / enrich_cached (batch path used by the Spark UDF)
# --------------------------------------------------------------------------- #


def test_enrich_cached_never_touches_the_network(make):
    session = FakeSession(abuse(90, [18]))
    enricher = make(session)
    assert enricher.enrich_cached(MALICIOUS_IP) == UNASSESSED
    assert session.call_count == 0
    enricher.enrich(MALICIOUS_IP)  # now cached
    assert enricher.enrich_cached(MALICIOUS_IP)["reputation_score"] == 90
    assert session.call_count == 1


def test_enrich_cached_still_honours_the_blocklist_and_private_rules(make, blocklist_file):
    blocklist_file("10.9.8.7\n")
    enricher = make(FakeSession(), blocklist_path=blocklist_file.path)
    assert enricher.enrich_cached("10.9.8.7")["is_known_threat"] is True
    assert enricher.enrich_cached("10.0.0.1") == UNASSESSED


def test_prefetch_warms_the_cache_with_one_call_per_distinct_public_ip(make, blocklist_file):
    blocklist_file("1.1.1.1\n")
    session = FakeSession(handler=lambda ip: abuse(0))
    enricher = make(session, blocklist_path=blocklist_file.path)
    enricher.enrich(GOOGLE_DNS)  # already cached

    done = enricher.prefetch(
        [GOOGLE_DNS, "9.9.9.9", "9.9.9.9", "10.0.0.1", "1.1.1.1", "garbage", None, MALICIOUS_IP]
    )
    assert done == 2  # 9.9.9.9 and MALICIOUS_IP only
    assert sorted(c[1]["params"]["ipAddress"] for c in session.calls) == sorted(
        [GOOGLE_DNS, "9.9.9.9", MALICIOUS_IP])
    for ip in ("9.9.9.9", MALICIOUS_IP):
        assert enricher.enrich_cached(ip)["reputation_score"] == 0


def test_prefetch_is_a_no_op_without_an_api_or_while_paused(make, clock):
    assert make(FakeSession(), api_key="").prefetch(["9.9.9.9"]) == 0
    session = FakeSession(FakeResponse(status=429, headers={"Retry-After": "600"}))
    enricher = make(session)
    enricher.enrich(MALICIOUS_IP)  # trips the pause
    assert enricher.prefetch(["9.9.9.9", "8.8.4.4"]) == 0
    assert session.call_count == 1


def test_prefetch_deadline_abandons_slow_lookups(make):
    import time as _time

    def slow(ip):
        _time.sleep(0.5)
        return abuse(0)

    enricher = make(FakeSession(handler=slow), daily_limit=None)
    started = _time.perf_counter()
    done = enricher.prefetch([f"30.0.0.{i}" for i in range(1, 9)], max_workers=2, deadline_seconds=0.1)
    assert _time.perf_counter() - started < 0.4
    assert done < 8