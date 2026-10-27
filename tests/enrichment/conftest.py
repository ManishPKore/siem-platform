"""Shared fixtures for tests/enrichment/.

``city_db`` / ``asn_db`` build tiny but *real* MaxMind-format databases (via
the ``mmdb-writer`` dev dependency), so the tests exercise the genuine
``geoip2.database.Reader`` path without the licensed GeoLite2 files.
"""

from __future__ import annotations

import os
import sys

os.environ.setdefault("PYSPARK_PYTHON", sys.executable)
os.environ.setdefault("PYSPARK_DRIVER_PYTHON", sys.executable)

import pytest

KNOWN_IPS = {
    "8.8.8.8": ("US", "Mountain View", 37.3860517, -122.0838511),
    "81.2.69.142": ("GB", "London", 51.5142, -0.0931),
    "203.0.114.7": ("AU", "Sydney", -33.8688, 151.2093),
}
COUNTRY_ONLY_IP = "1.1.1.1"
UNKNOWN_PUBLIC_IP = "93.184.216.34"

# ip -> (asn_number, asn_org). Mirrors real GeoLite2-ASN records.
KNOWN_ASNS = {
    "8.8.8.8": (15169, "GOOGLE"),
    "104.131.0.1": (14061, "DIGITALOCEAN-ASN"),
    "52.95.110.1": (16509, "AMAZON-02"),
    "81.2.69.142": (4200000000, "BIG-PRIVATE-USE-ASN"),
    # > 2**31: uint32 range
}
ASN_IPV6 = "2001:4860:4860::8888"
# Google public DNS, same AS as 8.8.8.8
ASN_NUMBER_ONLY_IP = "185.199.108.1"
# record without an organization


_REPUTATION_ENV_VARS = (
    "ABUSEIPDB_API_KEY",
    "ABUSEIPDB_THREAT_THRESHOLD",
    "ABUSEIPDB_DAILY_LIMIT",
)


@pytest.fixture(autouse=True)
def _isolate_reputation_env(monkeypatch, tmp_path):
    """No real API key, no developer blocklist: tests must be hermetic."""
    for name in _REPUTATION_ENV_VARS:
        monkeypatch.delenv(name, raising=False)

    monkeypatch.setenv(
        "KNOWN_BAD_IPS_PATH",
        str(tmp_path / "no_blocklist.txt"),
    )
    yield


@pytest.fixture(scope="session")
def city_db(tmp_path_factory) -> str:
    mmdb_writer = pytest.importorskip(
        "mmdb_writer",
        reason="dev dependency 'mmdb-writer' not installed (requirements-dev.txt)",
    )
    from netaddr import IPSet

    writer = mmdb_writer.MMDBWriter(
        ip_version=4,
        database_type="GeoIP2-City",
        languages=["en"],
        description={"en": "siem-platform test city database"},
    )
    for ip, (iso, city, lat, lon) in KNOWN_IPS.items():
        writer.insert_network(
            IPSet([f"{ip}/32"]),
            {
                "country": {"iso_code": iso, "names": {"en": iso}},
                "city": {"names": {"en": city}},
                "location": {"latitude": lat, "longitude": lon},
            },
        )
    writer.insert_network(
        IPSet([f"{COUNTRY_ONLY_IP}/32"]),
        {"country": {"iso_code": "AU", "names": {"en": "Australia"}}},
    )

    path = tmp_path_factory.mktemp("geoip") / "GeoLite2-City.mmdb"
    writer.to_db_file(str(path))
    return str(path)


@pytest.fixture(scope="session")
def asn_db(tmp_path_factory) -> str:
    mmdb_writer = pytest.importorskip(
        "mmdb_writer",
        reason="dev dependency 'mmdb-writer' not installed (requirements-dev.txt)",
    )
    from netaddr import IPSet

    # Real GeoLite2-ASN is an IPv6 database that also answers IPv4 lookups.
    writer = mmdb_writer.MMDBWriter(
        ip_version=6,
        ipv4_compatible=True,
        database_type="GeoLite2-ASN",
        languages=["en"],
        description={"en": "siem-platform test ASN database"},
    )
    for ip, (number, org) in KNOWN_ASNS.items():
        writer.insert_network(
            IPSet([f"{ip}/32"]),
            {
                "autonomous_system_number": number,
                "autonomous_system_organization": org,
            },
        )
    writer.insert_network(
        IPSet([f"{ASN_IPV6}/128"]),
        {
            "autonomous_system_number": 15169,
            "autonomous_system_organization": "GOOGLE",
        },
    )
    writer.insert_network(
        IPSet([f"{ASN_NUMBER_ONLY_IP}/32"]),
        {"autonomous_system_number": 64500},
    )

    path = tmp_path_factory.mktemp("asn") / "GeoLite2-ASN.mmdb"
    writer.to_db_file(str(path))
    return str(path)


@pytest.fixture(scope="session")
def spark():
    from pyspark.sql import SparkSession

    old_hostname = os.environ.get("SPARK_LOCAL_HOSTNAME")
    os.environ["SPARK_LOCAL_HOSTNAME"] = "localhost"

    # Python workers inherit this process's environment when Spark starts:
    # make sure a developer's real AbuseIPDB key can never reach them.
    saved_env = {
        name: os.environ.pop(name, None)
        for name in _REPUTATION_ENV_VARS
    }

    try:
        session = (
            SparkSession.builder.master("local[2]")
            .appName("siem-enrichment-tests")
            .config("spark.ui.enabled", "false")
            .config("spark.sql.shuffle.partitions", "2")
            .config("spark.sql.session.timeZone", "UTC")
            .getOrCreate()
        )
        session.sparkContext.setLogLevel("ERROR")

        yield session

    finally:
        # Restore the Spark session and the environment even if a test fails.
        if "session" in locals():
            session.stop()

        if old_hostname is None:
            os.environ.pop("SPARK_LOCAL_HOSTNAME", None)
        else:
            os.environ["SPARK_LOCAL_HOSTNAME"] = old_hostname

        for name, value in saved_env.items():
            if value is not None:
                os.environ[name] = value