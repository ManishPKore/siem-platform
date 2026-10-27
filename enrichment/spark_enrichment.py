"""Spark pipeline steps: add GeoIP, ASN and IP reputation columns to the
normalized event stream.

    logs-raw -> parse -> normalize_event() -> is_normalization_valid()
                                                     |
                              valid rows ---> add_geoip_columns()
                                                     |
                                             add_asn_columns()
                                                     |
                                        add_reputation_columns()
                                                     |
                                      +--------------+-------------+
                                      v                            v
                          dual sink (PostgreSQL + ES)    detection rules

Column contract: detection_engine/rules/impossible_travel.py reads
``geo_country``, ``geo_latitude`` and ``geo_longitude``.
``geo_is_private`` stays on the stream only (not part of the stored LogEvent).
``asn_number`` / ``asn_org`` are likewise stream columns.
Reputation columns are added for downstream detection and analytics.

Notes
* Vectorized pandas_udf (Arrow), not a row-at-a-time UDF.
* Readers and enrichers are cached per Python worker.
* UDFs are non-deterministic so the optimizer does not reuse their results
  across extracted columns.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional, Union

import pandas as pd
from pyspark.sql import DataFrame
from pyspark.sql import functions as F
from pyspark.sql.functions import pandas_udf
from pyspark.sql.types import (
    ArrayType,
    BooleanType,
    DoubleType,
    IntegerType,
    LongType,
    StringType,
    StructField,
    StructType,
)

from enrichment import asn as _asn
from enrichment.asn import ASNEnricher
from enrichment.geoip import GeoIPEnricher, resolve_db_path
from enrichment.ip_reputation import (
    IPReputationEnricher,
    resolve_blocklist_path,
)

GEO_COUNTRY_COL = "geo_country"
GEO_CITY_COL = "geo_city"
GEO_LATITUDE_COL = "geo_latitude"
GEO_LONGITUDE_COL = "geo_longitude"
GEO_IS_PRIVATE_COL = "geo_is_private"

GEO_COLUMNS = (
    GEO_COUNTRY_COL,
    GEO_CITY_COL,
    GEO_LATITUDE_COL,
    GEO_LONGITUDE_COL,
    GEO_IS_PRIVATE_COL,
)

# GeoIPEnricher.enrich() key -> stream column
_RESULT_KEY_TO_COLUMN = {
    "country": GEO_COUNTRY_COL,
    "city": GEO_CITY_COL,
    "latitude": GEO_LATITUDE_COL,
    "longitude": GEO_LONGITUDE_COL,
    "is_private": GEO_IS_PRIVATE_COL,
}

_GEO_SCHEMA = StructType(
    [
        StructField(GEO_COUNTRY_COL, StringType(), True),
        StructField(GEO_CITY_COL, StringType(), True),
        StructField(GEO_LATITUDE_COL, DoubleType(), True),
        StructField(GEO_LONGITUDE_COL, DoubleType(), True),
        StructField(GEO_IS_PRIVATE_COL, BooleanType(), True),
    ]
)

_enrichers: dict[str, GeoIPEnricher] = {}
_lock = threading.Lock()


def get_enricher(db_path: Optional[Union[str, Path]] = None) -> GeoIPEnricher:
    """Process-wide ``GeoIPEnricher`` for ``db_path`` (the Reader opens once)."""
    key = str(resolve_db_path(db_path))
    enricher = _enrichers.get(key)
    if enricher is None:
        with _lock:
            enricher = _enrichers.get(key)
            if enricher is None:
                enricher = GeoIPEnricher(key)
                _enrichers[key] = enricher
    return enricher


def _build_udf(db_path: Optional[str]):
    @pandas_udf(_GEO_SCHEMA)
    def _geoip(ips: pd.Series) -> pd.DataFrame:
        enricher = get_enricher(db_path)
        records = [
            enricher.enrich(ip if isinstance(ip, str) else None) for ip in ips
        ]
        frame = pd.DataFrame.from_records(
            records, columns=list(_RESULT_KEY_TO_COLUMN)
        )
        return frame.rename(columns=_RESULT_KEY_TO_COLUMN)

    return _geoip.asNondeterministic()


def add_geoip_columns(
    df: DataFrame,
    ip_col: str = "source_ip",
    db_path: Optional[Union[str, Path]] = None,
) -> DataFrame:
    """Append geo_country, geo_city, geo_latitude, geo_longitude and
    geo_is_private. Never drops or filters rows."""
    udf = _build_udf(str(db_path) if db_path is not None else None)
    out = df.withColumn("_geo", udf(F.col(ip_col).cast("string")))
    for column in GEO_COLUMNS:
        out = out.withColumn(column, F.col(f"_geo.{column}"))
    return out.drop("_geo")


# ---------------------------------------------------------------------- ASN
ASN_NUMBER_COL = "asn_number"
ASN_ORG_COL = "asn_org"

ASN_COLUMNS = (ASN_NUMBER_COL, ASN_ORG_COL)

# ASNs are unsigned 32-bit (up to 4,294,967,295) -- LongType, not IntegerType.
_ASN_SCHEMA = StructType(
    [
        StructField(ASN_NUMBER_COL, LongType(), True),
        StructField(ASN_ORG_COL, StringType(), True),
    ]
)

_asn_enrichers: dict[str, ASNEnricher] = {}


def get_asn_enricher(db_path: Optional[Union[str, Path]] = None) -> ASNEnricher:
    """Process-wide ``ASNEnricher`` for ``db_path`` (the Reader opens once)."""
    key = str(_asn.resolve_db_path(db_path))
    enricher = _asn_enrichers.get(key)
    if enricher is None:
        with _lock:
            enricher = _asn_enrichers.get(key)
            if enricher is None:
                enricher = ASNEnricher(key)
                _asn_enrichers[key] = enricher
    return enricher


def _build_asn_udf(db_path: Optional[str]):
    @pandas_udf(_ASN_SCHEMA)
    def _asn_lookup(ips: pd.Series) -> pd.DataFrame:
        enricher = get_asn_enricher(db_path)
        records = [
            enricher.enrich(ip if isinstance(ip, str) else None) for ip in ips
        ]
        frame = pd.DataFrame.from_records(records, columns=list(ASN_COLUMNS))
        # Nullable Int64 keeps large ASNs exact instead of going via float64.
        frame[ASN_NUMBER_COL] = frame[ASN_NUMBER_COL].astype("Int64")
        return frame

    return _asn_lookup.asNondeterministic()


def add_asn_columns(
    df: DataFrame,
    ip_col: str = "source_ip",
    db_path: Optional[Union[str, Path]] = None,
) -> DataFrame:
    """Append asn_number (long) and asn_org (string). Never drops or filters
    rows; private, invalid, null and unknown IPs get null ASN fields."""
    udf = _build_asn_udf(str(db_path) if db_path is not None else None)
    out = df.withColumn("_asn", udf(F.col(ip_col).cast("string")))
    for column in ASN_COLUMNS:
        out = out.withColumn(column, F.col(f"_asn.{column}"))
    return out.drop("_asn")


# --------------------------------------------------------------- IP reputation
REPUTATION_SCORE_COL = "reputation_score"
IS_KNOWN_THREAT_COL = "is_known_threat"
THREAT_CATEGORIES_COL = "threat_categories"

REPUTATION_COLUMNS = (
    REPUTATION_SCORE_COL,
    IS_KNOWN_THREAT_COL,
    THREAT_CATEGORIES_COL,
)

_REPUTATION_SCHEMA = StructType(
    [
        StructField(REPUTATION_SCORE_COL, IntegerType(), True),
        StructField(IS_KNOWN_THREAT_COL, BooleanType(), True),
        StructField(THREAT_CATEGORIES_COL, ArrayType(StringType()), True),
    ]
)

_reputation_enrichers: dict[str, IPReputationEnricher] = {}


def get_reputation_enricher(
    blocklist_path: Optional[Union[str, Path]] = None,
) -> IPReputationEnricher:
    """Return a process-wide IPReputationEnricher for the selected blocklist.

    Each Python worker maintains its own enricher, cache and daily API budget.
    API credentials should be obtained from the worker's environment.
    """
    key = str(resolve_blocklist_path(blocklist_path))
    enricher = _reputation_enrichers.get(key)

    if enricher is None:
        with _lock:
            enricher = _reputation_enrichers.get(key)
            if enricher is None:
                enricher = IPReputationEnricher(blocklist_path=key)
                _reputation_enrichers[key] = enricher

    return enricher


def reputation_frame(
    ips: pd.Series,
    enricher: IPReputationEnricher,
) -> pd.DataFrame:
    """Build the pandas result frame used by the reputation pandas UDF."""
    records = [
        enricher.enrich(ip if isinstance(ip, str) else None)
        for ip in ips
    ]

    frame = pd.DataFrame.from_records(
        records,
        columns=list(REPUTATION_COLUMNS),
    )
    frame[REPUTATION_SCORE_COL] = frame[REPUTATION_SCORE_COL].astype("Int64")

    return frame


def _build_reputation_udf(blocklist_path: Optional[str]):
    @pandas_udf(_REPUTATION_SCHEMA)
    def _reputation_lookup(ips: pd.Series) -> pd.DataFrame:
        return reputation_frame(
            ips,
            get_reputation_enricher(blocklist_path),
        )

    return _reputation_lookup.asNondeterministic()


def add_reputation_columns(
    df: DataFrame,
    ip_col: str = "source_ip",
    blocklist_path: Optional[Union[str, Path]] = None,
) -> DataFrame:
    """Append IP reputation columns without dropping or filtering events.

    Adds:
    - reputation_score: nullable integer score
    - is_known_threat: nullable boolean indicating a known threat
    - threat_categories: array of threat category strings

    Private, invalid and null IPs should remain unassessed, and unavailable
    external reputation services should fall back to the local blocklist.
    """
    udf = _build_reputation_udf(
        str(blocklist_path) if blocklist_path is not None else None
    )

    out = df.withColumn(
        "_rep",
        udf(F.col(ip_col).cast("string")),
    )

    for column in REPUTATION_COLUMNS:
        out = out.withColumn(column, F.col(f"_rep.{column}"))

    return out.drop("_rep")
