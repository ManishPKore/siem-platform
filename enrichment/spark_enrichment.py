"""Spark pipeline step: add GeoIP columns to the normalized event stream.

    logs-raw -> parse -> normalize_event() -> is_normalization_valid()
                                                     |
                              valid rows ---> add_geoip_columns()   <- here
                                                     |
                                      +--------------+-------------+
                                      v                            v
                          dual sink (PostgreSQL + ES)    detection rules

Column contract: detection_engine/rules/impossible_travel.py reads
``geo_country``, ``geo_latitude`` and ``geo_longitude``;
tests/enrichment/test_enrichment_contract.py fails if either side drifts.
``geo_is_private`` stays on the stream only (not part of the stored LogEvent).

Notes
* Vectorized pandas_udf (Arrow), not a row-at-a-time UDF, in the spirit of
  consumers/normalizer.py. pandas/pyarrow are already in requirements.txt.
* The MMDB reader can't be pickled, so each Python worker opens its own once
  (``get_enricher``). The db path is captured in the UDF closure.
* The UDF is non-deterministic so the optimizer runs it once per row, not
  once per extracted geo_* column.
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
    BooleanType,
    DoubleType,
    StringType,
    StructField,
    StructType,
)

from enrichment.geoip import GeoIPEnricher, resolve_db_path

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