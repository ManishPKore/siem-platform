"""Event enrichment (GeoIP today; ASN / threat intelligence later).

Only the plain-Python ``GeoIPEnricher`` is re-exported here so that importing
``enrichment`` never pulls in PySpark. Spark integration lives in
``enrichment.spark_enrichment``.
"""

from enrichment.geoip import GeoIPEnricher

__all__ = ["GeoIPEnricher"]