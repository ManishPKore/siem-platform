"""IP-address helpers shared by the GeoIP and ASN enrichers.

Pure standard library: importing this module never pulls in geoip2, pandas
or PySpark.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Optional, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def parse_ip(value: Any) -> Optional[IPAddress]:
    """Parse ``value`` into an address, or return None if it is not an IP.

    IPv4-mapped IPv6 addresses (``::ffff:8.8.8.8``) are unwrapped to IPv4 so
    they hit the same database record and cache entry as the plain form.
    """
    if not isinstance(value, str):
        return None
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


def is_non_public(addr: IPAddress) -> bool:
    """True for addresses that can never appear in a public MaxMind database.

    ``not is_global`` covers RFC 1918, loopback, link-local, CGNAT
    (100.64/10), documentation ranges (e.g. 203.0.113.0/24), reserved and
    unspecified addresses; multicast is excluded explicitly.
    """
    return (not addr.is_global) or addr.is_multicast