from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Final, NamedTuple, Tuple, Union


SOURCE_URL: Final = (
    "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt"
)
PRIVATE_CIDRS: Final = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
    "::/128",
    "::1/128",
    "fc00::/7",
    "ff00::/8",
    "fe80::/10",
)

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class GeoIPBuildError(Exception):
    pass


class CIDR(NamedTuple):
    ip: bytes
    prefix: int


class GeoEntry(NamedTuple):
    code: str
    cidrs: Tuple[CIDR, ...]


class Paths(NamedTuple):
    root: Path
    source: Path
    output: Path
    checksum: Path
    provenance: Path


class BuildResult(NamedTuple):
    input_sha256: str
    output_sha256: str
    cn_count: int
    private_count: int


def build_paths(root: Path) -> Paths:
    return Paths(
        root=root,
        source=root / "china_ip_list.txt",
        output=root / "geoip.dat",
        checksum=root / "geoip.dat.sha256",
        provenance=root / "PROVENANCE.json",
    )
