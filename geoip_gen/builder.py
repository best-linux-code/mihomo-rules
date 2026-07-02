from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence, Set, Tuple

from .codec import decode_geoip_list, encode_geoip_list
from .models import BuildResult, CIDR, GeoEntry, IPNetwork, PRIVATE_CIDRS, Paths, SOURCE_URL
from .wire import require


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_networks(path: Path) -> Tuple[IPNetwork, ...]:
    networks: Set[IPNetwork] = set()
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.partition("#")[0].strip()
            if line:
                networks.add(ipaddress.ip_network(line, strict=False))
    return tuple(sorted(networks, key=network_sort_key))


def network_sort_key(network: IPNetwork) -> Tuple[int, int, int]:
    return network.version, int(network.network_address), network.prefixlen


def cidrs_from_networks(networks: Sequence[IPNetwork]) -> Tuple[CIDR, ...]:
    return tuple(CIDR(network.network_address.packed, network.prefixlen) for network in networks)


def validate_cidr(cidr: CIDR) -> None:
    length = len(cidr.ip)
    max_prefix = {4: 32, 16: 128}.get(length)
    require(max_prefix is not None, "CIDR ip must be 4 or 16 bytes")
    require(cidr.prefix <= max_prefix, "CIDR prefix exceeds address length")


def contains_ip(entry: GeoEntry, address_text: str) -> bool:
    address = ipaddress.ip_address(address_text)
    return any(address in cidr_network(cidr) for cidr in entry.cidrs)


def cidr_network(cidr: CIDR) -> IPNetwork:
    address = ipaddress.ip_address(cidr.ip)
    return ipaddress.ip_network(str(address) + "/" + str(cidr.prefix), strict=False)


def validate_membership(cn_entry: GeoEntry, private_entry: GeoEntry, cn_networks: Sequence[IPNetwork]) -> None:
    for address in ("192.168.1.1", "10.0.0.1", "127.0.0.1", "::1", "fe80::1", "ff02::1"):
        require(contains_ip(private_entry, address), address + " should be PRIVATE")
    require(not contains_ip(private_entry, "8.8.8.8"), "8.8.8.8 should not be PRIVATE")
    require(not contains_ip(cn_entry, "8.8.8.8"), "8.8.8.8 should not be CN")
    preferred = ipaddress.ip_address("1.0.1.1")
    sample = str(preferred) if any(preferred in network for network in cn_networks) else str(cn_networks[0].network_address)
    require(contains_ip(cn_entry, sample), sample + " should be CN")


def validate_entries(entries: Sequence[GeoEntry], cn_networks: Sequence[IPNetwork]) -> BuildResult:
    require(len(entries) == 2, "GeoIPList must contain exactly two entries")
    require(tuple(entry.code for entry in entries) == ("CN", "PRIVATE"), "codes must be CN, PRIVATE")
    cn_entry, private_entry = entries
    require(len(cn_entry.cidrs) == len(cn_networks), "CN decoded count differs from parsed input")
    require(len(private_entry.cidrs) == len(PRIVATE_CIDRS), "PRIVATE decoded count must be 21")
    for entry in entries:
        for cidr in entry.cidrs:
            validate_cidr(cidr)
    validate_membership(cn_entry, private_entry, cn_networks)
    return BuildResult("", "", len(cn_entry.cidrs), len(private_entry.cidrs))


def write_provenance(paths: Paths, result: BuildResult) -> None:
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    provenance = {
        "source_url": SOURCE_URL,
        "timestamp_utc": timestamp,
        "input_sha256": result.input_sha256,
        "output_sha256": result.output_sha256,
        "entry_counts": {"CN": result.cn_count, "PRIVATE": result.private_count},
        "private_cidrs": list(PRIVATE_CIDRS),
    }
    paths.provenance.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def generate(paths: Paths) -> BuildResult:
    cn_networks = parse_networks(paths.source)
    private_networks = tuple(ipaddress.ip_network(cidr, strict=False) for cidr in PRIVATE_CIDRS)
    entries = (
        GeoEntry("CN", cidrs_from_networks(cn_networks)),
        GeoEntry("PRIVATE", cidrs_from_networks(private_networks)),
    )
    paths.output.write_bytes(encode_geoip_list(entries))
    checked = validate_entries(decode_geoip_list(paths.output.read_bytes()), cn_networks)
    result = BuildResult(sha256_file(paths.source), sha256_file(paths.output), checked.cn_count, checked.private_count)
    paths.checksum.write_text(result.output_sha256 + "  " + paths.output.name + "\n", encoding="utf-8")
    write_provenance(paths, result)
    return result


def inspect(paths: Paths) -> BuildResult:
    cn_networks = parse_networks(paths.source)
    checked = validate_entries(decode_geoip_list(paths.output.read_bytes()), cn_networks)
    return BuildResult(sha256_file(paths.source), sha256_file(paths.output), checked.cn_count, checked.private_count)
