from __future__ import annotations

from typing import Optional, Sequence, Tuple

from .models import CIDR, GeoEntry, GeoIPBuildError
from .wire import encode_length_field, encode_varint, read_length_payload, read_tag, read_varint, require


def encode_cidr(cidr: CIDR) -> bytes:
    return encode_length_field(1, cidr.ip) + encode_varint(16) + encode_varint(cidr.prefix)


def encode_geoip(entry: GeoEntry) -> bytes:
    cidrs = b"".join(encode_length_field(2, encode_cidr(cidr)) for cidr in entry.cidrs)
    return encode_length_field(1, entry.code.encode("ascii")) + cidrs


def encode_geoip_list(entries: Sequence[GeoEntry]) -> bytes:
    return b"".join(encode_length_field(1, encode_geoip(entry)) for entry in entries)


def decode_cidr(data: bytes) -> CIDR:
    cursor = 0
    ip_bytes: Optional[bytes] = None
    prefix: Optional[int] = None
    while cursor < len(data):
        field_number, wire_type, cursor = read_tag(data, cursor)
        if field_number == 1 and wire_type == 2:
            ip_bytes, cursor = read_length_payload(data, cursor)
        elif field_number == 2 and wire_type == 0:
            prefix, cursor = read_varint(data, cursor)
        else:
            raise GeoIPBuildError("unexpected CIDR field")
    require(ip_bytes is not None, "CIDR is missing ip bytes")
    require(prefix is not None, "CIDR is missing prefix")
    return CIDR(ip_bytes, prefix)


def decode_geoip(data: bytes) -> GeoEntry:
    cursor = 0
    code: Optional[str] = None
    cidrs = []
    while cursor < len(data):
        field_number, wire_type, cursor = read_tag(data, cursor)
        if field_number == 1 and wire_type == 2:
            payload, cursor = read_length_payload(data, cursor)
            code = payload.decode("ascii")
        elif field_number == 2 and wire_type == 2:
            payload, cursor = read_length_payload(data, cursor)
            cidrs.append(decode_cidr(payload))
        else:
            raise GeoIPBuildError("unexpected GeoIP field")
    require(code is not None, "GeoIP is missing code")
    return GeoEntry(code, tuple(cidrs))


def decode_geoip_list(data: bytes) -> Tuple[GeoEntry, ...]:
    cursor = 0
    entries = []
    while cursor < len(data):
        field_number, wire_type, cursor = read_tag(data, cursor)
        require(field_number == 1 and wire_type == 2, "unexpected GeoIPList field")
        payload, cursor = read_length_payload(data, cursor)
        entries.append(decode_geoip(payload))
    return tuple(entries)
