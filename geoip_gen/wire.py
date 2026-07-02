from __future__ import annotations

from typing import Tuple

from .models import GeoIPBuildError


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise GeoIPBuildError(detail)


def encode_varint(value: int) -> bytes:
    require(value >= 0, "varint cannot encode a negative value")
    out = bytearray()
    remaining = value
    while remaining >= 0x80:
        out.append((remaining & 0x7F) | 0x80)
        remaining >>= 7
    out.append(remaining)
    return bytes(out)


def encode_length_field(field_number: int, payload: bytes) -> bytes:
    return encode_varint((field_number << 3) | 2) + encode_varint(len(payload)) + payload


def read_varint(data: bytes, offset: int) -> Tuple[int, int]:
    value = 0
    shift = 0
    cursor = offset
    while cursor < len(data):
        byte = data[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, cursor
        shift += 7
        require(shift <= 63, "varint is too long")
    raise GeoIPBuildError("truncated varint")


def read_length_payload(data: bytes, offset: int) -> Tuple[bytes, int]:
    length, cursor = read_varint(data, offset)
    end = cursor + length
    require(end <= len(data), "length-delimited field exceeds message size")
    return data[cursor:end], end


def read_tag(data: bytes, offset: int) -> Tuple[int, int, int]:
    tag, cursor = read_varint(data, offset)
    field_number = tag >> 3
    wire_type = tag & 0x07
    require(field_number > 0, "protobuf field number must be positive")
    return field_number, wire_type, cursor
