from __future__ import annotations

import ipaddress
import unittest

from geoip_gen.builder import validate_cidr
from geoip_gen.codec import decode_geoip_list, encode_geoip_list
from geoip_gen.models import CIDR, GeoEntry, GeoIPBuildError


def cidr_from_text(value: str) -> CIDR:
    network = ipaddress.ip_network(value, strict=False)
    return CIDR(network.network_address.packed, network.prefixlen)


class CodecTests(unittest.TestCase):
    def test_decode_geoip_list_round_trips_encoded_entries(self) -> None:
        # Given: a deterministic CN and PRIVATE fixture with IPv4 and IPv6 CIDRs.
        entries = (
            GeoEntry(
                "CN",
                (
                    cidr_from_text("1.0.1.0/24"),
                    cidr_from_text("240e::/20"),
                ),
            ),
            GeoEntry(
                "PRIVATE",
                (
                    cidr_from_text("10.0.0.0/8"),
                    cidr_from_text("fc00::/7"),
                ),
            ),
        )

        # When: the entries are encoded and decoded through the real codec.
        decoded = decode_geoip_list(encode_geoip_list(entries))

        # Then: the model values are preserved exactly.
        self.assertEqual(entries, decoded)

    def test_validate_cidr_rejects_prefix_longer_than_address_length(self) -> None:
        cases = (
            CIDR(ipaddress.ip_address("192.0.2.0").packed, 33),
            CIDR(ipaddress.ip_address("2001:db8::").packed, 129),
        )

        for cidr in cases:
            with self.subTest(prefix=cidr.prefix):
                with self.assertRaises(GeoIPBuildError):
                    validate_cidr(cidr)

    def test_constructed_cidr_values_have_expected_ip_byte_lengths(self) -> None:
        cases = (
            (cidr_from_text("198.51.100.0/24"), 4),
            (cidr_from_text("2001:db8::/32"), 16),
        )

        for cidr, expected_length in cases:
            with self.subTest(prefix=cidr.prefix):
                self.assertEqual(expected_length, len(cidr.ip))


if __name__ == "__main__":
    unittest.main()
