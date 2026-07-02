from __future__ import annotations

import hashlib
import unittest
from pathlib import Path
from typing import Final

from geoip_gen.builder import contains_ip
from geoip_gen.codec import decode_geoip_list
from geoip_gen.models import GeoEntry, build_paths


ROOT: Final = Path(__file__).resolve().parents[1]
EXPECTED_SHA256: Final = "303d175dad44a2c342645504e3ac50f95c4fa5c798901737bdb84e7a8a8071f6"


def entries_by_code() -> dict[str, GeoEntry]:
    data = build_paths(ROOT).output.read_bytes()
    return {entry.code: entry for entry in decode_geoip_list(data)}


class GeoIPArtifactTests(unittest.TestCase):
    def test_geoip_dat_contains_cn_and_private_entries_for_mihomo(self) -> None:
        paths = build_paths(ROOT)
        data = paths.output.read_bytes()
        entries = decode_geoip_list(data)
        by_code = {entry.code: entry for entry in entries}

        self.assertEqual(EXPECTED_SHA256, hashlib.sha256(data).hexdigest())
        self.assertEqual(("CN", "PRIVATE"), tuple(entry.code for entry in entries))
        self.assertEqual(7456, len(by_code["CN"].cidrs))
        self.assertGreaterEqual(len(by_code["CN"].cidrs), 5000)
        self.assertEqual(21, len(by_code["PRIVATE"].cidrs))

    def test_geoip_dat_membership_matches_mihomo_rules(self) -> None:
        entries = entries_by_code()
        cn_entry = entries["CN"]
        private_entry = entries["PRIVATE"]

        for address in ("114.114.114.114", "1.0.1.1"):
            with self.subTest(address=address):
                self.assertTrue(contains_ip(cn_entry, address))

        self.assertFalse(contains_ip(cn_entry, "8.8.8.8"))

        for address in ("192.168.1.1", "10.0.0.1", "127.0.0.1", "::1", "fe80::1", "ff02::1"):
            with self.subTest(address=address):
                self.assertTrue(contains_ip(private_entry, address))

        self.assertFalse(contains_ip(private_entry, "8.8.8.8"))


if __name__ == "__main__":
    unittest.main()
