# mihomo-rules

Pre-built `geoip.dat` for [Mihomo](https://github.com/MetaCubeX/mihomo) and [FlClash](https://github.com/chen08209/FlClash). Contains exactly two tags: `CN` (Chinese mainland IP ranges) and `PRIVATE` (standard special-purpose and private ranges).

## Artifact

| Field | Value |
|---|---|
| File | `geoip.dat` |
| Format | V2Ray GeoIPList (protobuf) |
| CN entries | 7456 |
| PRIVATE entries | 21 |
| SHA-256 | `303d175dad44a2c342645504e3ac50f95c4fa5c798901737bdb84e7a8a8071f6` |

Source data: [17mon/china_ip_list](https://github.com/17mon/china_ip_list) (`china_ip_list.txt`), licensed CC-BY-NC-SA 4.0.

## Download URLs

**jsDelivr CDN (recommended for most users):**
```
https://cdn.jsdelivr.net/gh/best-linux-code/mihomo-rules@main/geoip.dat
```

**Raw GitHub (fallback):**
```
https://raw.githubusercontent.com/best-linux-code/mihomo-rules/main/geoip.dat
```

**GitHub Releases:**
```
https://github.com/best-linux-code/mihomo-rules/releases/download/latest/geoip.dat
```

## Mihomo / FlClash Configuration

Add these keys to your `config.yaml`:

```yaml
geodata-mode: true
geo-auto-update: true
geo-update-interval: 24

geox-url:
  geoip: "https://cdn.jsdelivr.net/gh/best-linux-code/mihomo-rules@main/geoip.dat"
```

After changing `geox-url.geoip`, delete the cached `geoip.dat` in Mihomo's data directory and restart the service (or FlClash) so it fetches the new file. Mihomo won't replace a cached file just because the URL changed.

### Rules example

```yaml
rules:
  - GEOIP,PRIVATE,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
```

> **Note:** This file only contains the `CN` and `PRIVATE` tags. Rules referencing any other tag (e.g., `GEOIP,US,...`) will not match anything and should be removed.

## Regeneration

Clone the repo and run:

```sh
# Rebuild geoip.dat from the latest china_ip_list.txt
python3 generate_geoip.py generate

# Inspect tag counts and CIDRs in the built file
python3 generate_geoip.py inspect

# Run the test suite
python3 -m unittest discover -s tests -v
```

## License

The generator code and tooling in this repository are released under the [MIT License](LICENSE).

The IP data embedded in `geoip.dat` is derived from [17mon/china_ip_list](https://github.com/17mon/china_ip_list), which is licensed under [CC-BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/). See [NOTICE](NOTICE) for full attribution.
