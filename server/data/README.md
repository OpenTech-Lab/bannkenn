# GeoLite2 Databases

This directory holds MaxMind GeoLite2 binary databases used for IP geolocation.
The `.mmdb` files are **not included in the repository** and must be downloaded separately.

## Required files

| File | Purpose |
|------|---------|
| `GeoLite2-Country.mmdb` | IP → country code and name |
| `GeoLite2-City.mmdb` | IP → city, region, coordinates |
| `GeoLite2-ASN.mmdb` | IP → ASN and organisation name |

## How to download

1. Create a free MaxMind account at <https://www.maxmind.com/en/geolite2/signup>
2. Generate a licence key under **My Account → Manage Licence Keys**
3. Download the databases directly:

```bash
# Replace YOUR_LICENCE_KEY with your key
curl -sL "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=YOUR_LICENCE_KEY&suffix=tar.gz" \
  | tar -xzO --wildcards "*/GeoLite2-Country.mmdb" > GeoLite2-Country.mmdb

curl -sL "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENCE_KEY&suffix=tar.gz" \
  | tar -xzO --wildcards "*/GeoLite2-City.mmdb" > GeoLite2-City.mmdb

curl -sL "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=YOUR_LICENCE_KEY&suffix=tar.gz" \
  | tar -xzO --wildcards "*/GeoLite2-ASN.mmdb" > GeoLite2-ASN.mmdb
```

Alternatively, use the [MaxMind GeoIP Update](https://github.com/maxmind/geoipupdate) tool
(`geoipupdate`) to keep the databases automatically up to date.

## License

GeoLite2 databases are provided by MaxMind and licensed under the
[Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).

See `LICENSE` in this directory for the full license text.

This product includes GeoLite2 data created by MaxMind, available from
<https://www.maxmind.com>.
