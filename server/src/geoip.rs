use maxminddb::Reader;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::OnceLock;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct GeoIpResult {
    pub country: String,
    pub asn_org: String,
}

#[derive(Debug)]
struct GeoIpResolver {
    country: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
}

#[derive(Debug, Deserialize)]
struct CountryRecord {
    country: Option<NamedRecord>,
}

#[derive(Debug, Deserialize)]
struct NamedRecord {
    names: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct AsnRecord {
    autonomous_system_organization: Option<String>,
}

impl GeoIpResolver {
    fn load() -> Self {
        let mmdb_dir =
            std::env::var("BANNKENN_MMDB_DIR").unwrap_or_else(|_| "server/data".to_string());
        let country_path = PathBuf::from(&mmdb_dir).join("GeoLite2-Country.mmdb");
        let asn_path = PathBuf::from(&mmdb_dir).join("GeoLite2-ASN.mmdb");

        let country = match Reader::open_readfile(&country_path) {
            Ok(reader) => {
                info!("GeoIP country DB loaded from {}", country_path.display());
                Some(reader)
            }
            Err(err) => {
                warn!(
                    "GeoIP country DB unavailable at {}: {}",
                    country_path.display(),
                    err
                );
                None
            }
        };

        let asn = match Reader::open_readfile(&asn_path) {
            Ok(reader) => {
                info!("GeoIP ASN DB loaded from {}", asn_path.display());
                Some(reader)
            }
            Err(err) => {
                warn!(
                    "GeoIP ASN DB unavailable at {}: {}",
                    asn_path.display(),
                    err
                );
                None
            }
        };

        Self { country, asn }
    }

    fn lookup(&self, ip: &str) -> GeoIpResult {
        let mut result = GeoIpResult {
            country: "Unknown".to_string(),
            asn_org: "Unknown".to_string(),
        };

        let Ok(ip_addr) = ip.parse::<IpAddr>() else {
            return result;
        };

        if let Some(reader) = &self.country {
            if let Ok(record) = reader.lookup::<CountryRecord>(ip_addr) {
                if let Some(country) = record
                    .country
                    .and_then(|entry| entry.names)
                    .and_then(|names| names.get("en").cloned())
                    .filter(|value| !value.trim().is_empty())
                {
                    result.country = country;
                }
            }
        }

        if let Some(reader) = &self.asn {
            if let Ok(record) = reader.lookup::<AsnRecord>(ip_addr) {
                if let Some(org) = record
                    .autonomous_system_organization
                    .filter(|value| !value.trim().is_empty())
                {
                    result.asn_org = org;
                }
            }
        }

        result
    }
}

static GEOIP_RESOLVER: OnceLock<GeoIpResolver> = OnceLock::new();

pub fn lookup(ip: &str) -> GeoIpResult {
    let resolver = GEOIP_RESOLVER.get_or_init(GeoIpResolver::load);
    resolver.lookup(ip)
}
