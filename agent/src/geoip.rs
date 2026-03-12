//! Lightweight GeoIP lookup for the agent.
//!
//! Reads the same MaxMind GeoLite2 `.mmdb` database files used by the server.
//! The directory path is configured via `mmdb_dir` in `agent.toml`.  If the
//! files are not found at startup, all lookups return `"Unknown"` gracefully —
//! GeoIP enrichment is entirely optional.
//!
//! The resolver is initialised **once** via [`init`] (called from `main`) and
//! stored in a process-global `OnceLock`.  Subsequent calls to [`lookup`] are
//! cheap in-memory reads.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::OnceLock;

// ── Public types ──────────────────────────────────────────────────────────────

/// GeoIP information for a single IP address.
#[derive(Debug, Clone, Default)]
pub struct GeoTag {
    /// ISO country name (e.g. `"United States"`) or `"Unknown"`.
    pub country: String,
    /// Autonomous-system organisation name (e.g. `"Cloudflare"`) or `"Unknown"`.
    pub asn_org: String,
}

// ── Internal resolver ─────────────────────────────────────────────────────────

struct GeoResolver {
    country: Option<maxminddb::Reader<Vec<u8>>>,
    asn: Option<maxminddb::Reader<Vec<u8>>>,
}

#[derive(serde::Deserialize)]
struct CountryRecord {
    country: Option<NamedRecord>,
}

#[derive(serde::Deserialize)]
struct NamedRecord {
    names: Option<HashMap<String, String>>,
}

#[derive(serde::Deserialize)]
struct AsnRecord {
    autonomous_system_organization: Option<String>,
}

impl GeoResolver {
    fn load(mmdb_dir: &str) -> Self {
        let base = PathBuf::from(mmdb_dir);

        let country = Self::open_reader(base.join("GeoLite2-Country.mmdb"));
        let asn = Self::open_reader(base.join("GeoLite2-ASN.mmdb"));

        Self { country, asn }
    }

    fn open_reader(path: PathBuf) -> Option<maxminddb::Reader<Vec<u8>>> {
        match maxminddb::Reader::open_readfile(&path) {
            Ok(r) => {
                tracing::info!("GeoIP DB loaded: {}", path.display());
                Some(r)
            }
            Err(e) => {
                tracing::debug!(
                    "GeoIP DB not available at {} (geo features disabled for this DB): {}",
                    path.display(),
                    e
                );
                None
            }
        }
    }

    fn lookup(&self, ip: &str) -> GeoTag {
        let addr: IpAddr = match ip.parse() {
            Ok(a) => a,
            Err(_) => return GeoTag::default(),
        };

        let country = self
            .country
            .as_ref()
            .and_then(|r| {
                let rec: CountryRecord = r.lookup(addr).ok()?;
                let name = rec.country?.names?.remove("en")?;
                Some(name)
            })
            .unwrap_or_else(|| "Unknown".to_string());

        let asn_org = self
            .asn
            .as_ref()
            .and_then(|r| {
                let rec: AsnRecord = r.lookup(addr).ok()?;
                rec.autonomous_system_organization
            })
            .unwrap_or_else(|| "Unknown".to_string());

        GeoTag { country, asn_org }
    }
}

// ── Global resolver ───────────────────────────────────────────────────────────

static RESOLVER: OnceLock<GeoResolver> = OnceLock::new();

/// Initialise the GeoIP resolver with the given database directory.
///
/// Must be called once at agent startup before any call to [`lookup`].
/// Subsequent calls are harmless no-ops (the first call wins).
pub fn init(mmdb_dir: &str) {
    RESOLVER.get_or_init(|| {
        tracing::info!("Initialising agent GeoIP resolver from '{}'", mmdb_dir);
        GeoResolver::load(mmdb_dir)
    });
}

/// Look up GeoIP data for `ip`.
///
/// Returns `GeoTag { country: "Unknown", asn_org: "Unknown" }` when the
/// resolver has not been initialised or the IP is not in the database.
pub fn lookup(ip: &str) -> GeoTag {
    RESOLVER.get().map(|r| r.lookup(ip)).unwrap_or_default()
}
