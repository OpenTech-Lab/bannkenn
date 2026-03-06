//! Local cross-IP campaign correlation.
//!
//! Even when an attacker rotates through different IPs (potentially from
//! different countries or ISPs), they typically reuse the **same attack pattern**
//! within a short time window.  This module detects such coordinated campaigns
//! by tracking distinct source IPs per attack category.
//!
//! ## Two detection modes
//!
//! ### Volume-based campaign
//! Triggered when the number of **distinct IPs** using the same attack category
//! within the window exceeds `distinct_ips_threshold`.  The IPs can originate
//! from anywhere in the world — the pattern alone is sufficient.
//!
//! ### Geo-fingerprinted campaign (requires `geo_grouping = true`)
//! Triggered when distinct IPs from the **same country + ISP** pair attack with
//! the same category within the window.  Useful against botnets whose nodes
//! share an ASN (e.g. rented cloud VMs from the same provider/region).
//!
//! When either campaign is detected, the caller should reduce the block
//! threshold to 1 so the **next new IP** using that attack type is immediately
//! blocked rather than being allowed to accumulate attempts.

use crate::burst::categorize_reason;
use crate::geoip::GeoTag;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

// ── Configuration ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignConfig {
    /// Whether campaign correlation is active.
    #[serde(default)]
    pub enabled: bool,

    /// Sliding window (seconds) over which distinct IPs are counted.
    /// Attacks from outside this window are forgotten.
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,

    /// Number of **distinct** source IPs using the same attack category within
    /// `window_secs` before a *volume* campaign is declared.
    #[serde(default = "default_distinct_ips_threshold")]
    pub distinct_ips_threshold: u32,

    /// Enable the geo-fingerprinted campaign detector.
    /// Requires `mmdb_dir` to be configured in the agent config.
    #[serde(default)]
    pub geo_grouping: bool,

    /// Number of distinct IPs from the **same country + ISP** using the same
    /// attack category within the window before a *geo* campaign is declared.
    #[serde(default = "default_geo_ips_threshold")]
    pub geo_ips_threshold: u32,
}

fn default_window_secs() -> u64 {
    3600
}
fn default_distinct_ips_threshold() -> u32 {
    5
}
fn default_geo_ips_threshold() -> u32 {
    3
}

impl Default for CampaignConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_secs: default_window_secs(),
            distinct_ips_threshold: default_distinct_ips_threshold(),
            geo_grouping: false,
            geo_ips_threshold: default_geo_ips_threshold(),
        }
    }
}

// ── Campaign Level ────────────────────────────────────────────────────────────

/// What kind of campaign was identified for this event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CampaignLevel {
    /// Many unrelated IPs using the same attack pattern (global sweep).
    ByVolume,
    /// Many IPs from the same country + ISP using the same attack pattern
    /// (coordinated botnet within the same infrastructure).
    ByGeo { country: String, asn_org: String },
}

impl CampaignLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ByVolume => "volume",
            Self::ByGeo { .. } => "geo",
        }
    }

    /// Human-readable label for log messages and reason tags.
    pub fn label(&self) -> String {
        match self {
            Self::ByVolume => "campaign:volume".to_string(),
            Self::ByGeo { country, asn_org } => {
                format!("campaign:geo|{}/{}", country, asn_org)
            }
        }
    }
}

// ── Internal window tracker ───────────────────────────────────────────────────

/// Time-windowed list of `(ip, timestamp)` entries.
///
/// After pruning, `.distinct_ips()` returns the set of unique IPs seen within
/// the window.
struct CategoryWindow {
    entries: VecDeque<(String, Instant)>,
}

impl CategoryWindow {
    fn new() -> Self {
        Self {
            entries: VecDeque::new(),
        }
    }

    /// Prune entries older than `window`, add `ip`, and return the set of
    /// distinct IPs currently in the window (including the just-added one).
    fn push_and_count(&mut self, ip: &str, now: Instant, window: Duration) -> HashSet<String> {
        // Evict stale entries.
        while let Some((_, ts)) = self.entries.front() {
            if now.duration_since(*ts) > window {
                self.entries.pop_front();
            } else {
                break;
            }
        }
        self.entries.push_back((ip.to_string(), now));

        // Collect distinct IPs.
        self.entries.iter().map(|(ip, _)| ip.clone()).collect()
    }
}

// ── Tracker ───────────────────────────────────────────────────────────────────

/// Tracks distinct source IPs per attack category and declares campaigns when
/// the configured thresholds are exceeded.
pub struct LocalCampaignTracker {
    /// Per-category volume tracker: `attack_category → window`.
    by_category: HashMap<String, CategoryWindow>,

    /// Geo-fingerprinted tracker: `(country, asn_org) → (category → window)`.
    by_geo: HashMap<(String, String), HashMap<String, CategoryWindow>>,
}

impl Default for LocalCampaignTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalCampaignTracker {
    pub fn new() -> Self {
        Self {
            by_category: HashMap::new(),
            by_geo: HashMap::new(),
        }
    }

    /// Record one attack attempt and return a `CampaignLevel` if a campaign
    /// has been detected.  Returns `None` when disabled or below thresholds.
    ///
    /// - `ip`: source address of the attacker.
    /// - `reason`: raw event reason string (will be normalized to a category).
    /// - `geo`: optional GeoIP data for this IP.
    pub fn record(
        &mut self,
        ip: &str,
        reason: &str,
        geo: Option<&GeoTag>,
        cfg: &CampaignConfig,
    ) -> Option<CampaignLevel> {
        if !cfg.enabled {
            return None;
        }

        let now = Instant::now();
        let window = Duration::from_secs(cfg.window_secs.max(60));
        let category = categorize_reason(reason).to_string();

        // ── Volume-based check ────────────────────────────────────────────────
        let vol_win = self
            .by_category
            .entry(category.clone())
            .or_insert_with(CategoryWindow::new);
        let distinct = vol_win.push_and_count(ip, now, window);

        if distinct.len() >= cfg.distinct_ips_threshold as usize {
            tracing::warn!(
                "Campaign (volume) detected for '{}': {} distinct IPs in {}s window",
                category,
                distinct.len(),
                cfg.window_secs
            );
            return Some(CampaignLevel::ByVolume);
        }

        // ── Geo-fingerprinted check ───────────────────────────────────────────
        if cfg.geo_grouping {
            if let Some(g) = geo {
                let country = g.country.as_str();
                let asn = g.asn_org.as_str();
                // Skip if GeoIP is unavailable for this IP.
                if country != "Unknown" || asn != "Unknown" {
                    let geo_key = (country.to_string(), asn.to_string());
                    let geo_distinct = self
                        .by_geo
                        .entry(geo_key)
                        .or_default()
                        .entry(category.clone())
                        .or_insert_with(CategoryWindow::new)
                        .push_and_count(ip, now, window);

                    if geo_distinct.len() >= cfg.geo_ips_threshold as usize {
                        tracing::warn!(
                            "Campaign (geo) detected for '{}' from {}/{}: {} distinct IPs",
                            category,
                            country,
                            asn,
                            geo_distinct.len()
                        );
                        return Some(CampaignLevel::ByGeo {
                            country: country.to_string(),
                            asn_org: asn.to_string(),
                        });
                    }
                }
            }
        }

        None
    }

    /// Return the number of distinct IPs currently tracked for `reason` category.
    /// Useful for metrics / debugging.
    #[allow(dead_code)]
    pub fn distinct_ip_count(&mut self, reason: &str, window_secs: u64) -> usize {
        let category = categorize_reason(reason).to_string();
        let now = Instant::now();
        let window = Duration::from_secs(window_secs.max(60));
        self.by_category
            .get_mut(&category)
            .map(|w| {
                w.push_and_count("__probe__", now, window)
                    .len()
                    .saturating_sub(1)
            })
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(threshold: u32) -> CampaignConfig {
        CampaignConfig {
            enabled: true,
            window_secs: 3600,
            distinct_ips_threshold: threshold,
            geo_grouping: false,
            geo_ips_threshold: 2,
        }
    }

    fn geo_cfg(vol_threshold: u32, geo_threshold: u32) -> CampaignConfig {
        CampaignConfig {
            enabled: true,
            window_secs: 3600,
            distinct_ips_threshold: vol_threshold,
            geo_grouping: true,
            geo_ips_threshold: geo_threshold,
        }
    }

    #[test]
    fn disabled_never_returns_campaign() {
        let mut tracker = LocalCampaignTracker::new();
        let c = CampaignConfig {
            enabled: false,
            ..Default::default()
        };
        for i in 0..100 {
            let ip = format!("1.2.3.{}", i);
            assert!(tracker.record(&ip, "Invalid SSH user", None, &c).is_none());
        }
    }

    #[test]
    fn volume_campaign_fires_at_threshold() {
        let mut tracker = LocalCampaignTracker::new();
        let c = cfg(3);
        // First two IPs should not trigger.
        assert!(tracker
            .record("1.1.1.1", "Invalid SSH user", None, &c)
            .is_none());
        assert!(tracker
            .record("2.2.2.2", "Invalid SSH user", None, &c)
            .is_none());
        // Third distinct IP crosses the threshold.
        let result = tracker.record("3.3.3.3", "Invalid SSH user", None, &c);
        assert_eq!(result, Some(CampaignLevel::ByVolume));
    }

    #[test]
    fn repeated_same_ip_does_not_trigger_volume_campaign() {
        let mut tracker = LocalCampaignTracker::new();
        let c = cfg(3);
        // Same IP repeated many times — only one distinct IP.
        for _ in 0..10 {
            let r = tracker.record("1.1.1.1", "Failed SSH password", None, &c);
            assert!(r.is_none(), "repeated same IP must not trigger campaign");
        }
    }

    #[test]
    fn different_categories_are_independent() {
        let mut tracker = LocalCampaignTracker::new();
        let c = cfg(3);
        tracker.record("1.1.1.1", "Invalid SSH user", None, &c);
        tracker.record("2.2.2.2", "Invalid SSH user", None, &c);
        // Different category — should not affect "Invalid SSH user" count.
        tracker.record("3.3.3.3", "Failed SSH password", None, &c);
        // Fourth distinct IP for "Invalid SSH user".
        let r = tracker.record("4.4.4.4", "Invalid SSH user", None, &c);
        assert_eq!(r, Some(CampaignLevel::ByVolume));
    }

    #[test]
    fn reason_annotations_are_normalized() {
        let mut tracker = LocalCampaignTracker::new();
        let c = cfg(3);
        // Annotated reasons like "(1/3)" and "(2/3)" map to the same category.
        tracker.record("1.1.1.1", "Invalid SSH user (1/3)", None, &c);
        tracker.record("2.2.2.2", "Invalid SSH user (2/3)", None, &c);
        let r = tracker.record("3.3.3.3", "Invalid SSH user (1/3)", None, &c);
        assert_eq!(r, Some(CampaignLevel::ByVolume));
    }

    #[test]
    fn geo_campaign_fires_within_same_country_asn() {
        let mut tracker = LocalCampaignTracker::new();
        let c = geo_cfg(100, 2); // volume threshold too high; geo threshold = 2

        let china = GeoTag {
            country: "China".to_string(),
            asn_org: "ChinaTelecom".to_string(),
        };
        tracker.record("1.1.1.1", "Invalid SSH user", Some(&china), &c);
        let r = tracker.record("2.2.2.2", "Invalid SSH user", Some(&china), &c);
        assert_eq!(
            r,
            Some(CampaignLevel::ByGeo {
                country: "China".to_string(),
                asn_org: "ChinaTelecom".to_string()
            })
        );
    }

    #[test]
    fn geo_campaign_does_not_fire_across_different_asn() {
        let mut tracker = LocalCampaignTracker::new();
        let c = geo_cfg(100, 2);

        let china_a = GeoTag {
            country: "China".to_string(),
            asn_org: "ChinaTelecom".to_string(),
        };
        let china_b = GeoTag {
            country: "China".to_string(),
            asn_org: "Alibaba".to_string(),
        };
        tracker.record("1.1.1.1", "Invalid SSH user", Some(&china_a), &c);
        let r = tracker.record("2.2.2.2", "Invalid SSH user", Some(&china_b), &c);
        assert!(r.is_none(), "Different ASN should not trigger geo campaign");
    }
}
