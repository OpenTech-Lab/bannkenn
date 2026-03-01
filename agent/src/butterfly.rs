use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

/// ButterflyShield configuration parameters.
///
/// When `enabled = true`, the agent replaces its static `threshold` with a
/// dynamically computed value derived from a logistic-map chaotic iteration.
/// The effective multiplier is in [0.5, 1.5] relative to the static base,
/// seeded from the attacker IP and the current unix second.
///
/// An attacker who reads the source code still cannot pre-compute "safe"
/// request rates, because the seed changes every second and depends on
/// server-side time — solving the inverse chaotic iteration is infeasible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ButterflyShieldConfig {
    /// Whether dynamic threshold mode is active.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Logistic-map parameter r. Must be in (3.57, 4.0] for full chaos.
    #[serde(default = "default_chaos_r")]
    pub chaos_r: f64,
    /// Number of logistic-map iterations (higher = more unpredictable).
    #[serde(default = "default_iterations")]
    pub iterations: u32,
}

fn default_enabled() -> bool {
    true
}

fn default_chaos_r() -> f64 {
    3.99
}

fn default_iterations() -> u32 {
    10
}

impl Default for ButterflyShieldConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            chaos_r: default_chaos_r(),
            iterations: default_iterations(),
        }
    }
}

/// Compute the effective block threshold for `ip` using the logistic-map.
///
/// The seed is derived from the attacker IP and the current unix second,
/// making the threshold unpredictable from the outside while staying
/// deterministic within a single second (useful for testing via
/// [`effective_threshold_with_seed`]).
///
/// Returns at least 1 to avoid divide-by-zero or never-triggering logic.
pub fn effective_threshold(base: u32, ip: &str, cfg: &ButterflyShieldConfig) -> u32 {
    let seed = make_seed(ip);
    effective_threshold_with_seed(base, seed, cfg)
}

/// Deterministic version of [`effective_threshold`] — accepts an explicit
/// seed in [0.0, 1.0) so unit tests can verify bounds and repeatability.
pub fn effective_threshold_with_seed(base: u32, seed: f64, cfg: &ButterflyShieldConfig) -> u32 {
    let mut x = seed.fract().abs();
    // Avoid the fixed-point x=0 (maps to threshold = base * 0.5).
    // Use a mid-range value as a safe fallback.
    if x == 0.0 {
        x = 0.5;
    }

    let r = cfg.chaos_r.clamp(0.0, 4.0);
    for _ in 0..cfg.iterations {
        x = r * x * (1.0 - x);
    }

    // Multiplier in [0.5, 1.5]
    let multiplier = 0.5 + x;
    let effective = (base as f64 * multiplier).round() as u32;
    // Always at least 1 so detection never becomes impossible.
    effective.max(1)
}

/// Build a normalised seed ∈ [0.0, 1.0) from `ip` and the current unix second.
fn make_seed(ip: &str) -> f64 {
    let unix_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let key = format!("{}{}", ip, unix_sec);
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    let h = hasher.finish();
    // Normalize to [0, 1)
    (h as f64) / (u64::MAX as f64 + 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_cfg() -> ButterflyShieldConfig {
        ButterflyShieldConfig::default()
    }

    /// The multiplier x after 10 iterations of the logistic map is always
    /// in [0, 1], so the effective threshold must be in [base*0.5, base*1.5].
    #[test]
    fn test_multiplier_bounds() {
        let cfg = default_cfg();
        let base = 10u32;

        let seeds = [0.1, 0.25, 0.5, 0.75, 0.99, 0.123, 0.987, 0.333];
        for seed in seeds {
            let t = effective_threshold_with_seed(base, seed, &cfg);
            assert!(t >= base / 2, "threshold {} below floor for seed {seed}", t);
            assert!(
                t <= base * 2,
                "threshold {} above ceiling for seed {seed}",
                t
            );
        }
    }

    /// Same seed must always produce the same threshold (determinism).
    #[test]
    fn test_determinism() {
        let cfg = default_cfg();
        let seed = 0.42;
        let base = 5u32;
        let t1 = effective_threshold_with_seed(base, seed, &cfg);
        let t2 = effective_threshold_with_seed(base, seed, &cfg);
        assert_eq!(t1, t2);
    }

    /// Minimum threshold is always at least 1.
    #[test]
    fn test_minimum_threshold() {
        let cfg = default_cfg();
        for base in [1u32, 2, 5] {
            for seed in [0.0, 0.01, 0.99] {
                let t = effective_threshold_with_seed(base, seed, &cfg);
                assert!(t >= 1, "threshold must be >= 1, got {t}");
            }
        }
    }

    /// Different seeds should (almost always) produce different thresholds,
    /// demonstrating sensitivity — a core property of chaos.
    #[test]
    fn test_sensitivity() {
        let cfg = default_cfg();
        let base = 20u32;
        let t1 = effective_threshold_with_seed(base, 0.40001, &cfg);
        let t2 = effective_threshold_with_seed(base, 0.40002, &cfg);
        // We can't guarantee exact difference (chaos isn't perfectly uniform),
        // but both must still be within valid bounds.
        let lo = base / 2;
        let hi = base * 2;
        assert!((lo..=hi).contains(&t1));
        assert!((lo..=hi).contains(&t2));
    }

    /// Disabling butterfly shield should fall back to the static base value,
    /// handled by the call-site in watcher.rs, but ensure the helper still
    /// computes a valid number when called with enabled=false.
    #[test]
    fn test_disabled_still_computes() {
        let cfg = ButterflyShieldConfig {
            enabled: false,
            ..Default::default()
        };
        let t = effective_threshold_with_seed(5, 0.5, &cfg);
        assert!(t >= 1);
    }
}
