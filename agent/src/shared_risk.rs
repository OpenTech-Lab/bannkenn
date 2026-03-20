use crate::burst::categorize_reason;
use crate::ebpf::events::{ProcessInfo, ProcessTrustClass};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SharedRiskCategory {
    pub category: String,
    pub distinct_ips: u32,
    pub distinct_agents: u32,
    pub event_count: u32,
    pub threshold_multiplier: f64,
    pub force_threshold: Option<u32>,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedProcessProfile {
    pub identity: String,
    pub exe_path: String,
    #[serde(default)]
    pub service_unit: Option<String>,
    #[serde(default)]
    pub package_name: Option<String>,
    #[serde(default)]
    pub container_image: Option<String>,
    pub trust_class: String,
    pub distinct_agents: u32,
    pub event_count: u32,
    pub highest_level: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SharedRiskSnapshot {
    pub generated_at: String,
    pub window_secs: i64,
    pub global_risk_score: f64,
    pub global_threshold_multiplier: f64,
    pub categories: Vec<SharedRiskCategory>,
    #[serde(default)]
    pub process_profiles: Vec<SharedProcessProfile>,
}

impl Default for SharedRiskSnapshot {
    fn default() -> Self {
        Self {
            generated_at: String::new(),
            window_secs: 600,
            global_risk_score: 0.0,
            global_threshold_multiplier: 1.0,
            categories: Vec::new(),
            process_profiles: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharedRiskDecision {
    pub effective_threshold: Option<u32>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedProcessTrustMatch {
    pub trust_class: ProcessTrustClass,
    pub label: String,
}

impl SharedRiskSnapshot {
    pub fn apply(&self, base_threshold: u32, reason: &str) -> SharedRiskDecision {
        let mut effective = base_threshold;
        let mut applied = false;
        let mut tags = Vec::new();

        if self.global_threshold_multiplier < 0.999 {
            let global_threshold =
                scaled_threshold(base_threshold, self.global_threshold_multiplier);
            if global_threshold <= effective {
                effective = global_threshold;
                applied = true;
                tags.push("shared:global".to_string());
            }
        }

        let category = categorize_reason(reason);
        if let Some(shared_category) = self
            .categories
            .iter()
            .find(|item| item.category == category)
        {
            let category_threshold = shared_category.force_threshold.unwrap_or_else(|| {
                scaled_threshold(base_threshold, shared_category.threshold_multiplier)
            });

            if category_threshold <= effective {
                effective = category_threshold;
                applied = true;
                tags.push(shared_category.label.clone());
            }
        }

        if applied {
            tags.sort();
            tags.dedup();
            SharedRiskDecision {
                effective_threshold: Some(effective.max(1)),
                tags,
            }
        } else {
            SharedRiskDecision::default()
        }
    }

    pub fn shared_process_trust(&self, process: &ProcessInfo) -> Option<SharedProcessTrustMatch> {
        let exe_path = normalize_identity_value(&process.exe_path)?;
        let service_unit = normalize_optional_identity_value(process.service_unit.as_deref());
        let package_name = normalize_optional_identity_value(process.package_name.as_deref());
        let container_image = normalize_optional_identity_value(process.container_image.as_deref());
        if service_unit == "-" && package_name == "-" && container_image == "-" {
            return None;
        }

        self.process_profiles.iter().find_map(|profile| {
            let identity = profile_identity(profile)?;
            if identity.exe_path != exe_path {
                return None;
            }
            if identity.service_unit != "-"
                && service_unit != "-"
                && identity.service_unit != service_unit
            {
                return None;
            }
            if identity.package_name != "-"
                && package_name != "-"
                && identity.package_name != package_name
            {
                return None;
            }
            if identity.container_image != "-"
                && container_image != "-"
                && identity.container_image != container_image
            {
                return None;
            }

            let matched_discriminator = (identity.service_unit != "-"
                && identity.service_unit == service_unit)
                || (identity.package_name != "-" && identity.package_name == package_name)
                || (identity.container_image != "-" && identity.container_image == container_image);
            if !matched_discriminator {
                return None;
            }

            Some(SharedProcessTrustMatch {
                trust_class: parse_trust_class(&profile.trust_class)?,
                label: profile.label.clone(),
            })
        })
    }
}

fn scaled_threshold(base: u32, multiplier: f64) -> u32 {
    ((base as f64) * multiplier).round().max(1.0) as u32
}

fn parse_trust_class(value: &str) -> Option<ProcessTrustClass> {
    match value.trim() {
        "trusted_system_process" => Some(ProcessTrustClass::TrustedSystem),
        "trusted_package_managed_process" => Some(ProcessTrustClass::TrustedPackageManaged),
        "allowed_local_process" => Some(ProcessTrustClass::AllowedLocal),
        "unknown_process" => Some(ProcessTrustClass::Unknown),
        "suspicious_process" => Some(ProcessTrustClass::Suspicious),
        _ => None,
    }
}

fn profile_identity(profile: &SharedProcessProfile) -> Option<ProfileIdentity> {
    if let Some(identity) = normalize_identity_value(&profile.identity) {
        let mut parts = identity.split('|');
        let exe_path = parts.next()?.to_string();
        let service_unit = parts.next().unwrap_or("-").to_string();
        let package_name = parts.next().unwrap_or("-").to_string();
        let container_image = parts.next().unwrap_or("-").to_string();
        return Some(ProfileIdentity {
            exe_path,
            service_unit,
            package_name,
            container_image,
        });
    }

    Some(ProfileIdentity {
        exe_path: normalize_identity_value(&profile.exe_path)?,
        service_unit: normalize_optional_identity_value(profile.service_unit.as_deref()),
        package_name: normalize_optional_identity_value(profile.package_name.as_deref()),
        container_image: normalize_optional_identity_value(profile.container_image.as_deref()),
    })
}

fn normalize_identity_value(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    (!normalized.is_empty()).then_some(normalized)
}

fn normalize_optional_identity_value(value: Option<&str>) -> String {
    value
        .and_then(normalize_identity_value)
        .unwrap_or_else(|| "-".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProfileIdentity {
    exe_path: String,
    service_unit: String,
    package_name: String,
    container_image: String,
}

#[cfg(test)]
#[path = "../tests/unit/shared_risk_tests.rs"]
mod tests;
