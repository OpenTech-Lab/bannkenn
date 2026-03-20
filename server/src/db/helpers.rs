use super::*;

pub(super) const INCIDENT_CORRELATION_WINDOW_MINUTES: i64 = 30;

pub(super) fn normalize_reason_category(reason: &str) -> &str {
    if let Some(idx) = reason.rfind(" (") {
        let suffix = &reason[idx + 2..];
        if suffix.ends_with(')') {
            return &reason[..idx];
        }
    }
    reason
}

pub(super) fn telemetry_level_weight(level: &str) -> f64 {
    match level {
        "block" => 3.0,
        "listed" => 2.0,
        _ => 1.0,
    }
}

pub(super) fn normalize_event_timestamp(timestamp: Option<&str>) -> String {
    match timestamp {
        Some(value) => match DateTime::parse_from_rfc3339(value) {
            Ok(parsed) => parsed.with_timezone(&Utc).to_rfc3339(),
            Err(err) => {
                tracing::warn!(
                    "invalid event timestamp '{}', falling back to receipt time: {}",
                    value,
                    err
                );
                Utc::now().to_rfc3339()
            }
        },
        None => Utc::now().to_rfc3339(),
    }
}

pub(super) fn normalize_lookup_geo(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub(super) fn encode_json<T: Serialize>(value: &T) -> anyhow::Result<String> {
    Ok(serde_json::to_string(value)?)
}

pub(super) fn decode_json<T: DeserializeOwned>(value: &str, field: &str) -> anyhow::Result<T> {
    serde_json::from_str(value)
        .map_err(|err| anyhow::anyhow!("failed to decode {} JSON: {}", field, err))
}

pub(super) fn to_i64<T>(value: T, field: &str) -> anyhow::Result<i64>
where
    T: TryInto<i64>,
    T::Error: std::fmt::Display,
{
    value
        .try_into()
        .map_err(|err| anyhow::anyhow!("{} out of range: {}", field, err))
}

pub(super) fn from_i64_u32(value: i64, field: &str) -> anyhow::Result<u32> {
    u32::try_from(value).map_err(|_| anyhow::anyhow!("{} out of range: {}", field, value))
}

pub(super) fn from_i64_u64(value: i64, field: &str) -> anyhow::Result<u64> {
    u64::try_from(value).map_err(|_| anyhow::anyhow!("{} out of range: {}", field, value))
}

pub(super) fn from_i64_opt_u32(value: Option<i64>, field: &str) -> anyhow::Result<Option<u32>> {
    value.map(|value| from_i64_u32(value, field)).transpose()
}

pub(super) fn source_label(source: &str, agent_display_name: Option<String>) -> String {
    agent_display_name
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| match source {
            "campaign" => "Campaign auto-block".to_string(),
            _ => source.to_string(),
        })
}

pub(super) fn source_kind(source: &str, agent_id: Option<i64>) -> &'static str {
    if agent_id.is_some() {
        "agent"
    } else if source == "campaign" {
        "campaign"
    } else {
        "community"
    }
}

pub(super) fn normalize_behavior_reason_category(reason: &str) -> String {
    let normalized = normalize_reason_category(reason).trim().to_lowercase();
    if let Some((prefix, suffix)) = normalized.rsplit_once(" x") {
        if !prefix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit()) {
            return prefix.to_string();
        }
    }
    normalized
}

pub(super) fn normalize_behavior_reasons_key(reasons: &[String]) -> String {
    let mut reasons = reasons
        .iter()
        .map(|reason| normalize_behavior_reason_category(reason))
        .filter(|reason| !reason.is_empty())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if reasons.is_empty() {
        "observed".to_string()
    } else {
        reasons.sort();
        reasons.join("|")
    }
}

pub(super) fn primary_behavior_reason(reasons: &[String]) -> String {
    reasons
        .first()
        .map(|reason| normalize_behavior_reason_category(reason))
        .filter(|reason| !reason.is_empty())
        .unwrap_or_else(|| "behavior activity".to_string())
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

pub(super) fn max_severity(current: &str, candidate: &str) -> &'static str {
    if severity_rank(candidate) > severity_rank(current) {
        match candidate {
            "critical" => "critical",
            "high" => "high",
            "medium" => "medium",
            _ => "low",
        }
    } else {
        match current {
            "critical" => "critical",
            "high" => "high",
            "medium" => "medium",
            _ => "low",
        }
    }
}

pub(super) fn behavior_level_to_severity(level: &str) -> &'static str {
    match level {
        "containment_candidate" | "fuse_candidate" => "critical",
        "high_risk" | "throttle_candidate" => "high",
        "suspicious" => "medium",
        _ => "low",
    }
}

pub(super) fn containment_state_to_severity(state: &str) -> &'static str {
    match state {
        "fuse" => "critical",
        "throttle" => "high",
        "suspicious" => "medium",
        _ => "low",
    }
}

pub(super) fn incident_cutoff(created_at: &str) -> String {
    DateTime::parse_from_rfc3339(created_at)
        .map(|dt| {
            dt.with_timezone(&Utc) - ChronoDuration::minutes(INCIDENT_CORRELATION_WINDOW_MINUTES)
        })
        .unwrap_or_else(|_| {
            Utc::now() - ChronoDuration::minutes(INCIDENT_CORRELATION_WINDOW_MINUTES)
        })
        .to_rfc3339()
}

pub(super) fn window_cutoff(window_secs: i64) -> String {
    let clamped_window = window_secs.max(1);
    (Utc::now() - ChronoDuration::seconds(clamped_window)).to_rfc3339()
}

pub(super) fn build_behavior_incident_key(event: &NewBehaviorEvent) -> String {
    format!(
        "behavior:{}:{}",
        event.watched_root.to_lowercase(),
        normalize_behavior_reasons_key(&event.reasons)
    )
}

pub(super) fn build_behavior_incident_title(primary_reason: &str, cross_agent: bool) -> String {
    if cross_agent {
        format!("Cross-agent behavior incident: {}", primary_reason)
    } else {
        format!("Behavior incident: {}", primary_reason)
    }
}

pub(super) fn build_behavior_incident_summary(
    primary_reason: &str,
    agent_count: usize,
    roots: &[String],
    watched_root: &str,
) -> String {
    if agent_count > 1 {
        format!(
            "{} correlated across {} agents on {}",
            primary_reason,
            agent_count,
            roots
                .first()
                .cloned()
                .unwrap_or_else(|| watched_root.to_string())
        )
    } else {
        format!("{} observed on {}", primary_reason, watched_root)
    }
}

pub(super) fn build_containment_alert_title(agent_name: &str, state: &str) -> String {
    match state {
        "normal" => format!("Containment cleared on {}", agent_name),
        _ => format!("Containment transitioned to {} on {}", state, agent_name),
    }
}

pub(super) fn build_containment_alert_message(event: &NewContainmentEvent) -> String {
    format!(
        "{} on {} for {} ({})",
        event.state, event.agent_name, event.watched_root, event.reason
    )
}

pub(super) fn build_cross_agent_alert_title(primary_reason: &str) -> String {
    format!("Cross-agent incident detected: {}", primary_reason)
}

pub(super) fn build_cross_agent_alert_message(
    primary_reason: &str,
    affected_agents: &[String],
    watched_root: &str,
) -> String {
    format!(
        "{} correlated across {} agents on {}",
        primary_reason,
        affected_agents.len(),
        watched_root
    )
}

pub(super) fn build_containment_incident_key(event: &NewContainmentEvent) -> String {
    format!(
        "containment:{}:{}",
        event.agent_name.to_lowercase(),
        event.watched_root.to_lowercase()
    )
}

pub(super) fn build_containment_incident_title(agent_name: &str, state: &str) -> String {
    match state {
        "normal" => format!("Containment cleared on {}", agent_name),
        _ => format!("Containment incident: {} on {}", state, agent_name),
    }
}

pub(super) fn build_containment_incident_summary(event: &NewContainmentEvent) -> String {
    format!(
        "{} on {} for {} ({})",
        event.state, event.agent_name, event.watched_root, event.reason
    )
}

pub(super) fn push_unique_sorted(values: &mut Vec<String>, candidate: &str) {
    if values.iter().all(|existing| existing != candidate) {
        values.push(candidate.to_string());
        values.sort();
    }
}
