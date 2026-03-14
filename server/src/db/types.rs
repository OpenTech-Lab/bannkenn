use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRow {
    pub id: i64,
    pub ip: String,
    pub reason: String,
    pub action: String,
    pub source: String,
    pub country: Option<String>,
    pub asn_org: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryRow {
    pub id: i64,
    pub ip: String,
    pub reason: String,
    pub level: String,
    pub source: String,
    pub log_path: Option<String>,
    pub country: Option<String>,
    pub asn_org: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BehaviorFileOpsRow {
    pub created: u32,
    pub modified: u32,
    pub renamed: u32,
    pub deleted: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BehaviorEventRow {
    pub id: i64,
    pub agent_name: String,
    pub source: String,
    pub watched_root: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
    pub correlation_hits: u32,
    pub file_ops: BehaviorFileOpsRow,
    pub touched_paths: Vec<String>,
    pub protected_paths_touched: Vec<String>,
    pub bytes_written: u64,
    pub io_rate_bytes_per_sec: u64,
    pub score: u32,
    pub reasons: Vec<String>,
    pub level: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainmentOutcomeRow {
    pub enforcer: String,
    pub applied: bool,
    pub dry_run: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainmentEventRow {
    pub id: i64,
    pub agent_name: String,
    pub state: String,
    pub previous_state: Option<String>,
    pub reason: String,
    pub watched_root: String,
    pub pid: Option<u32>,
    pub score: u32,
    pub actions: Vec<String>,
    pub outcomes: Vec<ContainmentOutcomeRow>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainmentStatusRow {
    pub agent_name: String,
    pub state: String,
    pub previous_state: Option<String>,
    pub reason: String,
    pub watched_root: String,
    pub pid: Option<u32>,
    pub score: u32,
    pub actions: Vec<String>,
    pub outcomes: Vec<ContainmentOutcomeRow>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainmentActionRow {
    pub id: i64,
    pub agent_name: String,
    pub command_kind: String,
    pub reason: String,
    pub watched_root: Option<String>,
    pub pid: Option<u32>,
    pub requested_by: String,
    pub status: String,
    pub resulting_state: Option<String>,
    pub result_message: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub executed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IncidentRow {
    pub id: i64,
    pub incident_key: String,
    pub status: String,
    pub severity: String,
    pub title: String,
    pub summary: String,
    pub primary_reason: String,
    pub latest_state: Option<String>,
    pub latest_score: u32,
    pub event_count: u32,
    pub correlated_agent_count: u32,
    pub affected_agents: Vec<String>,
    pub affected_roots: Vec<String>,
    pub cross_agent: bool,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub alert_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IncidentTimelineRow {
    pub id: i64,
    pub source_type: String,
    pub source_event_id: Option<i64>,
    pub agent_name: String,
    pub watched_root: String,
    pub severity: String,
    pub message: String,
    pub payload: Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IncidentDetailRow {
    pub incident: IncidentRow,
    pub timeline: Vec<IncidentTimelineRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdminAlertRow {
    pub id: i64,
    pub alert_type: String,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub agent_name: Option<String>,
    pub incident_id: Option<i64>,
    pub metadata: Value,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct NewBehaviorEvent {
    pub agent_name: String,
    pub source: String,
    pub watched_root: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
    pub correlation_hits: u32,
    pub file_ops: BehaviorFileOpsRow,
    pub touched_paths: Vec<String>,
    pub protected_paths_touched: Vec<String>,
    pub bytes_written: u64,
    pub io_rate_bytes_per_sec: u64,
    pub score: u32,
    pub reasons: Vec<String>,
    pub level: String,
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewContainmentEvent {
    pub agent_name: String,
    pub state: String,
    pub previous_state: Option<String>,
    pub reason: String,
    pub watched_root: String,
    pub pid: Option<u32>,
    pub score: u32,
    pub actions: Vec<String>,
    pub outcomes: Vec<ContainmentOutcomeRow>,
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewContainmentAction {
    pub agent_name: String,
    pub command_kind: String,
    pub reason: String,
    pub watched_root: Option<String>,
    pub pid: Option<u32>,
    pub requested_by: String,
}

#[derive(Debug, Clone)]
pub struct BehaviorIngestResult {
    pub id: i64,
    pub incident_id: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRow {
    pub id: i64,
    pub name: String,
    pub token_hash: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatusRow {
    pub id: i64,
    pub name: String,
    pub uuid: Option<String>,
    pub nickname: Option<String>,
    pub created_at: String,
    pub last_seen_at: Option<String>,
    pub butterfly_shield_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshLoginRow {
    pub id: i64,
    pub ip: String,
    pub username: String,
    pub agent_name: String,
    pub country: Option<String>,
    pub asn_org: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityIpRow {
    pub ip: String,
    pub source: String,
    pub source_label: String,
    pub kind: String,
    pub sightings: i64,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityFeedRow {
    pub source: String,
    pub source_label: String,
    pub kind: String,
    pub ip_count: i64,
    pub first_seen_at: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityFeedIpRow {
    pub ip: String,
    pub reason: String,
    pub sightings: i64,
    pub first_seen_at: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpLookupEventRow {
    pub id: i64,
    pub source: String,
    pub source_label: String,
    pub agent_id: Option<i64>,
    pub reason: String,
    pub level: String,
    pub log_path: Option<String>,
    pub country: Option<String>,
    pub asn_org: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpLookupDecisionRow {
    pub id: i64,
    pub source: String,
    pub source_label: String,
    pub agent_id: Option<i64>,
    pub reason: String,
    pub action: String,
    pub country: Option<String>,
    pub asn_org: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpLookupMachineSummaryRow {
    pub agent_id: Option<i64>,
    pub source: String,
    pub source_label: String,
    pub event_count: i64,
    pub alert_count: i64,
    pub listed_count: i64,
    pub block_count: i64,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub last_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpLookupCommunityMatchRow {
    pub source: String,
    pub matched_entry: String,
    pub reason: String,
    pub sightings: i64,
    pub first_seen_at: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpLookupResponse {
    pub ip: String,
    pub country: Option<String>,
    pub asn_org: Option<String>,
    pub local_history: Vec<IpLookupEventRow>,
    pub decision_history: Vec<IpLookupDecisionRow>,
    pub machine_summaries: Vec<IpLookupMachineSummaryRow>,
    pub community_matches: Vec<IpLookupCommunityMatchRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SharedRiskCategoryRow {
    pub category: String,
    pub distinct_ips: u32,
    pub distinct_agents: u32,
    pub event_count: u32,
    pub threshold_multiplier: f64,
    pub force_threshold: Option<u32>,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhitelistEntryRow {
    pub id: i64,
    pub ip: String,
    pub note: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SharedRiskProfileRow {
    pub generated_at: String,
    pub window_secs: i64,
    pub global_risk_score: f64,
    pub global_threshold_multiplier: f64,
    pub categories: Vec<SharedRiskCategoryRow>,
}
