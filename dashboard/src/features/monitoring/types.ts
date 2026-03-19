export type HealthStatus = {
  status: string;
};

export type AgentStatus = {
  id: number;
  name: string;
  uuid?: string | null;
  nickname?: string | null;
  created_at: string;
  last_seen_at: string | null;
  status: 'online' | 'offline' | 'unknown';
  butterfly_shield_enabled?: boolean | null;
  containment_sensor?: string | null;
};

export type BehaviorFileOps = {
  created: number;
  modified: number;
  renamed: number;
  deleted: number;
};

export type BehaviorParentChainEntry = {
  pid: number;
  process_name?: string | null;
  exe_path?: string | null;
  command_line?: string | null;
};

export type BehaviorEvent = {
  id: number;
  agent_name: string;
  source: string;
  watched_root: string;
  pid?: number | null;
  parent_pid?: number | null;
  uid?: number | null;
  gid?: number | null;
  service_unit?: string | null;
  first_seen_at?: string | null;
  trust_class?: string | null;
  trust_policy_name?: string | null;
  maintenance_activity?: string | null;
  package_name?: string | null;
  package_manager?: string | null;
  parent_chain: BehaviorParentChainEntry[];
  process_name?: string | null;
  exe_path?: string | null;
  command_line?: string | null;
  parent_process_name?: string | null;
  parent_command_line?: string | null;
  container_runtime?: string | null;
  container_id?: string | null;
  correlation_hits: number;
  file_ops: BehaviorFileOps;
  touched_paths: string[];
  protected_paths_touched: string[];
  bytes_written: number;
  io_rate_bytes_per_sec: number;
  score: number;
  reasons: string[];
  level: string;
  created_at: string;
};

export type ContainmentOutcome = {
  enforcer: string;
  applied: boolean;
  dry_run: boolean;
  detail: string;
};

export type ContainmentStatus = {
  agent_name: string;
  state: string;
  previous_state?: string | null;
  reason: string;
  watched_root: string;
  pid?: number | null;
  score: number;
  actions: string[];
  outcomes: ContainmentOutcome[];
  updated_at: string;
};

export type ContainmentEvent = {
  id: number;
  agent_name: string;
  state: string;
  previous_state?: string | null;
  reason: string;
  watched_root: string;
  pid?: number | null;
  score: number;
  actions: string[];
  outcomes: ContainmentOutcome[];
  created_at: string;
};

export type ContainmentAction = {
  id: number;
  agent_name: string;
  command_kind: string;
  reason: string;
  watched_root?: string | null;
  pid?: number | null;
  requested_by: string;
  status: string;
  resulting_state?: string | null;
  result_message?: string | null;
  created_at: string;
  updated_at: string;
  executed_at?: string | null;
};

export type Incident = {
  id: number;
  incident_key: string;
  status: string;
  severity: string;
  title: string;
  summary: string;
  primary_reason: string;
  latest_state?: string | null;
  latest_score: number;
  event_count: number;
  correlated_agent_count: number;
  affected_agents: string[];
  affected_roots: string[];
  cross_agent: boolean;
  first_seen_at: string;
  last_seen_at: string;
  alert_count: number;
};

export type IncidentTimelineEntry = {
  id: number;
  source_type: string;
  source_event_id?: number | null;
  agent_name: string;
  watched_root: string;
  severity: string;
  message: string;
  payload: unknown;
  created_at: string;
};

export type IncidentDetail = {
  incident: Incident;
  timeline: IncidentTimelineEntry[];
};

export type AdminAlert = {
  id: number;
  alert_type: string;
  severity: string;
  title: string;
  message: string;
  agent_name?: string | null;
  incident_id?: number | null;
  metadata: unknown;
  created_at: string;
};

export type TimelineSeverity = 'low' | 'medium' | 'high' | 'critical';

export type FleetAgentSummary = {
  agent: AgentStatus;
  containment?: ContainmentStatus;
  incidentCount: number;
  activeIncident?: Incident;
  alertCount: number;
  heat: number;
};

export type ActivityEntry = {
  id: string;
  kind: 'behavior' | 'containment' | 'alert';
  severity: TimelineSeverity;
  title: string;
  description: string;
  agentName?: string;
  createdAt: string;
  href?: string;
  tags: string[];
};

export type DashboardSnapshot = {
  health: HealthStatus;
  agents: AgentStatus[];
  containmentStatuses: ContainmentStatus[];
  containmentEvents: ContainmentEvent[];
  incidents: Incident[];
  alerts: AdminAlert[];
  behaviorEvents: BehaviorEvent[];
};

export type IncidentDetailSnapshot = {
  detail: IncidentDetail;
  agents: AgentStatus[];
};

export type TelemetryEvent = {
  id: number;
  ip: string;
  reason: string;
  level: string;
  source: string;
  log_path?: string | null;
  country?: string | null;
  asn_org?: string | null;
  created_at: string;
};

export type Decision = {
  id: number;
  ip: string;
  reason: string;
  action: string;
  source: string;
  country?: string | null;
  asn_org?: string | null;
  created_at: string;
  expires_at?: string | null;
};

export type PaginatedResult<T> = {
  items: T[];
  limit: number;
  offset: number;
  has_more: boolean;
};

export type AgentDetailSnapshot = {
  agent: AgentStatus;
  behaviorEvents: BehaviorEvent[];
  containmentEvents: ContainmentEvent[];
  containmentActions: ContainmentAction[];
  relatedIncidents: Incident[];
  telemetryEvents: TelemetryEvent[];
  decisions: Decision[];
};

export type ContainmentActionRequest = {
  command_kind: 'trigger_fuse' | 'release_fuse';
  reason: string;
  watched_root?: string | null;
  pid?: number | null;
};
