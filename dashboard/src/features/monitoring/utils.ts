import {
  ActivityEntry,
  AdminAlert,
  AgentStatus,
  BehaviorEvent,
  ContainmentEvent,
  ContainmentStatus,
  DashboardSnapshot,
  FleetAgentSummary,
  TimelineSeverity,
} from '@/src/features/monitoring/types';

export function agentLabel(agent: Pick<AgentStatus, 'name' | 'nickname'>) {
  return agent.nickname?.trim() || agent.name;
}

export function formatTimestamp(value: string | null | undefined) {
  if (!value) {
    return 'Never';
  }

  const timestamp = new Date(value);
  if (Number.isNaN(timestamp.getTime())) {
    return value;
  }

  return timestamp.toLocaleString();
}

export function formatRelativeTime(value: string | null | undefined) {
  if (!value) {
    return 'never';
  }

  const timestamp = new Date(value);
  if (Number.isNaN(timestamp.getTime())) {
    return value;
  }

  const diffSeconds = Math.round((timestamp.getTime() - Date.now()) / 1000);
  const abs = Math.abs(diffSeconds);

  if (abs < 60) {
    return diffSeconds >= 0 ? 'in a few seconds' : 'just now';
  }

  const minutes = Math.round(abs / 60);
  if (minutes < 60) {
    return diffSeconds >= 0 ? `in ${minutes}m` : `${minutes}m ago`;
  }

  const hours = Math.round(minutes / 60);
  if (hours < 48) {
    return diffSeconds >= 0 ? `in ${hours}h` : `${hours}h ago`;
  }

  const days = Math.round(hours / 24);
  return diffSeconds >= 0 ? `in ${days}d` : `${days}d ago`;
}

export function formatStateLabel(state: string) {
  return state.replace(/_/g, ' ');
}

export function isActiveContainmentState(state: string) {
  return state === 'throttle' || state === 'fuse';
}

export function containmentStateSeverity(state: string): TimelineSeverity {
  switch (state) {
    case 'fuse':
      return 'critical';
    case 'throttle':
      return 'high';
    case 'suspicious':
      return 'medium';
    default:
      return 'low';
  }
}

export function behaviorLevelSeverity(level: string): TimelineSeverity {
  switch (level) {
    case 'fuse_candidate':
      return 'critical';
    case 'throttle_candidate':
      return 'high';
    case 'suspicious':
      return 'medium';
    default:
      return 'low';
  }
}

function stateRank(state: string | undefined) {
  switch (state) {
    case 'fuse':
      return 4;
    case 'throttle':
      return 3;
    case 'suspicious':
      return 2;
    case 'normal':
    default:
      return 1;
  }
}

function alertMatchesAgent(alert: AdminAlert, incidentsForAgent: Set<number>, agentName: string) {
  return (
    alert.agent_name === agentName ||
    (alert.incident_id !== null &&
      alert.incident_id !== undefined &&
      incidentsForAgent.has(alert.incident_id))
  );
}

export function buildFleetAgentSummaries(snapshot: DashboardSnapshot): FleetAgentSummary[] {
  const containmentByAgent = new Map(
    snapshot.containmentStatuses.map((entry) => [entry.agent_name, entry] as const)
  );

  return snapshot.agents
    .map((agent) => {
      const containment = containmentByAgent.get(agent.name);
      const incidents = snapshot.incidents.filter((incident) =>
        incident.affected_agents.includes(agent.name)
      );
      const incidentIds = new Set(incidents.map((incident) => incident.id));
      const alerts = snapshot.alerts.filter((alert) =>
        alertMatchesAgent(alert, incidentIds, agent.name)
      );

      const baseHeat = containment ? stateRank(containment.state) * 18 : 0;
      const incidentHeat = Math.min(incidents.length * 12, 36);
      const alertHeat = Math.min(alerts.length * 8, 24);
      const scoreHeat = containment ? Math.min(Math.round(containment.score / 2), 22) : 0;

      return {
        agent,
        containment,
        incidentCount: incidents.length,
        activeIncident: incidents[0],
        alertCount: alerts.length,
        heat: Math.min(100, baseHeat + incidentHeat + alertHeat + scoreHeat),
      };
    })
    .sort((left, right) => {
      return (
        right.heat - left.heat ||
        stateRank(right.containment?.state) - stateRank(left.containment?.state) ||
        agentLabel(left.agent).localeCompare(agentLabel(right.agent))
      );
    });
}

function describeBehaviorEvent(event: BehaviorEvent) {
  const reasons = event.reasons.length > 0 ? event.reasons.join(', ') : event.level;
  const process = event.process_name ?? event.exe_path ?? 'unknown process';
  return `${process} on ${event.watched_root} scored ${event.score}: ${reasons}`;
}

function describeContainmentEvent(event: ContainmentEvent) {
  return `${formatStateLabel(event.state)} on ${event.watched_root}: ${event.reason}`;
}

export function buildActivityEntries(
  behaviorEvents: BehaviorEvent[],
  containmentEvents: ContainmentEvent[],
  alerts: AdminAlert[],
  agents: AgentStatus[]
) {
  const agentIdByName = new Map(agents.map((agent) => [agent.name, agent.id] as const));
  const entries: ActivityEntry[] = [];

  for (const event of behaviorEvents) {
    const agentId = agentIdByName.get(event.agent_name);
    entries.push({
      id: `behavior-${event.id}`,
      kind: 'behavior',
      severity: behaviorLevelSeverity(event.level),
      title: `Behavior spike on ${event.agent_name}`,
      description: describeBehaviorEvent(event),
      agentName: event.agent_name,
      createdAt: event.created_at,
      href: agentId ? `/behavior/agents/${agentId}` : undefined,
      tags: [event.level, `${event.score} score`, event.watched_root],
    });
  }

  for (const event of containmentEvents) {
    const agentId = agentIdByName.get(event.agent_name);
    entries.push({
      id: `containment-${event.id}`,
      kind: 'containment',
      severity: containmentStateSeverity(event.state),
      title: `Containment moved to ${formatStateLabel(event.state)}`,
      description: describeContainmentEvent(event),
      agentName: event.agent_name,
      createdAt: event.created_at,
      href: agentId ? `/behavior/agents/${agentId}` : undefined,
      tags: [event.state, `${event.score} score`, event.watched_root],
    });
  }

  for (const alert of alerts) {
    const agentId = alert.agent_name ? agentIdByName.get(alert.agent_name) : undefined;
    entries.push({
      id: `alert-${alert.id}`,
      kind: 'alert',
      severity: normalizeSeverity(alert.severity),
      title: alert.title,
      description: alert.message,
      agentName: alert.agent_name ?? undefined,
      createdAt: alert.created_at,
      href: alert.incident_id
        ? `/behavior/incidents/${alert.incident_id}`
        : agentId
        ? `/behavior/agents/${agentId}`
        : undefined,
      tags: [alert.alert_type, alert.severity],
    });
  }

  return entries
    .sort((left, right) => {
      return (
        new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime() ||
        left.title.localeCompare(right.title)
      );
    })
    .slice(0, 40);
}

export function normalizeSeverity(severity: string): TimelineSeverity {
  switch (severity) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    default:
      return 'low';
  }
}

export function summarizeAlertCount(alerts: AdminAlert[]) {
  return alerts.filter((alert) => normalizeSeverity(alert.severity) !== 'low').length;
}
