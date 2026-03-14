import {
  AgentDetailSnapshot,
  AgentStatus,
  BehaviorEvent,
  ContainmentAction,
  ContainmentActionRequest,
  ContainmentEvent,
  ContainmentStatus,
  DashboardSnapshot,
  HealthStatus,
  Incident,
  IncidentDetail,
  IncidentDetailSnapshot,
  AdminAlert,
} from '@/src/features/monitoring/types';

async function readError(response: Response) {
  const contentType = response.headers.get('Content-Type') ?? '';

  if (contentType.includes('application/json')) {
    const body = (await response.json()) as { error?: string };
    return body.error ?? `Request failed with status ${response.status}`;
  }

  const text = await response.text();
  return text || `Request failed with status ${response.status}`;
}

async function readJson<T>(path: string) {
  const response = await fetch(path, { cache: 'no-store' });
  if (!response.ok) {
    throw new Error(await readError(response));
  }

  return (await response.json()) as T;
}

export async function fetchDashboardSnapshot(): Promise<DashboardSnapshot> {
  const [health, agents, containmentStatuses, containmentEvents, incidents, alerts, behaviorEvents] =
    await Promise.all([
      readJson<HealthStatus>('/api/health'),
      readJson<AgentStatus[]>('/api/agents'),
      readJson<ContainmentStatus[]>('/api/containment?limit=250'),
      readJson<ContainmentEvent[]>('/api/containment/events?limit=120'),
      readJson<Incident[]>('/api/incidents?limit=80'),
      readJson<AdminAlert[]>('/api/alerts?limit=80'),
      readJson<BehaviorEvent[]>('/api/behavior-events?limit=120'),
    ]);

  return {
    health,
    agents,
    containmentStatuses,
    containmentEvents,
    incidents,
    alerts,
    behaviorEvents,
  };
}

export async function fetchAgentDetailSnapshot(agentId: string): Promise<AgentDetailSnapshot> {
  const [agent, behaviorEvents, containmentEvents, containmentActions, incidents] = await Promise.all([
    readJson<AgentStatus>(`/api/agents/${agentId}`),
    readJson<BehaviorEvent[]>(`/api/agents/${agentId}/behavior-events?limit=120`),
    readJson<ContainmentEvent[]>(`/api/agents/${agentId}/containment?limit=120`),
    readJson<ContainmentAction[]>(`/api/agents/${agentId}/containment-actions?limit=120`),
    readJson<Incident[]>('/api/incidents?limit=120'),
  ]);

  return {
    agent,
    behaviorEvents,
    containmentEvents,
    containmentActions,
    relatedIncidents: incidents.filter((incident) => incident.affected_agents.includes(agent.name)),
  };
}

export async function fetchIncidentDetailSnapshot(
  incidentId: string
): Promise<IncidentDetailSnapshot> {
  const [detail, agents] = await Promise.all([
    readJson<IncidentDetail>(`/api/incidents/${incidentId}?timeline_limit=300`),
    readJson<AgentStatus[]>('/api/agents'),
  ]);

  return { detail, agents };
}

export async function requestContainmentAction(
  agentId: number,
  payload: ContainmentActionRequest
) {
  const response = await fetch(`/api/agents/${agentId}/containment-actions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(await readError(response));
  }

  const body = (await response.json()) as { action: ContainmentAction };
  return body.action;
}
