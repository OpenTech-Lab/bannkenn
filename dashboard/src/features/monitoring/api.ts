import {
  AgentDetailSnapshot,
  AgentStatus,
  BehaviorEvent,
  ContainmentAction,
  ContainmentActionRequest,
  ContainmentEvent,
  ContainmentStatus,
  DashboardSnapshot,
  Decision,
  HealthStatus,
  Incident,
  IncidentDetail,
  IncidentDetailSnapshot,
  AdminAlert,
  PaginatedResult,
  TelemetryEvent,
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

async function readJsonBodyIfPresent<T>(response: Response): Promise<T | null> {
  if (response.status === 204) {
    return null;
  }

  const contentType = response.headers.get('Content-Type') ?? '';
  if (!contentType.includes('application/json')) {
    return null;
  }

  const body = await response.text();
  if (!body.trim()) {
    return null;
  }

  return JSON.parse(body) as T;
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
  const [
    agent,
    behaviorEvents,
    containmentEvents,
    containmentActions,
    incidents,
    telemetryEvents,
    decisions,
  ] = await Promise.all([
    readJson<AgentStatus>(`/api/agents/${agentId}`),
    fetchAgentBehaviorEventsPage(agentId, 120, 0),
    fetchAgentContainmentEventsPage(agentId, 120, 0),
    fetchAgentContainmentActionsPage(agentId, 120, 0),
    readJson<Incident[]>('/api/incidents?limit=120'),
    fetchAgentTelemetryEventsPage(agentId, 200, 0),
    fetchAgentDecisionsPage(agentId, 200, 0),
  ]);

  return {
    agent,
    behaviorEvents: behaviorEvents.items,
    containmentEvents: containmentEvents.items,
    containmentActions: containmentActions.items,
    relatedIncidents: incidents.filter((incident) => incident.affected_agents.includes(agent.name)),
    telemetryEvents: telemetryEvents.items,
    decisions: decisions.items,
  };
}

export async function fetchAgentBehaviorEventsPage(
  agentId: string,
  limit: number,
  offset: number
): Promise<PaginatedResult<BehaviorEvent>> {
  return readJson<PaginatedResult<BehaviorEvent>>(
    `/api/agents/${agentId}/behavior-events?limit=${limit}&offset=${offset}`
  );
}

export async function fetchAgentContainmentEventsPage(
  agentId: string,
  limit: number,
  offset: number
): Promise<PaginatedResult<ContainmentEvent>> {
  return readJson<PaginatedResult<ContainmentEvent>>(
    `/api/agents/${agentId}/containment?limit=${limit}&offset=${offset}`
  );
}

export async function fetchAgentContainmentActionsPage(
  agentId: string,
  limit: number,
  offset: number
): Promise<PaginatedResult<ContainmentAction>> {
  return readJson<PaginatedResult<ContainmentAction>>(
    `/api/agents/${agentId}/containment-actions?limit=${limit}&offset=${offset}`
  );
}

export async function fetchAgentTelemetryEventsPage(
  agentId: string,
  limit: number,
  offset: number
): Promise<PaginatedResult<TelemetryEvent>> {
  return readJson<PaginatedResult<TelemetryEvent>>(
    `/api/agents/${agentId}/telemetry?limit=${limit}&offset=${offset}`
  );
}

export async function fetchAgentDecisionsPage(
  agentId: string,
  limit: number,
  offset: number
): Promise<PaginatedResult<Decision>> {
  return readJson<PaginatedResult<Decision>>(
    `/api/agents/${agentId}/decisions?limit=${limit}&offset=${offset}`
  );
}

export async function updateAgentNickname(agentId: number, nickname: string): Promise<AgentStatus> {
  const response = await fetch(`/api/agents/${agentId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nickname }),
  });

  if (!response.ok) {
    throw new Error(await readError(response));
  }

  const updatedAgent = await readJsonBodyIfPresent<AgentStatus>(response);
  if (updatedAgent) {
    return updatedAgent;
  }

  return readJson<AgentStatus>(`/api/agents/${agentId}`);
}

export async function deleteAgent(agentId: number) {
  const response = await fetch(`/api/agents/${agentId}`, {
    method: 'DELETE',
  });

  if (!response.ok) {
    throw new Error(await readError(response));
  }
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
