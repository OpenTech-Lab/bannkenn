'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { startTransition, useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  fetchAgentBehaviorEventsPage,
  fetchAgentContainmentActionsPage,
  fetchAgentContainmentEventsPage,
  fetchAgentDecisionsPage,
  fetchAgentDetailSnapshot,
  fetchAgentTelemetryEventsPage,
  requestContainmentAction,
} from '@/src/features/monitoring/api';
import {
  AgentStatusBadge,
  ContainmentStateBadge,
  ContainmentStateTrack,
  EbpfSensorBadge,
} from '@/src/features/monitoring/components/status-badge';
import {
  AgentDetailSnapshot,
  BehaviorEvent,
  ContainmentAction,
  ContainmentEvent,
  Decision,
  PaginatedResult,
  TelemetryEvent,
} from '@/src/features/monitoring/types';
import {
  agentLabel,
  formatRelativeTime,
  formatTimestamp,
} from '@/src/features/monitoring/utils';

const POLL_INTERVAL_MS = 30_000;
const ACTION_PAGE_SIZE = 6;
const BEHAVIOR_PAGE_SIZE = 10;
const CONTAINMENT_PAGE_SIZE = 10;
const TELEMETRY_PAGE_SIZE = 10;
const DECISION_PAGE_SIZE = 10;

type LogBlockTab = 'behavior' | 'ip';
type EventTab = 'behavior' | 'containment';
type IpTab = 'telemetry' | 'decisions';

function formatParentChain(chain: BehaviorEvent['parent_chain']) {
  if (!chain.length) {
    return 'unknown';
  }

  return chain
    .map((entry) => {
      const label = entry.process_name ?? entry.exe_path ?? `pid ${entry.pid}`;
      const details = [
        entry.exe_path ? `exe: ${entry.exe_path}` : null,
        entry.command_line ? `cmd: ${entry.command_line}` : null,
      ].filter((value): value is string => Boolean(value));
      return details.length ? `${label} (${details.join(' / ')})` : label;
    })
    .join(' -> ');
}

export function AgentDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params?.id;
  const [snapshot, setSnapshot] = useState<AgentDetailSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [pendingActionKey, setPendingActionKey] = useState<string | null>(null);
  const [logsRefreshTick, setLogsRefreshTick] = useState(0);
  const [logBlockTab, setLogBlockTab] = useState<LogBlockTab>('behavior');
  const [eventTab, setEventTab] = useState<EventTab>('behavior');
  const [ipTab, setIpTab] = useState<IpTab>('telemetry');
  const hasCompletedInitialSnapshot = useRef(false);

  useEffect(() => {
    setLogBlockTab('behavior');
    setEventTab('behavior');
    setIpTab('telemetry');
  }, [id]);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    const refresh = async () => {
      try {
        const next = await fetchAgentDetailSnapshot(id);
        if (cancelled) return;
        startTransition(() => {
          setSnapshot(next);
          setError(null);
          setLoading(false);
        });
        if (hasCompletedInitialSnapshot.current) {
          setLogsRefreshTick((tick) => tick + 1);
        } else {
          hasCompletedInitialSnapshot.current = true;
        }
      } catch (cause) {
        if (cancelled) return;
        startTransition(() => {
          setError(cause instanceof Error ? cause.message : 'Failed to load agent detail');
          setLoading(false);
        });
      }
    };
    void refresh();
    const intervalId = window.setInterval(() => void refresh(), POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [id]);

  const actionLog = usePaginatedAgentLog(
    id,
    ACTION_PAGE_SIZE,
    logsRefreshTick,
    fetchAgentContainmentActionsPage
  );
  const behaviorLog = usePaginatedAgentLog(
    id,
    BEHAVIOR_PAGE_SIZE,
    logsRefreshTick,
    fetchAgentBehaviorEventsPage
  );
  const containmentLog = usePaginatedAgentLog(
    id,
    CONTAINMENT_PAGE_SIZE,
    logsRefreshTick,
    fetchAgentContainmentEventsPage
  );
  const telemetryLog = usePaginatedAgentLog(
    id,
    TELEMETRY_PAGE_SIZE,
    logsRefreshTick,
    fetchAgentTelemetryEventsPage
  );
  const decisionLog = usePaginatedAgentLog(
    id,
    DECISION_PAGE_SIZE,
    logsRefreshTick,
    fetchAgentDecisionsPage
  );

  const currentContainment = snapshot?.containmentEvents[0];
  const pendingActions =
    snapshot?.containmentActions.filter((action) => action.status === 'pending').length ?? 0;
  const elevatedBehaviorCount =
    snapshot?.behaviorEvents.filter((event) => event.level !== 'observed').length ?? 0;
  const actionHistory = actionLog.data.items;
  const behaviorEvents = behaviorLog.data.items;
  const containmentHistory = containmentLog.data.items;
  const telemetryEvents = telemetryLog.data.items;
  const decisions = decisionLog.data.items;
  const hasIpLogs = (snapshot?.telemetryEvents.length ?? 0) > 0 || (snapshot?.decisions.length ?? 0) > 0;

  async function handleAction(commandKind: 'trigger_fuse' | 'release_fuse') {
    if (!snapshot) return;
    const key = `${snapshot.agent.id}:${commandKind}`;
    setPendingActionKey(key);
    try {
      await requestContainmentAction(snapshot.agent.id, {
        command_kind: commandKind,
        reason:
          commandKind === 'trigger_fuse'
            ? 'Manual fuse trigger from agent detail view'
            : 'Manual fuse release from agent detail view',
        watched_root: currentContainment?.watched_root ?? null,
        pid: currentContainment?.pid ?? null,
      });
      toast.success(
        commandKind === 'trigger_fuse'
          ? `FUSE queued for ${agentLabel(snapshot.agent)}`
          : `FUSE release queued for ${agentLabel(snapshot.agent)}`
      );
      const next = await fetchAgentDetailSnapshot(id ?? String(snapshot.agent.id));
      startTransition(() => {
        setSnapshot(next);
        setError(null);
      });
      setLogsRefreshTick((tick) => tick + 1);
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Failed to queue containment action');
    } finally {
      setPendingActionKey(null);
    }
  }

  if (loading && !snapshot) {
    return (
      <div className="px-6 py-8">
        <p className="text-sm text-muted-foreground">Loading agent detail...</p>
      </div>
    );
  }

  if (error && !snapshot) {
    return (
      <div className="px-6 py-8 space-y-4">
        <div className="rounded-xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
        <Link href="/behavior/fleet" className="text-sm text-blue-400 hover:text-blue-300">
          Back to fleet
        </Link>
      </div>
    );
  }

  if (!snapshot) return null;

  const state = currentContainment?.state ?? 'normal';
  const triggerKey = `${snapshot.agent.id}:trigger_fuse`;
  const releaseKey = `${snapshot.agent.id}:release_fuse`;

  return (
    <div className="max-w-7xl space-y-6 px-6 py-8">
      <div className="flex items-start justify-between gap-4">
        <div>
          <Link href="/behavior/fleet" className="text-sm text-blue-400 hover:text-blue-300">
            Back to fleet
          </Link>
          <p className="mt-4 text-xs uppercase tracking-[0.3em] text-muted-foreground">
            Agent Detail
          </p>
          <h1 className="mt-2 text-2xl font-bold text-white">{agentLabel(snapshot.agent)}</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Registered {formatTimestamp(snapshot.agent.created_at)}
            {snapshot.agent.last_seen_at && (
              <> · last seen {formatRelativeTime(snapshot.agent.last_seen_at)}</>
            )}
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <AgentStatusBadge status={snapshot.agent.status} />
            <ContainmentStateBadge state={state} />
            <EbpfSensorBadge sensor={snapshot.agent.containment_sensor} />
          </div>
        </div>
        <div className="space-y-3 rounded-xl border border-border bg-card p-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
            Manual Containment
          </p>
          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              variant="destructive"
              disabled={pendingActionKey === triggerKey || state === 'fuse'}
              onClick={() => void handleAction('trigger_fuse')}
            >
              {pendingActionKey === triggerKey ? 'Queuing...' : 'Trigger FUSE'}
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={pendingActionKey === releaseKey || state !== 'fuse'}
              onClick={() => void handleAction('release_fuse')}
            >
              {pendingActionKey === releaseKey ? 'Queuing...' : 'Release FUSE'}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            {currentContainment
              ? `Root ${currentContainment.watched_root} · score ${currentContainment.score}`
              : 'No containment transitions recorded yet'}
          </p>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Behavior Events</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-white">
            {snapshot.behaviorEvents.length}
          </p>
        </div>
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Elevated</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-amber-400">
            {elevatedBehaviorCount}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">Above observed severity</p>
        </div>
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
            Containment Changes
          </p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-orange-400">
            {snapshot.containmentEvents.length}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            {currentContainment
              ? `Latest ${formatRelativeTime(currentContainment.created_at)}`
              : 'No history yet'}
          </p>
        </div>
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Incidents</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-red-400">
            {snapshot.relatedIncidents.length}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            {pendingActions} pending action{pendingActions !== 1 ? 's' : ''}
          </p>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <section className="space-y-0">
          <h2 className="pb-3 text-xs font-semibold uppercase tracking-[0.3em] text-muted-foreground">
            Current Containment State
          </h2>

          <div className="space-y-4">
            <ContainmentStateTrack state={state} />
            {currentContainment && (
              <p className="text-sm text-muted-foreground">{currentContainment.reason}</p>
            )}
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-xl border border-gray-800 bg-gray-900/40 px-3 py-3">
                <p className="text-xs text-gray-500">Watched Root</p>
                <p className="mt-1 truncate text-sm text-gray-300">
                  {currentContainment?.watched_root ?? 'Not available'}
                </p>
              </div>
              <div className="rounded-xl border border-gray-800 bg-gray-900/40 px-3 py-3">
                <p className="text-xs text-gray-500">Last Transition</p>
                <p className="mt-1 text-sm text-gray-300">
                  {currentContainment ? formatTimestamp(currentContainment.created_at) : 'Never'}
                </p>
              </div>
            </div>
          </div>
        </section>

        <section className="space-y-0">
          <div className="flex items-center justify-between gap-4 pb-3">
            <h2 className="text-xs font-semibold uppercase tracking-[0.3em] text-muted-foreground">
              Operator Action Queue
            </h2>
            <span className="text-xs text-muted-foreground">Paginated history</span>
          </div>

          <div className="overflow-hidden rounded-xl border border-border">
            {actionLog.error && actionHistory.length === 0 ? (
              <div className="px-4 py-6 text-sm text-red-300">{actionLog.error}</div>
            ) : actionLog.loading && actionHistory.length === 0 ? (
              <div className="px-4 py-6 text-sm text-muted-foreground">Loading operator actions...</div>
            ) : actionHistory.length === 0 ? (
              <div className="px-4 py-6 text-sm text-muted-foreground">
                No operator actions have been queued yet.
              </div>
            ) : (
              <div className="space-y-3 p-4">
                {actionHistory.map((action) => (
                  <div
                    key={action.id}
                    className="rounded-xl border border-gray-800 bg-gray-900/40 p-4"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="space-y-1">
                        <p className="text-sm font-medium text-white">
                          {action.command_kind.replace('_', ' ')}
                        </p>
                        <p className="text-sm text-muted-foreground">{action.reason}</p>
                        <p className="text-xs text-gray-500">
                          {action.result_message ?? 'Awaiting agent acknowledgement'}
                        </p>
                      </div>
                      <div className="shrink-0 text-right text-xs text-muted-foreground">
                        <p>{action.status}</p>
                        <p>{formatTimestamp(action.executed_at ?? action.updated_at)}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
            <PaginationControls
              page={actionLog.page}
              pageSize={ACTION_PAGE_SIZE}
              itemCount={actionHistory.length}
              hasMore={actionLog.data.has_more}
              loading={actionLog.loading}
              onPrevious={() => actionLog.setPage((page) => Math.max(page - 1, 0))}
              onNext={() => actionLog.setPage((page) => page + 1)}
              label="actions"
            />
          </div>
        </section>
      </div>

      <section className="space-y-0">
        <Tabs value={logBlockTab} onValueChange={(value) => setLogBlockTab(value as LogBlockTab)}>
          <div className="flex items-center justify-between gap-4 pb-3">
            <div>
              <h2 className="text-xs font-semibold uppercase tracking-[0.3em] text-muted-foreground">
                Investigation Logs
              </h2>
              <p className="mt-2 text-sm text-muted-foreground">
                Switch between behavior-side history and IP monitor history below the latest
                suspicious score threshold crossing context.
              </p>
            </div>
            <TabsList>
              <TabsTrigger value="behavior">Behavior Logs</TabsTrigger>
              <TabsTrigger value="ip" disabled={!hasIpLogs}>
                IP Logs
              </TabsTrigger>
            </TabsList>
          </div>
          <div className="border-t border-border" />

          <TabsContent value="behavior" className="mt-0 space-y-4 pt-4">
            <div className="rounded-xl border border-border bg-card/40 px-4 py-3 text-sm text-muted-foreground">
              {currentContainment?.reason ?? 'No suspicious score threshold crossing has been recorded yet.'}
            </div>

            <Tabs value={eventTab} onValueChange={(value) => setEventTab(value as EventTab)}>
              <div className="flex items-center justify-between pb-3">
                <h3 className="text-xs font-semibold uppercase tracking-[0.3em] text-muted-foreground">
                  Events
                </h3>
                <TabsList>
                  <TabsTrigger value="behavior">
                    Behavior Events
                    <span className="ml-1.5 rounded-full bg-white/10 px-1.5 py-0.5 text-[10px] tabular-nums">
                      {behaviorEvents.length}
                    </span>
                  </TabsTrigger>
                  <TabsTrigger value="containment">
                    Containment History
                    <span className="ml-1.5 rounded-full bg-white/10 px-1.5 py-0.5 text-[10px] tabular-nums">
                      {containmentHistory.length}
                    </span>
                  </TabsTrigger>
                </TabsList>
              </div>
              <div className="border-t border-border" />

              <TabsContent value="behavior" className="mt-0">
                <div className="overflow-hidden rounded-b-xl border-x border-b border-border">
                  {behaviorLog.error && behaviorEvents.length === 0 ? (
                    <div className="px-4 py-6 text-sm text-red-300">{behaviorLog.error}</div>
                  ) : behaviorLog.loading && behaviorEvents.length === 0 ? (
                    <div className="px-4 py-6 text-sm text-muted-foreground">
                      Loading behavior events...
                    </div>
                  ) : behaviorEvents.length === 0 ? (
                    <div className="px-4 py-6 text-sm text-muted-foreground">
                      No behavior events have been uploaded yet.
                    </div>
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Process</TableHead>
                          <TableHead>Level</TableHead>
                          <TableHead>Reasons</TableHead>
                          <TableHead>Root</TableHead>
                          <TableHead className="text-right">Score</TableHead>
                          <TableHead>PID</TableHead>
                          <TableHead>Time</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {behaviorEvents.map((event) => (
                          <TableRow key={event.id}>
                            <TableCell className="max-w-[240px]">
                              <div className="space-y-1">
                                <p className="truncate font-medium text-white">
                                  {event.process_name ?? event.exe_path ?? 'unknown'}
                                </p>
                                <p className="truncate text-xs text-muted-foreground">
                                  exe: {event.exe_path ?? 'unknown'}
                                </p>
                                <p className="truncate text-xs text-muted-foreground">
                                  parent:{' '}
                                  {event.parent_process_name ??
                                    event.parent_command_line ??
                                    'unknown'}
                                </p>
                                <p className="truncate text-xs text-muted-foreground">
                                  trust: {event.trust_class ?? 'unknown'}
                                  {event.service_unit ? ` / unit: ${event.service_unit}` : ''}
                                  {event.trust_policy_name
                                    ? ` / policy: ${event.trust_policy_name}`
                                    : ''}
                                </p>
                                <p className="truncate text-xs text-muted-foreground">
                                  maintenance: {event.maintenance_activity ?? 'none'}
                                </p>
                                <p className="truncate text-xs text-muted-foreground">
                                  package: {event.package_name ?? 'unknown'}
                                  {event.package_manager
                                    ? ` / manager: ${event.package_manager}`
                                    : ''}
                                </p>
                                <p className="break-words text-xs text-muted-foreground">
                                  ancestry: {formatParentChain(event.parent_chain)}
                                </p>
                                <p className="truncate text-xs text-muted-foreground">
                                  ids: pid {event.pid ?? '—'} / ppid {event.parent_pid ?? '—'} / uid
                                  :gid {event.uid ?? '—'}:{event.gid ?? '—'}
                                </p>
                                <p className="truncate text-xs text-muted-foreground">
                                  first seen:{' '}
                                  {event.first_seen_at
                                    ? formatTimestamp(event.first_seen_at)
                                    : 'unknown'}
                                </p>
                                <p className="truncate text-xs text-muted-foreground">
                                  container:{' '}
                                  {event.container_runtime && event.container_id
                                    ? `${event.container_runtime}:${event.container_id}`
                                    : 'host'}
                                </p>
                              </div>
                            </TableCell>
                            <TableCell>
                              <Badge
                                className={
                                  event.level === 'critical'
                                    ? 'border border-red-700 bg-red-950/60 text-red-300'
                                    : event.level === 'high'
                                      ? 'border border-orange-700 bg-orange-950/50 text-orange-300'
                                      : event.level === 'suspicious'
                                        ? 'border border-amber-700 bg-amber-950/50 text-amber-300'
                                        : 'border border-gray-700 bg-gray-900/70 text-gray-200'
                                }
                              >
                                {event.level}
                              </Badge>
                            </TableCell>
                            <TableCell className="max-w-[200px] truncate text-sm text-muted-foreground">
                              {event.reasons.join(', ') || '—'}
                            </TableCell>
                            <TableCell className="max-w-[160px] truncate font-mono text-sm text-muted-foreground">
                              {event.watched_root}
                            </TableCell>
                            <TableCell className="text-right tabular-nums">{event.score}</TableCell>
                            <TableCell className="tabular-nums text-sm text-muted-foreground">
                              {event.pid ?? '—'}
                            </TableCell>
                            <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                              <p>{formatTimestamp(event.created_at)}</p>
                              <p>{formatRelativeTime(event.created_at)}</p>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                  <PaginationControls
                    page={behaviorLog.page}
                    pageSize={BEHAVIOR_PAGE_SIZE}
                    itemCount={behaviorEvents.length}
                    hasMore={behaviorLog.data.has_more}
                    loading={behaviorLog.loading}
                    onPrevious={() => behaviorLog.setPage((page) => Math.max(page - 1, 0))}
                    onNext={() => behaviorLog.setPage((page) => page + 1)}
                    label="behavior events"
                  />
                </div>
              </TabsContent>

              <TabsContent value="containment" className="mt-0">
                <div className="overflow-hidden rounded-b-xl border-x border-b border-border">
                  {containmentLog.error && containmentHistory.length === 0 ? (
                    <div className="px-4 py-6 text-sm text-red-300">{containmentLog.error}</div>
                  ) : containmentLog.loading && containmentHistory.length === 0 ? (
                    <div className="px-4 py-6 text-sm text-muted-foreground">
                      Loading containment history...
                    </div>
                  ) : containmentHistory.length === 0 ? (
                    <div className="px-4 py-6 text-sm text-muted-foreground">
                      No containment events have been reported yet.
                    </div>
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>State</TableHead>
                          <TableHead>Previous</TableHead>
                          <TableHead>Reason</TableHead>
                          <TableHead>Root</TableHead>
                          <TableHead className="text-right">Score</TableHead>
                          <TableHead>Time</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {containmentHistory.map((event) => (
                          <TableRow key={event.id}>
                            <TableCell>
                              <ContainmentStateBadge state={event.state} />
                            </TableCell>
                            <TableCell className="text-sm text-muted-foreground">
                              {event.previous_state ?? '—'}
                            </TableCell>
                            <TableCell className="max-w-xs truncate text-sm text-muted-foreground">
                              {event.reason}
                            </TableCell>
                            <TableCell className="max-w-[160px] truncate font-mono text-sm text-muted-foreground">
                              {event.watched_root}
                            </TableCell>
                            <TableCell className="text-right tabular-nums">{event.score}</TableCell>
                            <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                              <p>{formatTimestamp(event.created_at)}</p>
                              <p>{formatRelativeTime(event.created_at)}</p>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                  <PaginationControls
                    page={containmentLog.page}
                    pageSize={CONTAINMENT_PAGE_SIZE}
                    itemCount={containmentHistory.length}
                    hasMore={containmentLog.data.has_more}
                    loading={containmentLog.loading}
                    onPrevious={() => containmentLog.setPage((page) => Math.max(page - 1, 0))}
                    onNext={() => containmentLog.setPage((page) => page + 1)}
                    label="containment events"
                  />
                </div>
              </TabsContent>
            </Tabs>
          </TabsContent>

          <TabsContent value="ip" className="mt-0 space-y-4 pt-4">
            <div className="rounded-xl border border-border bg-card/40 px-4 py-3 text-sm text-muted-foreground">
              IP telemetry and enforcement decisions correlated with this agent.
            </div>

            <Tabs value={ipTab} onValueChange={(value) => setIpTab(value as IpTab)}>
              <div className="flex items-center justify-between pb-3">
                <h3 className="text-xs font-semibold uppercase tracking-[0.3em] text-muted-foreground">
                  IP Monitor Logs
                </h3>
                <TabsList>
                  <TabsTrigger value="telemetry">Telemetry Events</TabsTrigger>
                  <TabsTrigger value="decisions">IP Decisions</TabsTrigger>
                </TabsList>
              </div>
              <div className="border-t border-border" />

              <TabsContent value="telemetry" className="mt-0">
                <div className="overflow-hidden rounded-b-xl border-x border-b border-border">
                  {telemetryLog.error && telemetryEvents.length === 0 ? (
                    <div className="px-4 py-6 text-sm text-red-300">{telemetryLog.error}</div>
                  ) : telemetryLog.loading && telemetryEvents.length === 0 ? (
                    <div className="px-4 py-6 text-sm text-muted-foreground">
                      Loading telemetry events...
                    </div>
                  ) : telemetryEvents.length === 0 ? (
                    <div className="px-4 py-6 text-sm text-muted-foreground">
                      No telemetry events recorded for this agent.
                    </div>
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>IP</TableHead>
                          <TableHead>Level</TableHead>
                          <TableHead>Reason</TableHead>
                          <TableHead>Source</TableHead>
                          <TableHead>Country</TableHead>
                          <TableHead>ASN / Org</TableHead>
                          <TableHead>Timestamp</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {telemetryEvents.map((event) => (
                          <TableRow key={event.id}>
                            <TableCell className="font-mono text-sm">{event.ip}</TableCell>
                            <TableCell>
                              <Badge
                                className={
                                  event.level === 'alert'
                                    ? 'border border-red-700 bg-red-950/60 text-red-300'
                                    : event.level === 'block'
                                      ? 'border border-orange-700 bg-orange-950/50 text-orange-300'
                                      : 'border border-gray-700 bg-gray-900/70 text-gray-200'
                                }
                              >
                                {event.level}
                              </Badge>
                            </TableCell>
                            <TableCell className="max-w-xs truncate text-sm text-muted-foreground">
                              {event.reason}
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {event.source}
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {event.country ?? '—'}
                            </TableCell>
                            <TableCell className="max-w-[160px] truncate text-xs text-muted-foreground">
                              {event.asn_org ?? '—'}
                            </TableCell>
                            <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                              <p>{formatTimestamp(event.created_at)}</p>
                              <p>{formatRelativeTime(event.created_at)}</p>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                  <PaginationControls
                    page={telemetryLog.page}
                    pageSize={TELEMETRY_PAGE_SIZE}
                    itemCount={telemetryEvents.length}
                    hasMore={telemetryLog.data.has_more}
                    loading={telemetryLog.loading}
                    onPrevious={() => telemetryLog.setPage((page) => Math.max(page - 1, 0))}
                    onNext={() => telemetryLog.setPage((page) => page + 1)}
                    label="telemetry events"
                  />
                </div>
              </TabsContent>

              <TabsContent value="decisions" className="mt-0">
                <div className="overflow-hidden rounded-b-xl border-x border-b border-border">
                  {decisionLog.error && decisions.length === 0 ? (
                    <div className="px-4 py-6 text-sm text-red-300">{decisionLog.error}</div>
                  ) : decisionLog.loading && decisions.length === 0 ? (
                    <div className="px-4 py-6 text-sm text-muted-foreground">
                      Loading IP decisions...
                    </div>
                  ) : decisions.length === 0 ? (
                    <div className="px-4 py-6 text-sm text-muted-foreground">
                      No IP decisions recorded for this agent.
                    </div>
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>IP</TableHead>
                          <TableHead>Action</TableHead>
                          <TableHead>Reason</TableHead>
                          <TableHead>Source</TableHead>
                          <TableHead>Country</TableHead>
                          <TableHead>ASN / Org</TableHead>
                          <TableHead>Expires</TableHead>
                          <TableHead>Timestamp</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {decisions.map((decision) => (
                          <TableRow key={decision.id}>
                            <TableCell className="font-mono text-sm">{decision.ip}</TableCell>
                            <TableCell>
                              <Badge
                                className={
                                  decision.action === 'block'
                                    ? 'border border-red-700 bg-red-950/60 text-red-300'
                                    : decision.action === 'captcha'
                                      ? 'border border-amber-700 bg-amber-950/50 text-amber-300'
                                      : 'border border-gray-700 bg-gray-900/70 text-gray-200'
                                }
                              >
                                {decision.action}
                              </Badge>
                            </TableCell>
                            <TableCell className="max-w-xs truncate text-sm text-muted-foreground">
                              {decision.reason}
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {decision.source}
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {decision.country ?? '—'}
                            </TableCell>
                            <TableCell className="max-w-[160px] truncate text-xs text-muted-foreground">
                              {decision.asn_org ?? '—'}
                            </TableCell>
                            <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                              {decision.expires_at ? formatRelativeTime(decision.expires_at) : '—'}
                            </TableCell>
                            <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                              <p>{formatTimestamp(decision.created_at)}</p>
                              <p>{formatRelativeTime(decision.created_at)}</p>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                  <PaginationControls
                    page={decisionLog.page}
                    pageSize={DECISION_PAGE_SIZE}
                    itemCount={decisions.length}
                    hasMore={decisionLog.data.has_more}
                    loading={decisionLog.loading}
                    onPrevious={() => decisionLog.setPage((page) => Math.max(page - 1, 0))}
                    onNext={() => decisionLog.setPage((page) => page + 1)}
                    label="IP decisions"
                  />
                </div>
              </TabsContent>
            </Tabs>
          </TabsContent>
        </Tabs>
      </section>

      {snapshot.relatedIncidents.length > 0 && (
        <section className="space-y-0">
          <h2 className="pb-3 text-xs font-semibold uppercase tracking-[0.3em] text-muted-foreground">
            Related Incidents
          </h2>
          <div className="border-t border-border" />
          <div className="overflow-hidden rounded-b-xl border-x border-b border-border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Title</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead className="text-right">Events</TableHead>
                  <TableHead>Last Seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {snapshot.relatedIncidents.slice(0, 8).map((incident) => (
                  <TableRow key={incident.id}>
                    <TableCell className="max-w-xs font-medium">
                      <Link
                        href={`/behavior/incidents/${incident.id}`}
                        className="text-blue-400 hover:text-blue-300 hover:underline"
                      >
                        {incident.title}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={incident.severity} />
                    </TableCell>
                    <TableCell>
                      {incident.latest_state && (
                        <Badge
                          className={
                            incident.latest_state === 'fuse'
                              ? 'border border-red-700 bg-red-950/60 text-red-300'
                              : incident.latest_state === 'throttle'
                                ? 'border border-orange-700 bg-orange-950/50 text-orange-300'
                                : 'border border-gray-700 bg-gray-900/70 text-gray-200'
                          }
                        >
                          {incident.latest_state}
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {incident.event_count}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                      {formatRelativeTime(incident.last_seen_at)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </section>
      )}
    </div>
  );
}

type PageLoader<T> = (
  agentId: string,
  limit: number,
  offset: number
) => Promise<PaginatedResult<T>>;

function usePaginatedAgentLog<T>(
  agentId: string | undefined,
  pageSize: number,
  refreshTick: number,
  loader: PageLoader<T>
) {
  const [page, setPage] = useState(0);
  const [data, setData] = useState<PaginatedResult<T>>({
    items: [],
    limit: pageSize,
    offset: 0,
    has_more: false,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setPage(0);
    setData({
      items: [],
      limit: pageSize,
      offset: 0,
      has_more: false,
    });
    setError(null);
    setLoading(true);
  }, [agentId, pageSize]);

  useEffect(() => {
    if (!agentId) return;
    let cancelled = false;
    const offset = page * pageSize;

    const refresh = async () => {
      setLoading(true);
      try {
        const next = await loader(agentId, pageSize, offset);
        if (cancelled) return;
        startTransition(() => {
          setData(next);
          setError(null);
          setLoading(false);
        });
      } catch (cause) {
        if (cancelled) return;
        startTransition(() => {
          setError(cause instanceof Error ? cause.message : 'Failed to load log history');
          setLoading(false);
        });
      }
    };

    void refresh();
    return () => {
      cancelled = true;
    };
  }, [agentId, loader, page, pageSize, refreshTick]);

  return { data, error, loading, page, setPage };
}

function PaginationControls({
  page,
  pageSize,
  itemCount,
  hasMore,
  loading,
  onPrevious,
  onNext,
  label,
}: {
  page: number;
  pageSize: number;
  itemCount: number;
  hasMore: boolean;
  loading: boolean;
  onPrevious: () => void;
  onNext: () => void;
  label: string;
}) {
  const start = itemCount === 0 ? 0 : page * pageSize + 1;
  const end = itemCount === 0 ? 0 : page * pageSize + itemCount;

  return (
    <div className="flex items-center justify-between gap-3 border-t border-border px-4 py-3">
      <p className="text-xs text-muted-foreground">
        Page {page + 1}
        {itemCount > 0 ? ` · showing ${start}-${end} ${label}` : ` · no ${label} on this page`}
        {loading ? ' · refreshing...' : ''}
      </p>
      <div className="flex gap-2">
        <Button size="sm" variant="outline" disabled={page === 0 || loading} onClick={onPrevious}>
          Newer
        </Button>
        <Button size="sm" variant="outline" disabled={!hasMore || loading} onClick={onNext}>
          Older
        </Button>
      </div>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const cls =
    severity === 'critical'
      ? 'border border-red-700 bg-red-950/60 text-red-300'
      : severity === 'high'
        ? 'border border-orange-700 bg-orange-950/50 text-orange-300'
        : severity === 'medium'
          ? 'border border-amber-700 bg-amber-950/50 text-amber-300'
          : 'border border-gray-700 bg-gray-900/70 text-gray-200';
  return <Badge className={cls}>{severity}</Badge>;
}
