'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { startTransition, useEffect, useMemo, useState } from 'react';
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
  fetchAgentDetailSnapshot,
  requestContainmentAction,
} from '@/src/features/monitoring/api';
import {
  AgentStatusBadge,
  ContainmentStateBadge,
  ContainmentStateTrack,
  EbpfSensorBadge,
} from '@/src/features/monitoring/components/status-badge';
import { AgentDetailSnapshot } from '@/src/features/monitoring/types';
import {
  agentLabel,
  formatRelativeTime,
  formatTimestamp,
} from '@/src/features/monitoring/utils';

const POLL_INTERVAL_MS = 30_000;

export function AgentDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params?.id;
  const [snapshot, setSnapshot] = useState<AgentDetailSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [pendingActionKey, setPendingActionKey] = useState<string | null>(null);
  const [ipTab, setIpTab] = useState<'telemetry' | 'decisions'>('telemetry');

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

  const currentContainment = snapshot?.containmentEvents[0];
  const pendingActions =
    snapshot?.containmentActions.filter((a) => a.status === 'pending').length ?? 0;
  const elevatedBehaviorCount =
    snapshot?.behaviorEvents.filter((e) => e.level !== 'observed').length ?? 0;

  const containmentHistory = useMemo(() => snapshot?.containmentEvents.slice(0, 12) ?? [], [snapshot]);
  const actionHistory = useMemo(() => snapshot?.containmentActions.slice(0, 12) ?? [], [snapshot]);
  const behaviorEvents = useMemo(() => snapshot?.behaviorEvents.slice(0, 30) ?? [], [snapshot]);

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
    <div className="px-6 py-8 space-y-6 max-w-7xl">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <Link href="/behavior/fleet" className="text-sm text-blue-400 hover:text-blue-300">
            Back to fleet
          </Link>
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground mt-4">
            Agent Detail
          </p>
          <h1 className="text-2xl font-bold text-white mt-2">{agentLabel(snapshot.agent)}</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Registered {formatTimestamp(snapshot.agent.created_at)}
            {snapshot.agent.last_seen_at && (
              <> · last seen {formatRelativeTime(snapshot.agent.last_seen_at)}</>
            )}
          </p>
          <div className="flex flex-wrap gap-2 mt-3">
            <AgentStatusBadge status={snapshot.agent.status} />
            <ContainmentStateBadge state={state} />
            <EbpfSensorBadge sensor={snapshot.agent.containment_sensor} />
          </div>
        </div>
        <div className="rounded-xl border border-border bg-card p-4 space-y-3">
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

      {/* Metric cards */}
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
          <p className="text-xs text-muted-foreground mt-1">Above observed severity</p>
        </div>
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Containment Changes</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-orange-400">
            {snapshot.containmentEvents.length}
          </p>
          <p className="text-xs text-muted-foreground mt-1">
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
          <p className="text-xs text-muted-foreground mt-1">
            {pendingActions} pending action{pendingActions !== 1 ? 's' : ''}
          </p>
        </div>
      </div>

      {/* Containment state + action queue */}
      <div className="grid gap-6 lg:grid-cols-2">
        <section className="space-y-0">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em] pb-3">
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
                <p className="text-sm text-gray-300 mt-1 truncate">
                  {currentContainment?.watched_root ?? 'Not available'}
                </p>
              </div>
              <div className="rounded-xl border border-gray-800 bg-gray-900/40 px-3 py-3">
                <p className="text-xs text-gray-500">Last Transition</p>
                <p className="text-sm text-gray-300 mt-1">
                  {currentContainment ? formatTimestamp(currentContainment.created_at) : 'Never'}
                </p>
              </div>
            </div>
          </div>
        </section>

        <section className="space-y-0">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em] pb-3">
            Operator Action Queue
          </h2>
          
          {actionHistory.length === 0 ? (
            <p className="text-sm text-muted-foreground">No operator actions have been queued yet.</p>
          ) : (
            <div className="space-y-3">
              {actionHistory.map((action) => (
                <div
                  key={action.id}
                  className="rounded-xl border border-gray-800 bg-gray-900/40 p-4"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-1">
                      <p className="font-medium text-white text-sm">
                        {action.command_kind.replace('_', ' ')}
                      </p>
                      <p className="text-sm text-muted-foreground">{action.reason}</p>
                      <p className="text-xs text-gray-500">
                        {action.result_message ?? 'Awaiting agent acknowledgement'}
                      </p>
                    </div>
                    <div className="text-right text-xs text-muted-foreground shrink-0">
                      <p>{action.status}</p>
                      <p>{formatTimestamp(action.executed_at ?? action.updated_at)}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* Behavior Events + Containment History tabs */}
      <section className="space-y-0">
        <Tabs defaultValue="behavior">
          <div className="flex items-center justify-between pb-3">
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
              Events
            </h2>
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
            <div className="rounded-b-xl border-x border-b border-border overflow-hidden">
              {behaviorEvents.length === 0 ? (
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
                        <TableCell className="font-medium text-white max-w-[160px] truncate">
                          {event.process_name ?? event.exe_path ?? 'unknown'}
                        </TableCell>
                        <TableCell>
                          <Badge
                            className={
                              event.level === 'critical'
                                ? 'bg-red-950/60 text-red-300 border border-red-700'
                                : event.level === 'high'
                                ? 'bg-orange-950/50 text-orange-300 border border-orange-700'
                                : event.level === 'suspicious'
                                ? 'bg-amber-950/50 text-amber-300 border border-amber-700'
                                : 'bg-gray-900/70 text-gray-200 border border-gray-700'
                            }
                          >
                            {event.level}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground max-w-[200px] truncate">
                          {event.reasons.join(', ') || '—'}
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground font-mono max-w-[160px] truncate">
                          {event.watched_root}
                        </TableCell>
                        <TableCell className="text-right tabular-nums">{event.score}</TableCell>
                        <TableCell className="text-sm text-muted-foreground tabular-nums">
                          {event.pid ?? '—'}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                          <p>{formatTimestamp(event.created_at)}</p>
                          <p>{formatRelativeTime(event.created_at)}</p>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </div>
          </TabsContent>

          <TabsContent value="containment" className="mt-0">
            <div className="rounded-b-xl border-x border-b border-border overflow-hidden">
              {containmentHistory.length === 0 ? (
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
                        <TableCell className="text-sm text-muted-foreground max-w-xs truncate">
                          {event.reason}
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground font-mono max-w-[160px] truncate">
                          {event.watched_root}
                        </TableCell>
                        <TableCell className="text-right tabular-nums">{event.score}</TableCell>
                        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                          <p>{formatTimestamp(event.created_at)}</p>
                          <p>{formatRelativeTime(event.created_at)}</p>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </div>
          </TabsContent>
        </Tabs>
      </section>

      {/* Related incidents */}
      {snapshot.relatedIncidents.length > 0 && (
        <section className="space-y-0">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em] pb-3">
            Related Incidents
          </h2>
          <div className="border-t border-border" />
          <div className="rounded-b-xl border-x border-b border-border overflow-hidden">
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
                {snapshot.relatedIncidents.slice(0, 8).map((inc) => (
                  <TableRow key={inc.id}>
                    <TableCell className="font-medium max-w-xs">
                      <Link
                        href={`/behavior/incidents/${inc.id}`}
                        className="text-blue-400 hover:text-blue-300 hover:underline"
                      >
                        {inc.title}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={inc.severity} />
                    </TableCell>
                    <TableCell>
                      {inc.latest_state && (
                        <Badge
                          className={
                            inc.latest_state === 'fuse'
                              ? 'bg-red-950/60 text-red-300 border border-red-700'
                              : inc.latest_state === 'throttle'
                              ? 'bg-orange-950/50 text-orange-300 border border-orange-700'
                              : 'bg-gray-900/70 text-gray-200 border border-gray-700'
                          }
                        >
                          {inc.latest_state}
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{inc.event_count}</TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                      {formatRelativeTime(inc.last_seen_at)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </section>
      )}

      {/* IP Monitor Logs */}
      {(snapshot.telemetryEvents.length > 0 || snapshot.decisions.length > 0) && (
        <section className="space-y-0" id="ip-monitor-logs">
          <div className="flex items-center justify-between pb-3">
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
              IP Monitor Logs
            </h2>
            <div className="flex gap-1">
              <TabButton
                active={ipTab === 'telemetry'}
                onClick={() => setIpTab('telemetry')}
                count={snapshot.telemetryEvents.length}
              >
                Telemetry Events
              </TabButton>
              <TabButton
                active={ipTab === 'decisions'}
                onClick={() => setIpTab('decisions')}
                count={snapshot.decisions.length}
              >
                IP Decisions
              </TabButton>
            </div>
          </div>
          <div className="border-t border-border" />

          {ipTab === 'telemetry' && (
            <div className="rounded-b-xl border-x border-b border-border overflow-hidden">
              {snapshot.telemetryEvents.length === 0 ? (
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
                      <TableHead>Timestamp</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {snapshot.telemetryEvents.map((e) => (
                      <TableRow key={e.id}>
                        <TableCell className="font-mono text-sm">{e.ip}</TableCell>
                        <TableCell>
                          <Badge
                            className={
                              e.level === 'alert'
                                ? 'bg-red-950/60 text-red-300 border border-red-700'
                                : e.level === 'block'
                                ? 'bg-orange-950/50 text-orange-300 border border-orange-700'
                                : 'bg-gray-900/70 text-gray-200 border border-gray-700'
                            }
                          >
                            {e.level}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground max-w-xs truncate">
                          {e.reason}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">{e.source}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {e.country ?? '—'}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                          <p>{formatTimestamp(e.created_at)}</p>
                          <p>{formatRelativeTime(e.created_at)}</p>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </div>
          )}

          {ipTab === 'decisions' && (
            <div className="rounded-b-xl border-x border-b border-border overflow-hidden">
              {snapshot.decisions.length === 0 ? (
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
                      <TableHead>Expires</TableHead>
                      <TableHead>Timestamp</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {snapshot.decisions.map((d) => (
                      <TableRow key={d.id}>
                        <TableCell className="font-mono text-sm">{d.ip}</TableCell>
                        <TableCell>
                          <Badge
                            className={
                              d.action === 'block'
                                ? 'bg-red-950/60 text-red-300 border border-red-700'
                                : d.action === 'captcha'
                                ? 'bg-amber-950/50 text-amber-300 border border-amber-700'
                                : 'bg-gray-900/70 text-gray-200 border border-gray-700'
                            }
                          >
                            {d.action}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground max-w-xs truncate">
                          {d.reason}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">{d.source}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {d.country ?? '—'}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                          {d.expires_at ? formatRelativeTime(d.expires_at) : '—'}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                          <p>{formatTimestamp(d.created_at)}</p>
                          <p>{formatRelativeTime(d.created_at)}</p>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </div>
          )}
        </section>
      )}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  count,
  children,
}: {
  active: boolean;
  onClick: () => void;
  count: number;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
        active
          ? 'bg-white/10 text-white'
          : 'text-muted-foreground hover:text-white hover:bg-white/5'
      }`}
    >
      {children}
      <span
        className={`rounded-full px-1.5 py-0.5 text-[10px] tabular-nums ${
          active ? 'bg-white/20 text-white' : 'bg-white/5 text-muted-foreground'
        }`}
      >
        {count}
      </span>
    </button>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const cls =
    severity === 'critical'
      ? 'bg-red-950/60 text-red-300 border border-red-700'
      : severity === 'high'
      ? 'bg-orange-950/50 text-orange-300 border border-orange-700'
      : severity === 'medium'
      ? 'bg-amber-950/50 text-amber-300 border border-amber-700'
      : 'bg-gray-900/70 text-gray-200 border border-gray-700';
  return <Badge className={cls}>{severity}</Badge>;
}
