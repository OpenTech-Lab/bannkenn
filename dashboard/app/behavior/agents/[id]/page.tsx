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
import {
  fetchAgentDetailSnapshot,
  requestContainmentAction,
} from '@/src/features/monitoring/api';
import { AgentDetailSnapshot } from '@/src/features/monitoring/types';
import {
  agentLabel,
  formatRelativeTime,
  formatTimestamp,
} from '@/src/features/monitoring/utils';

const POLL_INTERVAL_MS = 10_000;

export default function BehaviorAgentDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params?.id;
  const [snapshot, setSnapshot] = useState<AgentDetailSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [pendingActionKey, setPendingActionKey] = useState<string | null>(null);

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
          setError(cause instanceof Error ? cause.message : 'Failed to load agent');
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
  const pendingActions = snapshot?.containmentActions.filter((a) => a.status === 'pending').length ?? 0;
  const elevatedBehavior = snapshot?.behaviorEvents.filter((e) => e.level !== 'observed').length ?? 0;
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
        reason: commandKind === 'trigger_fuse'
          ? 'Manual fuse trigger from agent detail'
          : 'Manual fuse release from agent detail',
        watched_root: currentContainment?.watched_root ?? null,
        pid: currentContainment?.pid ?? null,
      });
      toast.success(
        commandKind === 'trigger_fuse'
          ? `FUSE queued for ${agentLabel(snapshot.agent)}`
          : `FUSE release queued for ${agentLabel(snapshot.agent)}`
      );
      const next = await fetchAgentDetailSnapshot(id ?? String(snapshot.agent.id));
      startTransition(() => { setSnapshot(next); setError(null); });
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Failed to queue action');
    } finally {
      setPendingActionKey(null);
    }
  }

  if (loading) {
    return (
      <div className="max-w-6xl mx-auto px-4 py-8">
        <p className="text-sm text-muted-foreground">Loading agent detail...</p>
      </div>
    );
  }

  if (error && !snapshot) {
    return (
      <div className="max-w-6xl mx-auto px-4 py-8 space-y-4">
        <div className="rounded-xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
        <Link href="/behavior" className="text-sm text-blue-400 hover:text-blue-300">
          Back to overview
        </Link>
      </div>
    );
  }

  if (!snapshot) return null;

  const state = currentContainment?.state ?? 'normal';

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-6">
      {/* Header */}
      <div>
        <Link href="/behavior/fleet" className="text-sm text-blue-400 hover:text-blue-300">
          Back to fleet
        </Link>
        <div className="flex flex-wrap items-start justify-between gap-4 mt-4">
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Agent Detail</p>
            <h1 className="text-2xl font-bold text-white mt-2">{agentLabel(snapshot.agent)}</h1>
            <p className="text-sm text-muted-foreground mt-1">
              Registered {formatTimestamp(snapshot.agent.created_at)} · last seen{' '}
              {formatTimestamp(snapshot.agent.last_seen_at)}
            </p>
            <div className="flex flex-wrap gap-2 mt-2">
              <Badge
                className={
                  snapshot.agent.status === 'online'
                    ? 'bg-emerald-950/50 text-emerald-300 border border-emerald-700'
                    : 'bg-red-950/50 text-red-300 border border-red-700'
                }
              >
                {snapshot.agent.status}
              </Badge>
              <StateBadge state={state} />
            </div>
          </div>
          <div className="rounded-xl border border-border bg-card p-4 space-y-2">
            <p className="text-xs uppercase tracking-[0.25em] text-muted-foreground">
              Manual Containment
            </p>
            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                variant="destructive"
                disabled={pendingActionKey === `${snapshot.agent.id}:trigger_fuse` || state === 'fuse'}
                onClick={() => void handleAction('trigger_fuse')}
              >
                {pendingActionKey === `${snapshot.agent.id}:trigger_fuse` ? 'Queuing...' : 'Trigger FUSE'}
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={pendingActionKey === `${snapshot.agent.id}:release_fuse` || state !== 'fuse'}
                onClick={() => void handleAction('release_fuse')}
              >
                {pendingActionKey === `${snapshot.agent.id}:release_fuse` ? 'Queuing...' : 'Release FUSE'}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              {currentContainment
                ? `Root ${currentContainment.watched_root} · score ${currentContainment.score}`
                : 'No containment transitions recorded yet'}
            </p>
          </div>
        </div>
      </div>

      {/* Metric cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Behavior Events</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-white">{snapshot.behaviorEvents.length}</p>
        </div>
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Elevated</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-orange-400">{elevatedBehavior}</p>
        </div>
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Containment Changes</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-red-400">{snapshot.containmentEvents.length}</p>
        </div>
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Queued Actions</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-emerald-400">{pendingActions}</p>
          <p className="text-xs text-muted-foreground mt-1">{snapshot.relatedIncidents.length} related incidents</p>
        </div>
      </div>

      {/* Containment state */}
      <section className="rounded-xl border border-border bg-card p-5 space-y-4">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
          Current Containment State
        </h2>
        <div className="grid grid-cols-4 gap-2">
          {(['normal', 'suspicious', 'throttle', 'fuse'] as const).map((step, i) => {
            const activeIndex = Math.max(['normal', 'suspicious', 'throttle', 'fuse'].indexOf(state), 0);
            const isActive = i <= activeIndex;
            return (
              <div key={step} className="space-y-1">
                <div className={`h-1.5 rounded-full ${isActive
                  ? step === 'fuse' ? 'bg-red-500' : step === 'throttle' ? 'bg-orange-500' : step === 'suspicious' ? 'bg-amber-500' : 'bg-gray-500'
                  : 'bg-gray-800'
                }`} />
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground">{step}</p>
              </div>
            );
          })}
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="rounded-lg border border-border/70 bg-background/40 px-4 py-3">
            <p className="text-xs uppercase tracking-[0.25em] text-muted-foreground">Watched Root</p>
            <p className="mt-2 text-sm text-white">{currentContainment?.watched_root ?? 'Not available'}</p>
          </div>
          <div className="rounded-lg border border-border/70 bg-background/40 px-4 py-3">
            <p className="text-xs uppercase tracking-[0.25em] text-muted-foreground">Last Transition</p>
            <p className="mt-2 text-sm text-white">
              {currentContainment ? formatTimestamp(currentContainment.created_at) : 'Never'}
            </p>
          </div>
        </div>
      </section>

      {/* Action history */}
      {actionHistory.length > 0 && (
        <section className="rounded-xl border border-border bg-card p-5 space-y-4">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
            Operator Action Queue
          </h2>
          <div className="rounded-lg border border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Command</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Result</TableHead>
                  <TableHead>Timestamp</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {actionHistory.map((action) => (
                  <TableRow key={action.id}>
                    <TableCell className="font-medium">{action.command_kind.replace('_', ' ')}</TableCell>
                    <TableCell className="text-sm text-muted-foreground max-w-xs truncate">{action.reason}</TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="text-xs">{action.status}</Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground max-w-xs truncate">
                      {action.result_message ?? 'Awaiting acknowledgement'}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                      {formatTimestamp(action.executed_at ?? action.updated_at)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </section>
      )}

      {/* Containment history */}
      {containmentHistory.length > 0 && (
        <section className="rounded-xl border border-border bg-card p-5 space-y-4">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
            Containment History
          </h2>
          <div className="rounded-lg border border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>State</TableHead>
                  <TableHead>Previous</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Root</TableHead>
                  <TableHead className="text-right">Score</TableHead>
                  <TableHead>Timestamp</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {containmentHistory.map((event) => (
                  <TableRow key={event.id}>
                    <TableCell><StateBadge state={event.state} /></TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {event.previous_state ?? '—'}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground max-w-xs truncate">
                      {event.reason}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground font-mono">
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
          </div>
        </section>
      )}

      {/* Behavior events */}
      {behaviorEvents.length > 0 && (
        <section className="rounded-xl border border-border bg-card p-5 space-y-4">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
            Behavior Events
          </h2>
          <div className="rounded-lg border border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Process</TableHead>
                  <TableHead>Level</TableHead>
                  <TableHead>Reasons</TableHead>
                  <TableHead>Root</TableHead>
                  <TableHead className="text-right">Score</TableHead>
                  <TableHead>Timestamp</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {behaviorEvents.map((event) => (
                  <TableRow key={event.id}>
                    <TableCell className="font-medium">
                      {event.process_name ?? event.exe_path ?? 'unknown'}
                    </TableCell>
                    <TableCell>
                      <Badge
                        className={
                          event.level === 'fuse_candidate'
                            ? 'bg-red-950/60 text-red-300 border border-red-700'
                            : event.level === 'throttle_candidate'
                            ? 'bg-orange-950/50 text-orange-300 border border-orange-700'
                            : event.level === 'suspicious'
                            ? 'bg-amber-950/50 text-amber-300 border border-amber-700'
                            : 'bg-gray-900/70 text-gray-200 border border-gray-700'
                        }
                      >
                        {event.level}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground max-w-xs truncate">
                      {event.reasons.join(', ') || event.level}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground font-mono">
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
          </div>
        </section>
      )}

      {/* Related incidents */}
      {snapshot.relatedIncidents.length > 0 && (
        <section className="rounded-xl border border-border bg-card p-5 space-y-4">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
            Related Incidents
          </h2>
          <div className="rounded-lg border border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Title</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead className="text-right">Events</TableHead>
                  <TableHead>Last Seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {snapshot.relatedIncidents.slice(0, 8).map((inc) => (
                  <TableRow key={inc.id}>
                    <TableCell className="font-medium">
                      <Link
                        href={`/behavior/incidents/${inc.id}`}
                        className="text-blue-400 hover:text-blue-300 hover:underline"
                      >
                        {inc.title}
                      </Link>
                    </TableCell>
                    <TableCell><SeverityBadge severity={inc.severity} /></TableCell>
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
    </div>
  );
}

function StateBadge({ state }: { state: string }) {
  const cls =
    state === 'fuse'
      ? 'bg-red-950/60 text-red-300 border border-red-700'
      : state === 'throttle'
      ? 'bg-orange-950/50 text-orange-300 border border-orange-700'
      : state === 'suspicious'
      ? 'bg-amber-950/50 text-amber-300 border border-amber-700'
      : 'bg-gray-900/70 text-gray-200 border border-gray-700';
  return <Badge className={cls}>{state.replace(/_/g, ' ')}</Badge>;
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
