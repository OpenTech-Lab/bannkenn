'use client';

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
  fetchDashboardSnapshot,
  requestContainmentAction,
} from '@/src/features/monitoring/api';
import { DashboardSnapshot, FleetAgentSummary } from '@/src/features/monitoring/types';
import {
  agentLabel,
  buildFleetAgentSummaries,
  formatRelativeTime,
  formatTimestamp,
  isActiveContainmentState,
} from '@/src/features/monitoring/utils';
import Link from 'next/link';

const POLL_INTERVAL_MS = 30_000;

export default function FleetPage() {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null);
  const [pendingActionKey, setPendingActionKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  useEffect(() => {
    let cancelled = false;
    const refresh = async () => {
      try {
        const next = await fetchDashboardSnapshot();
        if (cancelled) return;
        startTransition(() => {
          setSnapshot(next);
          setError(null);
          setLoading(false);
          setLastUpdated(new Date());
        });
      } catch (cause) {
        if (cancelled) return;
        startTransition(() => {
          setError(cause instanceof Error ? cause.message : 'Failed to load fleet data');
          setLoading(false);
        });
      }
    };

    void refresh();
    const id = window.setInterval(() => void refresh(), POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  const summaries = useMemo(
    () => (snapshot ? buildFleetAgentSummaries(snapshot) : []),
    [snapshot]
  );

  const activeContainment = useMemo(
    () => summaries.filter((s) => (s.containment ? isActiveContainmentState(s.containment.state) : false)),
    [summaries]
  );

  async function handleAction(summary: FleetAgentSummary, commandKind: 'trigger_fuse' | 'release_fuse') {
    const key = `${summary.agent.id}:${commandKind}`;
    setPendingActionKey(key);
    try {
      await requestContainmentAction(summary.agent.id, {
        command_kind: commandKind,
        reason:
          commandKind === 'trigger_fuse'
            ? 'Manual fuse trigger from fleet view'
            : 'Manual fuse release from fleet view',
        watched_root: summary.containment?.watched_root ?? null,
        pid: summary.containment?.pid ?? null,
      });
      toast.success(
        commandKind === 'trigger_fuse'
          ? `FUSE queued for ${agentLabel(summary.agent)}`
          : `FUSE release queued for ${agentLabel(summary.agent)}`
      );
      const next = await fetchDashboardSnapshot();
      startTransition(() => {
        setSnapshot(next);
        setError(null);
        setLastUpdated(new Date());
      });
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Failed to queue action');
    } finally {
      setPendingActionKey(null);
    }
  }

  if (loading) {
    return (
      <div className="px-6 py-8">
        <p className="text-sm text-muted-foreground">Loading fleet data...</p>
      </div>
    );
  }

  return (
    <div className="px-6 py-8 space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
            Behavior Monitor
          </p>
          <h1 className="text-2xl font-bold text-white mt-2">Fleet & Containment</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Per-host containment state, threat heatmap, and manual FUSE controls.
          </p>
        </div>
        {lastUpdated && (
          <p className="text-xs text-muted-foreground">
            Updated {lastUpdated.toLocaleTimeString()}
          </p>
        )}
      </div>

      {error && (
        <div className="rounded-xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Metric cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Agents</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-white">
            {snapshot?.agents.length ?? 0}
          </p>
        </div>
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Online</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-emerald-400">
            {snapshot?.agents.filter((a) => a.status === 'online').length ?? 0}
          </p>
        </div>
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Active Containment</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-orange-400">
            {activeContainment.length}
          </p>
        </div>
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
            Server Health
          </p>
          <p className={`mt-3 text-3xl font-semibold ${snapshot?.health.status === 'ok' ? 'text-emerald-400' : 'text-red-400'}`}>
            {snapshot?.health.status === 'ok' ? 'OK' : 'Error'}
          </p>
        </div>
      </div>

      {/* Fleet containment table */}
      <section className="rounded-xl border border-border bg-card p-5 space-y-4">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
          Containment Status Panel
        </h2>
        {summaries.length === 0 ? (
          <p className="text-sm text-muted-foreground">No agents are registered yet.</p>
        ) : (
          <div className="grid gap-4 lg:grid-cols-2">
            {summaries.map((summary) => {
              const state = summary.containment?.state ?? 'normal';
              const triggerKey = `${summary.agent.id}:trigger_fuse`;
              const releaseKey = `${summary.agent.id}:release_fuse`;

              return (
                <div
                  key={summary.agent.id}
                  className="rounded-xl border border-gray-800 bg-gray-900/40 p-4 space-y-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <Link
                          href={`/behavior/agents/${summary.agent.id}`}
                          className="font-semibold text-white hover:text-blue-400 transition-colors"
                        >
                          {agentLabel(summary.agent)}
                        </Link>
                        <Badge
                          className={
                            summary.agent.status === 'online'
                              ? 'bg-emerald-950/50 text-emerald-300 border border-emerald-700'
                              : 'bg-red-950/50 text-red-300 border border-red-700'
                          }
                        >
                          {summary.agent.status}
                        </Badge>
                        <Badge
                          className={
                            state === 'fuse'
                              ? 'bg-red-950/60 text-red-300 border border-red-700'
                              : state === 'throttle'
                              ? 'bg-orange-950/50 text-orange-300 border border-orange-700'
                              : state === 'suspicious'
                              ? 'bg-amber-950/50 text-amber-300 border border-amber-700'
                              : 'bg-gray-900/70 text-gray-200 border border-gray-700'
                          }
                        >
                          {state}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {summary.containment?.reason ?? 'No containment transition recorded.'}
                      </p>
                    </div>
                    <div className="text-right text-xs text-muted-foreground">
                      <p>{formatTimestamp(summary.containment?.updated_at ?? summary.agent.last_seen_at)}</p>
                      <p>{formatRelativeTime(summary.containment?.updated_at ?? summary.agent.last_seen_at)}</p>
                    </div>
                  </div>

                  {/* State track */}
                  <div className="grid grid-cols-4 gap-2">
                    {(['normal', 'suspicious', 'throttle', 'fuse'] as const).map((step, i) => {
                      const activeIndex = Math.max(['normal', 'suspicious', 'throttle', 'fuse'].indexOf(state), 0);
                      const isActive = i <= activeIndex;
                      return (
                        <div key={step} className="space-y-1">
                          <div
                            className={`h-1.5 rounded-full ${
                              isActive
                                ? step === 'fuse'
                                  ? 'bg-red-500'
                                  : step === 'throttle'
                                  ? 'bg-orange-500'
                                  : step === 'suspicious'
                                  ? 'bg-amber-500'
                                  : 'bg-gray-500'
                                : 'bg-gray-800'
                            }`}
                          />
                          <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                            {step}
                          </p>
                        </div>
                      );
                    })}
                  </div>

                  <div className="grid grid-cols-3 gap-3 text-xs text-muted-foreground">
                    <div>
                      <p className="text-gray-500">Root</p>
                      <p className="text-gray-300 truncate mt-0.5">
                        {summary.containment?.watched_root ?? 'Awaiting'}
                      </p>
                    </div>
                    <div>
                      <p className="text-gray-500">Score</p>
                      <p className="text-gray-300 mt-0.5">{summary.containment?.score ?? 0}</p>
                    </div>
                    <div>
                      <p className="text-gray-500">Incidents</p>
                      <p className="text-gray-300 mt-0.5">{summary.incidentCount}</p>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <Button
                      size="sm"
                      variant="destructive"
                      disabled={pendingActionKey === triggerKey || state === 'fuse'}
                      onClick={() => void handleAction(summary, 'trigger_fuse')}
                    >
                      {pendingActionKey === triggerKey ? 'Queuing...' : 'Trigger FUSE'}
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={pendingActionKey === releaseKey || state !== 'fuse'}
                      onClick={() => void handleAction(summary, 'release_fuse')}
                    >
                      {pendingActionKey === releaseKey ? 'Queuing...' : 'Release FUSE'}
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Active containment list */}
      {activeContainment.length > 0 && (
        <section className="rounded-xl border border-border bg-card p-5 space-y-4">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
            Active Throttling / FUSE
          </h2>
          <div className="rounded-lg border border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Agent</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Root</TableHead>
                  <TableHead className="text-right">Score</TableHead>
                  <TableHead>Since</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {activeContainment.map((s) => (
                  <TableRow key={s.agent.id}>
                    <TableCell className="font-medium">
                      <Link
                        href={`/behavior/agents/${s.agent.id}`}
                        className="text-blue-400 hover:text-blue-300 hover:underline"
                      >
                        {agentLabel(s.agent)}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <Badge
                        className={
                          s.containment?.state === 'fuse'
                            ? 'bg-red-950/60 text-red-300 border border-red-700'
                            : 'bg-orange-950/50 text-orange-300 border border-orange-700'
                        }
                      >
                        {s.containment?.state}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground max-w-xs truncate">
                      {s.containment?.reason}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {s.containment?.watched_root}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {s.containment?.score}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                      {formatRelativeTime(s.containment?.updated_at)}
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
