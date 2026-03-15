'use client';

import Link from 'next/link';
import { startTransition, useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { fetchDashboardSnapshot } from '@/src/features/monitoring/api';
import { DashboardSnapshot } from '@/src/features/monitoring/types';
import { formatRelativeTime } from '@/src/features/monitoring/utils';

export default function BehaviorIncidentsPage() {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null);
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
          setError(cause instanceof Error ? cause.message : 'Failed to load incidents');
          setLoading(false);
        });
      }
    };
    void refresh();
    return () => { cancelled = true; };
  }, []);

  const incidents = snapshot?.incidents ?? [];
  const criticalCount = incidents.filter((i) => i.severity === 'critical').length;
  const crossAgentCount = incidents.filter((i) => i.cross_agent).length;

  if (loading) {
    return (
      <div className="max-w-6xl mx-auto px-4 py-8">
        <p className="text-sm text-muted-foreground">Loading incidents...</p>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
            Behavior Monitor
          </p>
          <h1 className="text-2xl font-bold text-white mt-2">Incidents</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Timeline-backed incident summaries derived from behavior and containment telemetry.
          </p>
        </div>
        {lastUpdated && (
          <p className="text-xs text-muted-foreground">
            Updated {formatRelativeTime(lastUpdated.toISOString())}
          </p>
        )}
      </div>

      {error && (
        <div className="rounded-xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Metric cards */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Total Incidents</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-red-400">{incidents.length}</p>
        </div>
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Critical</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-orange-400">{criticalCount}</p>
        </div>
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Cross-Agent</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-emerald-400">{crossAgentCount}</p>
        </div>
      </div>

      {/* Incidents table */}
      <section className="rounded-xl border border-border bg-card p-5 space-y-4">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
          Incident Backlog
        </h2>
        {incidents.length === 0 ? (
          <div className="rounded-xl border border-dashed border-border bg-card/20 px-6 py-12 text-center">
            <h3 className="text-lg font-semibold text-white">No incidents yet</h3>
            <p className="text-sm text-muted-foreground mt-2">
              No incidents have been reconstructed yet.
            </p>
          </div>
        ) : (
          <div className="rounded-lg border border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Title</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>Agents</TableHead>
                  <TableHead>Roots</TableHead>
                  <TableHead className="text-right">Events</TableHead>
                  <TableHead className="text-right">Alerts</TableHead>
                  <TableHead>Last Seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {incidents.map((inc) => (
                  <TableRow key={inc.id}>
                    <TableCell className="font-medium max-w-xs">
                      <Link
                        href={`/behavior/incidents/${inc.id}`}
                        className="text-blue-400 hover:text-blue-300 hover:underline"
                      >
                        {inc.title}
                      </Link>
                      <p className="text-xs text-muted-foreground mt-0.5 truncate">
                        {inc.summary}
                      </p>
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
                    <TableCell className="text-sm text-muted-foreground">
                      {inc.affected_agents.join(', ') || 'none'}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground max-w-xs truncate">
                      {inc.affected_roots.join(', ') || 'none'}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{inc.event_count}</TableCell>
                    <TableCell className="text-right tabular-nums">{inc.alert_count}</TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                      {formatRelativeTime(inc.last_seen_at)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>
    </div>
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
