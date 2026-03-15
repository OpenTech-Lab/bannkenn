'use client';

import Link from 'next/link';
import { startTransition, useEffect, useMemo, useState } from 'react';
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
import {
  buildFleetAgentSummaries,
  formatRelativeTime,
  summarizeAlertCount,
} from '@/src/features/monitoring/utils';

const POLL_INTERVAL_MS = 10_000;

export default function BehaviorOverview() {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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
        });
      } catch (cause) {
        if (cancelled) return;
        startTransition(() => {
          setError(cause instanceof Error ? cause.message : 'Failed to load data');
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

  const behaviorSpikeCount =
    snapshot?.behaviorEvents.filter((e) => e.level !== 'observed').length ?? 0;
  const elevatedAlertCount = snapshot ? summarizeAlertCount(snapshot.alerts) : 0;
  const onlineAgents = snapshot?.agents.filter((a) => a.status === 'online').length ?? 0;

  if (loading) {
    return (
      <div className="max-w-6xl mx-auto px-4 py-8">
        <p className="text-sm text-muted-foreground">Loading behavior overview...</p>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-6">
      <div>
        <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
          Behavior Monitor
        </p>
        <h1 className="text-2xl font-bold text-white mt-2">Behavior & Containment Overview</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Fleet-wide behavior monitoring, containment status, and incident tracking.
        </p>
      </div>

      {error && (
        <div className="rounded-xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Metric cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <StatCard label="Agents" value={snapshot?.agents.length ?? 0} />
        <StatCard label="Online" value={onlineAgents} accent="green" />
        <StatCard
          label="Active containment"
          value={summaries.filter((s) => s.containment?.state === 'throttle' || s.containment?.state === 'fuse').length}
          accent="orange"
        />
        <StatCard label="Incidents" value={snapshot?.incidents.length ?? 0} accent="red" />
        <StatCard label="Behavior spikes" value={behaviorSpikeCount} accent="yellow" />
      </div>

      {/* Quick navigation */}
      <div className="grid gap-4 sm:grid-cols-2">
        <NavCard
          href="/behavior/fleet"
          title="Fleet & Containment"
          description="Per-host containment state, threat heatmap, and manual FUSE controls."
        />
        <NavCard
          href="/behavior/incidents"
          title="Incidents"
          description={`${snapshot?.incidents.length ?? 0} incidents reconstructed from behavior and containment telemetry.`}
        />
      </div>

      {/* Agent fleet table */}
      {summaries.length > 0 && (
        <section className="rounded-xl border border-border bg-card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
              Fleet Status
            </h2>
            <Link href="/behavior/fleet" className="text-sm text-blue-400 hover:text-blue-300">
              Full view
            </Link>
          </div>
          <div className="rounded-lg border border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Agent</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Containment</TableHead>
                  <TableHead className="text-right">Heat</TableHead>
                  <TableHead className="text-right">Incidents</TableHead>
                  <TableHead className="text-right">Alerts</TableHead>
                  <TableHead>Last Seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {summaries.slice(0, 8).map((s) => (
                  <TableRow key={s.agent.id}>
                    <TableCell className="font-medium">
                      <Link
                        href={`/behavior/agents/${s.agent.id}`}
                        className="text-blue-400 hover:text-blue-300 hover:underline"
                      >
                        {s.agent.nickname?.trim() || s.agent.name}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <Badge
                        className={
                          s.agent.status === 'online'
                            ? 'bg-emerald-950/50 text-emerald-300 border border-emerald-700'
                            : s.agent.status === 'offline'
                            ? 'bg-red-950/50 text-red-300 border border-red-700'
                            : 'bg-gray-900/70 text-gray-300 border border-gray-700'
                        }
                      >
                        {s.agent.status}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge
                        className={
                          s.containment?.state === 'fuse'
                            ? 'bg-red-950/60 text-red-300 border border-red-700'
                            : s.containment?.state === 'throttle'
                            ? 'bg-orange-950/50 text-orange-300 border border-orange-700'
                            : s.containment?.state === 'suspicious'
                            ? 'bg-amber-950/50 text-amber-300 border border-amber-700'
                            : 'bg-gray-900/70 text-gray-200 border border-gray-700'
                        }
                      >
                        {s.containment?.state ?? 'normal'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      <span
                        className={
                          s.heat >= 85
                            ? 'text-red-400'
                            : s.heat >= 60
                            ? 'text-orange-400'
                            : s.heat >= 35
                            ? 'text-amber-400'
                            : 'text-gray-300'
                        }
                      >
                        {s.heat}
                      </span>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{s.incidentCount}</TableCell>
                    <TableCell className="text-right tabular-nums">{s.alertCount}</TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                      {s.agent.last_seen_at ? formatRelativeTime(s.agent.last_seen_at) : 'Never'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </section>
      )}

      {/* Recent incidents */}
      {(snapshot?.incidents.length ?? 0) > 0 && (
        <section className="rounded-xl border border-border bg-card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
              Recent Incidents
            </h2>
            <Link href="/behavior/incidents" className="text-sm text-blue-400 hover:text-blue-300">
              View all
            </Link>
          </div>
          <div className="rounded-lg border border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Title</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Agents</TableHead>
                  <TableHead className="text-right">Events</TableHead>
                  <TableHead>Last Seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {snapshot?.incidents.slice(0, 5).map((inc) => (
                  <TableRow key={inc.id}>
                    <TableCell className="font-medium">
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
                    <TableCell className="text-sm text-muted-foreground">
                      {inc.affected_agents.join(', ') || 'none'}
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

      <p className="text-center text-xs text-muted-foreground">
        Auto-refreshes every {POLL_INTERVAL_MS / 1000}s · {elevatedAlertCount} elevated alerts
      </p>
    </div>
  );
}

function StatCard({
  label,
  value,
  accent = 'gray',
}: {
  label: string;
  value: number;
  accent?: 'gray' | 'red' | 'green' | 'orange' | 'yellow';
}) {
  const accentClass =
    accent === 'red'
      ? 'text-red-400'
      : accent === 'green'
      ? 'text-emerald-400'
      : accent === 'orange'
      ? 'text-orange-400'
      : accent === 'yellow'
      ? 'text-yellow-400'
      : 'text-white';

  return (
    <div className="rounded-xl border border-border bg-card px-4 py-4">
      <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">{label}</p>
      <p className={`mt-3 text-3xl font-semibold tabular-nums ${accentClass}`}>{value}</p>
    </div>
  );
}

function NavCard({
  href,
  title,
  description,
}: {
  href: string;
  title: string;
  description: string;
}) {
  return (
    <Link
      href={href}
      className="rounded-xl border border-gray-800 bg-gray-900/40 p-5 hover:border-gray-600 hover:bg-gray-900/70 transition-all group block"
    >
      <h3 className="font-semibold text-white group-hover:text-blue-400 transition-colors">
        {title}
      </h3>
      <p className="text-xs text-gray-500 mt-2 leading-relaxed">{description}</p>
    </Link>
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
