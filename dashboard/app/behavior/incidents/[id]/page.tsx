'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
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
import { fetchIncidentDetailSnapshot } from '@/src/features/monitoring/api';
import { IncidentDetailSnapshot } from '@/src/features/monitoring/types';
import {
  agentLabel,
  formatRelativeTime,
  formatTimestamp,
} from '@/src/features/monitoring/utils';

export default function BehaviorIncidentDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params?.id;
  const [snapshot, setSnapshot] = useState<IncidentDetailSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    const refresh = async () => {
      try {
        const next = await fetchIncidentDetailSnapshot(id);
        if (cancelled) return;
        startTransition(() => {
          setSnapshot(next);
          setError(null);
          setLoading(false);
        });
      } catch (cause) {
        if (cancelled) return;
        startTransition(() => {
          setError(cause instanceof Error ? cause.message : 'Failed to load incident');
          setLoading(false);
        });
      }
    };
    void refresh();
    return () => { cancelled = true; };
  }, [id]);

  const incident = snapshot?.detail.incident;

  const relatedAgents = useMemo(() => {
    if (!snapshot || !incident) return [];
    return snapshot.agents.filter((a) => incident.affected_agents.includes(a.name));
  }, [snapshot, incident]);

  if (loading) {
    return (
      <div className="px-6 py-8">
        <p className="text-sm text-muted-foreground">Loading incident detail...</p>
      </div>
    );
  }

  if (error && !snapshot) {
    return (
      <div className="px-6 py-8 space-y-4">
        <div className="rounded-xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
        <Link href="/behavior/incidents" className="text-sm text-blue-400 hover:text-blue-300">
          Back to incidents
        </Link>
      </div>
    );
  }

  if (!snapshot || !incident) return null;

  return (
    <div className="px-6 py-8 space-y-6">
      <div>
        <Link href="/behavior/incidents" className="text-sm text-blue-400 hover:text-blue-300">
          Back to incidents
        </Link>
        <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground mt-4">
          Incident Detail
        </p>
        <h1 className="text-2xl font-bold text-white mt-2">{incident.title}</h1>
        <p className="text-sm text-muted-foreground mt-1 max-w-2xl">{incident.summary}</p>
        <div className="flex flex-wrap gap-2 mt-3">
          <SeverityBadge severity={incident.severity} />
          {incident.latest_state && (
            <Badge
              className={
                incident.latest_state === 'fuse'
                  ? 'bg-red-950/60 text-red-300 border border-red-700'
                  : incident.latest_state === 'throttle'
                  ? 'bg-orange-950/50 text-orange-300 border border-orange-700'
                  : 'bg-gray-900/70 text-gray-200 border border-gray-700'
              }
            >
              {incident.latest_state}
            </Badge>
          )}
          {incident.cross_agent && (
            <Badge variant="secondary" className="text-xs">Cross-agent</Badge>
          )}
        </div>
      </div>

      {/* Metric cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Events</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-white">{incident.event_count}</p>
        </div>
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Agents</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-orange-400">{incident.correlated_agent_count}</p>
          <p className="text-xs text-muted-foreground mt-1">
            {incident.cross_agent ? 'Cross-agent correlated' : 'Single-host'}
          </p>
        </div>
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Alerts</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-red-400">{incident.alert_count}</p>
          <p className="text-xs text-muted-foreground mt-1">
            First seen {formatRelativeTime(incident.first_seen_at)}
          </p>
        </div>
        <div className="rounded-xl border border-border bg-card px-4 py-4">
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Latest Score</p>
          <p className="mt-3 text-3xl font-semibold tabular-nums text-emerald-400">{incident.latest_score}</p>
          <p className="text-xs text-muted-foreground mt-1">{incident.status}</p>
        </div>
      </div>

      {/* Affected scope */}
      <div className="grid gap-4 lg:grid-cols-2">
        <section className="rounded-xl border border-border bg-card p-5 space-y-4">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
            Affected Agents
          </h2>
          <div className="flex flex-wrap gap-2">
            {relatedAgents.map((agent) => (
              <Link
                key={agent.id}
                href={`/agents/${agent.id}`}
                className="rounded-lg border border-gray-800 bg-gray-900/40 px-3 py-1.5 text-sm text-gray-200 hover:border-gray-600 hover:text-blue-400 transition-colors"
              >
                {agentLabel(agent)}
              </Link>
            ))}
          </div>
        </section>

        <section className="rounded-xl border border-border bg-card p-5 space-y-4">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
            Watched Roots
          </h2>
          <div className="space-y-2">
            {incident.affected_roots.map((root) => (
              <div
                key={root}
                className="rounded-lg border border-gray-800 bg-gray-900/40 px-3 py-2 text-sm text-gray-300 font-mono"
              >
                {root}
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* Last seen info */}
      <section className="rounded-xl border border-border bg-card p-5 space-y-2">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
          Timing
        </h2>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="rounded-lg border border-border/70 bg-background/40 px-4 py-3">
            <p className="text-xs uppercase tracking-[0.25em] text-muted-foreground">First Seen</p>
            <p className="mt-2 text-sm text-white">{formatTimestamp(incident.first_seen_at)}</p>
            <p className="text-xs text-muted-foreground">{formatRelativeTime(incident.first_seen_at)}</p>
          </div>
          <div className="rounded-lg border border-border/70 bg-background/40 px-4 py-3">
            <p className="text-xs uppercase tracking-[0.25em] text-muted-foreground">Last Seen</p>
            <p className="mt-2 text-sm text-white">{formatTimestamp(incident.last_seen_at)}</p>
            <p className="text-xs text-muted-foreground">{formatRelativeTime(incident.last_seen_at)}</p>
          </div>
        </div>
      </section>

      {/* Timeline */}
      {snapshot.detail.timeline.length > 0 && (
        <section className="space-y-0">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em] pb-3">
            Event Timeline
          </h2>
          <div className="border-t border-border" />
          <div className="rounded-b-xl border-x border-b border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Severity</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Agent</TableHead>
                  <TableHead>Message</TableHead>
                  <TableHead>Root</TableHead>
                  <TableHead>Timestamp</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {snapshot.detail.timeline.map((entry) => {
                  const agentId = snapshot.agents.find((a) => a.name === entry.agent_name)?.id;
                  return (
                    <TableRow key={entry.id}>
                      <TableCell>
                        <SeverityBadge severity={entry.severity} />
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {entry.source_type.replace(/_/g, ' ')}
                      </TableCell>
                      <TableCell>
                        {agentId ? (
                          <Link
                            href={`/agents/${agentId}`}
                            className="text-blue-400 hover:text-blue-300 hover:underline text-sm"
                          >
                            {entry.agent_name}
                          </Link>
                        ) : (
                          <span className="text-sm text-muted-foreground">{entry.agent_name}</span>
                        )}
                      </TableCell>
                      <TableCell className="text-sm text-white max-w-sm">
                        {entry.message}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground font-mono">
                        {entry.watched_root}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                        <p>{formatTimestamp(entry.created_at)}</p>
                        <p>{formatRelativeTime(entry.created_at)}</p>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </section>
      )}
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
