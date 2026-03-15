'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { startTransition, useEffect, useMemo, useState } from 'react';
import { fetchIncidentDetailSnapshot } from '@/src/features/monitoring/api';
import { IncidentTimeline } from '@/src/features/monitoring/components/incident-timeline';
import { MetricCard, SectionPanel } from '@/src/features/monitoring/components/panel';
import {
  ContainmentStateBadge,
  SeverityBadge,
} from '@/src/features/monitoring/components/status-badge';
import { IncidentDetailSnapshot } from '@/src/features/monitoring/types';
import { formatRelativeTime, formatTimestamp } from '@/src/features/monitoring/utils';

export function IncidentDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params?.id;
  const [snapshot, setSnapshot] = useState<IncidentDetailSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id) {
      return;
    }

    let cancelled = false;

    const refresh = async () => {
      try {
        const next = await fetchIncidentDetailSnapshot(id);
        if (cancelled) {
          return;
        }
        startTransition(() => {
          setSnapshot(next);
          setError(null);
          setLoading(false);
        });
      } catch (cause) {
        if (cancelled) {
          return;
        }
        const message =
          cause instanceof Error ? cause.message : 'Failed to load the incident detail view';
        startTransition(() => {
          setError(message);
          setLoading(false);
        });
      }
    };

    void refresh();

    return () => {
      cancelled = true;
    };
  }, [id]);

  const incident = snapshot?.detail.incident;

  const relatedAgents = useMemo(() => {
    if (!snapshot || !incident) {
      return [];
    }

    return snapshot.agents.filter((agent) => incident.affected_agents.includes(agent.name));
  }, [snapshot, incident]);

  if (loading && !snapshot) {
    return <div className="px-6 py-10 text-sm text-slate-400">Loading incident detail…</div>;
  }

  if (error && !snapshot) {
    return (
      <div className="px-6 py-10 space-y-4">
        <p className="text-sm text-red-300">{error}</p>
        <Link href="/behavior/incidents" className="text-sm text-sky-300 transition-colors hover:text-sky-200">
          Back to incidents
        </Link>
      </div>
    );
  }

  if (!snapshot || !incident) {
    return null;
  }

  return (
    <div className="px-6 py-10 space-y-8">
      <div className="space-y-4">
        <Link href="/behavior/incidents" className="text-sm text-sky-300 transition-colors hover:text-sky-200">
          Back to incidents
        </Link>
        <div className="flex flex-wrap items-start justify-between gap-6">
          <div className="space-y-3">
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-500">
              Incident detail
            </p>
            <h1 className="text-4xl font-semibold tracking-tight text-white">{incident.title}</h1>
            <p className="max-w-3xl text-sm text-slate-400">{incident.summary}</p>
            <div className="flex flex-wrap gap-2">
              <SeverityBadge severity={incident.severity} />
              {incident.latest_state ? (
                <ContainmentStateBadge state={incident.latest_state} />
              ) : null}
            </div>
          </div>
          <div className="rounded-2xl border border-white/10 bg-black/60 p-4 text-sm text-slate-300">
            <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500">
              Last seen
            </p>
            <p className="mt-2">{formatTimestamp(incident.last_seen_at)}</p>
            <p className="text-xs text-slate-500">{formatRelativeTime(incident.last_seen_at)}</p>
          </div>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Events" value={incident.event_count} />
        <MetricCard
          label="Agents"
          value={incident.correlated_agent_count}
          detail={incident.cross_agent ? 'Cross-agent correlated incident' : 'Single-host incident'}
          accent="amber"
        />
        <MetricCard
          label="Alerts"
          value={incident.alert_count}
          detail={`First seen ${formatRelativeTime(incident.first_seen_at)}`}
          accent="red"
        />
        <MetricCard
          label="Latest score"
          value={incident.latest_score}
          detail={incident.status}
          accent="emerald"
        />
      </div>

      {error ? (
        <div className="rounded-2xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}

      <div className="grid gap-6 xl:grid-cols-[0.8fr_1.2fr]">
        <SectionPanel
          eyebrow="Impact"
          title="Affected scope"
          description="Hosts and watched roots attached to this incident."
        >
          <div className="space-y-4">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500">
                Agents
              </p>
              <div className="mt-2 flex flex-wrap gap-2">
                {relatedAgents.map((agent) => (
                  <Link
                    key={agent.id}
                    href={`/behavior/agents/${agent.id}`}
                    className="rounded-full border border-white/10 px-3 py-1 text-sm text-slate-200 transition-colors hover:border-sky-400/40 hover:text-sky-200"
                  >
                    {agent.nickname?.trim() || agent.name}
                  </Link>
                ))}
              </div>
            </div>
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500">
                Watched roots
              </p>
              <div className="mt-2 space-y-2">
                {incident.affected_roots.map((root) => (
                  <div
                    key={root}
                    className="rounded-2xl border border-white/10 bg-black/60 px-3 py-2 text-sm text-slate-300"
                  >
                    {root}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </SectionPanel>

        <IncidentTimeline timeline={snapshot.detail.timeline} agents={snapshot.agents} />
      </div>
    </div>
  );
}
