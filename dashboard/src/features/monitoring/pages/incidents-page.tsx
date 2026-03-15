'use client';

import Link from 'next/link';
import { startTransition, useEffect, useState } from 'react';
import { fetchDashboardSnapshot } from '@/src/features/monitoring/api';
import { IncidentList } from '@/src/features/monitoring/components/incident-list';
import { MetricCard } from '@/src/features/monitoring/components/panel';
import { DashboardSnapshot } from '@/src/features/monitoring/types';
import { formatRelativeTime } from '@/src/features/monitoring/utils';

export function IncidentsPage() {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  useEffect(() => {
    let cancelled = false;

    const refresh = async () => {
      try {
        const next = await fetchDashboardSnapshot();
        if (cancelled) {
          return;
        }
        startTransition(() => {
          setSnapshot(next);
          setError(null);
          setLoading(false);
          setLastUpdated(new Date());
        });
      } catch (cause) {
        if (cancelled) {
          return;
        }
        const message =
          cause instanceof Error ? cause.message : 'Failed to load the incident list';
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
  }, []);

  if (loading && !snapshot) {
    return <div className="px-6 py-10 text-sm text-slate-400">Loading incidents…</div>;
  }

  return (
    <div className="px-6 py-10 space-y-8">
      <div className="space-y-4">
        <Link href="/behavior" className="text-sm text-sky-300 transition-colors hover:text-sky-200">
          Back to overview
        </Link>
        <div className="flex flex-wrap items-start justify-between gap-6">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-500">
              Incident index
            </p>
            <h1 className="mt-2 text-4xl font-semibold tracking-tight text-white">
              Reconstructed incidents
            </h1>
            <p className="mt-2 text-sm text-slate-400">
              Timeline-backed incident summaries derived from behavior and containment telemetry.
            </p>
          </div>
          <div className="text-right text-xs text-slate-500">
            {lastUpdated ? `Updated ${formatRelativeTime(lastUpdated.toISOString())}` : null}
          </div>
        </div>
      </div>

      {error ? (
        <div className="rounded-2xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}

      <div className="grid gap-4 md:grid-cols-3">
        <MetricCard label="Incidents" value={snapshot?.incidents.length ?? 0} accent="red" />
        <MetricCard
          label="Critical incidents"
          value={
            snapshot?.incidents.filter((incident) => incident.severity === 'critical').length ?? 0
          }
          accent="amber"
        />
        <MetricCard
          label="Cross-agent cases"
          value={snapshot?.incidents.filter((incident) => incident.cross_agent).length ?? 0}
          accent="emerald"
        />
      </div>

      <IncidentList
        incidents={snapshot?.incidents ?? []}
        title="Incident backlog"
        description="Select an incident to inspect its reconstructed timeline."
        emptyMessage="No incidents have been reconstructed yet."
      />
    </div>
  );
}
