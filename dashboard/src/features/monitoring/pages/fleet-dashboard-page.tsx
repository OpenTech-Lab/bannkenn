'use client';

import { startTransition, useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import {
  fetchDashboardSnapshot,
  requestContainmentAction,
} from '@/src/features/monitoring/api';
import { ActivityTimeline } from '@/src/features/monitoring/components/activity-timeline';
import { ActiveContainmentList } from '@/src/features/monitoring/components/active-containment-list';
import { FleetContainmentPanel } from '@/src/features/monitoring/components/fleet-containment-panel';
import { IncidentList } from '@/src/features/monitoring/components/incident-list';
import { MetricCard } from '@/src/features/monitoring/components/panel';
import { ThreatHeatmap } from '@/src/features/monitoring/components/threat-heatmap';
import { DashboardSnapshot, FleetAgentSummary } from '@/src/features/monitoring/types';
import {
  buildActivityEntries,
  buildFleetAgentSummaries,
  formatRelativeTime,
  isActiveContainmentState,
  summarizeAlertCount,
} from '@/src/features/monitoring/utils';

const POLL_INTERVAL_MS = 30_000;

export function FleetDashboardPage() {
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
          cause instanceof Error ? cause.message : 'Failed to load dashboard snapshot';
        startTransition(() => {
          setError(message);
          setLoading(false);
        });
      }
    };

    void refresh();
    const intervalId = window.setInterval(() => {
      void refresh();
    }, POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, []);

  const summaries = useMemo(() => {
    return snapshot ? buildFleetAgentSummaries(snapshot) : [];
  }, [snapshot]);

  const activityEntries = useMemo(() => {
    return snapshot
      ? buildActivityEntries(
          snapshot.behaviorEvents,
          snapshot.containmentEvents,
          snapshot.alerts,
          snapshot.agents
        )
      : [];
  }, [snapshot]);

  const activeContainment = useMemo(() => {
    return summaries.filter((summary) =>
      summary.containment ? isActiveContainmentState(summary.containment.state) : false
    );
  }, [summaries]);

  async function handleAction(
    summary: FleetAgentSummary,
    commandKind: 'trigger_fuse' | 'release_fuse'
  ) {
    const actionKey = `${summary.agent.id}:${commandKind}`;
    setPendingActionKey(actionKey);

    try {
      await requestContainmentAction(summary.agent.id, {
        command_kind: commandKind,
        reason:
          commandKind === 'trigger_fuse'
            ? 'Manual fuse trigger from dashboard'
            : 'Manual fuse release from dashboard',
        watched_root: summary.containment?.watched_root ?? null,
        pid: summary.containment?.pid ?? null,
      });
      toast.success(
        commandKind === 'trigger_fuse'
          ? `FUSE queued for ${summary.agent.nickname ?? summary.agent.name}`
          : `FUSE release queued for ${summary.agent.nickname ?? summary.agent.name}`
      );

      const next = await fetchDashboardSnapshot();
      startTransition(() => {
        setSnapshot(next);
        setError(null);
        setLastUpdated(new Date());
      });
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Failed to queue containment action');
    } finally {
      setPendingActionKey(null);
    }
  }

  if (loading && !snapshot) {
    return <div className="px-6 py-10 text-sm text-slate-400">Loading dashboard…</div>;
  }

  const health = snapshot?.health.status === 'ok' ? 'ok' : 'error';
  const onlineAgents = snapshot?.agents.filter((agent) => agent.status === 'online').length ?? 0;
  const incidentCount = snapshot?.incidents.length ?? 0;
  const behaviorSpikeCount =
    snapshot?.behaviorEvents.filter((event) => event.level !== 'observed').length ?? 0;
  const elevatedAlertCount = snapshot ? summarizeAlertCount(snapshot.alerts) : 0;

  return (
    <div className="px-6 py-10 space-y-8">
      <div className="flex flex-wrap items-start justify-between gap-6">
        <div className="space-y-3">
          <div className="inline-flex items-center rounded-full border border-sky-500/20 bg-sky-500/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.28em] text-sky-300">
            Phase 4 dashboard
          </div>
          <div>
            <h1 className="text-4xl font-semibold tracking-tight text-white">Containment command center</h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-400">
              Fleet-wide containment status, cross-host pressure, operator fuse control, and
              incident navigation in one view.
            </p>
          </div>
        </div>
        <div className="rounded-2xl border border-white/10 bg-black/60 px-4 py-3 text-right">
          <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-500">
            Server health
          </p>
          <p className={`mt-2 text-sm font-medium ${health === 'ok' ? 'text-emerald-300' : 'text-red-300'}`}>
            {health === 'ok' ? 'Online' : 'Unreachable'}
          </p>
          <p className="mt-1 text-xs text-slate-500">
            {lastUpdated ? `Updated ${formatRelativeTime(lastUpdated.toISOString())}` : 'Waiting for first snapshot'}
          </p>
        </div>
      </div>

      {error ? (
        <div className="rounded-2xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <MetricCard label="Agents enrolled" value={snapshot?.agents.length ?? 0} />
        <MetricCard
          label="Agents online"
          value={onlineAgents}
          detail="Heartbeat within the last two minutes"
          accent="emerald"
        />
        <MetricCard
          label="Active throttle / FUSE"
          value={activeContainment.length}
          detail="Hosts currently restricted by containment"
          accent="amber"
        />
        <MetricCard
          label="Open incidents"
          value={incidentCount}
          detail="Aggregated behavior and containment incident records"
          accent="red"
        />
        <MetricCard
          label="Behavior spikes"
          value={behaviorSpikeCount}
          detail={`${elevatedAlertCount} elevated alerts in recent history`}
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.35fr_0.95fr]">
        <FleetContainmentPanel
          summaries={summaries}
          pendingActionKey={pendingActionKey}
          onAction={handleAction}
        />
        <div className="space-y-6">
          <ThreatHeatmap summaries={summaries.slice(0, 8)} />
          <ActiveContainmentList summaries={activeContainment} />
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
        <ActivityTimeline entries={activityEntries} />
        <IncidentList
          incidents={snapshot?.incidents.slice(0, 8) ?? []}
          title="Incident drill-down"
          description="Recent incidents reconstructed from the Phase 3 timeline store."
          emptyMessage="No incidents have been reconstructed yet."
        />
      </div>
    </div>
  );
}
