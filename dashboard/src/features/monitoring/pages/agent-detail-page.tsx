'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { startTransition, useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import {
  fetchAgentDetailSnapshot,
  requestContainmentAction,
} from '@/src/features/monitoring/api';
import { IncidentList } from '@/src/features/monitoring/components/incident-list';
import { MetricCard, SectionPanel } from '@/src/features/monitoring/components/panel';
import {
  AgentStatusBadge,
  ContainmentStateBadge,
  ContainmentStateTrack,
} from '@/src/features/monitoring/components/status-badge';
import { AgentDetailSnapshot } from '@/src/features/monitoring/types';
import {
  agentLabel,
  formatRelativeTime,
  formatTimestamp,
} from '@/src/features/monitoring/utils';

const POLL_INTERVAL_MS = 10_000;

export function AgentDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params?.id;
  const [snapshot, setSnapshot] = useState<AgentDetailSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [pendingActionKey, setPendingActionKey] = useState<string | null>(null);

  useEffect(() => {
    if (!id) {
      return;
    }

    let cancelled = false;

    const refresh = async () => {
      try {
        const next = await fetchAgentDetailSnapshot(id);
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
          cause instanceof Error ? cause.message : 'Failed to load the agent detail view';
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
  }, [id]);

  const currentContainment = snapshot?.containmentEvents[0];
  const pendingActions =
    snapshot?.containmentActions.filter((action) => action.status === 'pending').length ?? 0;
  const elevatedBehaviorCount =
    snapshot?.behaviorEvents.filter((event) => event.level !== 'observed').length ?? 0;

  async function handleAction(commandKind: 'trigger_fuse' | 'release_fuse') {
    if (!snapshot) {
      return;
    }

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

  const containmentHistory = useMemo(() => snapshot?.containmentEvents.slice(0, 12) ?? [], [snapshot]);
  const actionHistory = useMemo(() => snapshot?.containmentActions.slice(0, 12) ?? [], [snapshot]);
  const behaviorEvents = useMemo(() => snapshot?.behaviorEvents.slice(0, 30) ?? [], [snapshot]);

  if (loading && !snapshot) {
    return <div className="mx-auto max-w-7xl px-4 py-10 text-sm text-slate-400">Loading agent detail…</div>;
  }

  if (error && !snapshot) {
    return (
      <div className="mx-auto max-w-7xl px-4 py-10 space-y-4">
        <p className="text-sm text-red-300">{error}</p>
        <Link href="/behavior/fleet" className="text-sm text-sky-300 transition-colors hover:text-sky-200">
          Back to fleet
        </Link>
      </div>
    );
  }

  if (!snapshot) {
    return null;
  }

  const state = currentContainment?.state ?? 'normal';

  return (
    <div className="mx-auto max-w-7xl px-4 py-10 space-y-8">
      <div className="flex flex-wrap items-start justify-between gap-6">
        <div className="space-y-3">
          <Link href="/behavior/fleet" className="text-sm text-sky-300 transition-colors hover:text-sky-200">
            Back to fleet
          </Link>
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-500">
              Agent detail
            </p>
            <h1 className="mt-2 text-4xl font-semibold tracking-tight text-white">
              {agentLabel(snapshot.agent)}
            </h1>
            <p className="mt-2 text-sm text-slate-400">
              Registered {formatTimestamp(snapshot.agent.created_at)} · last seen{' '}
              {formatTimestamp(snapshot.agent.last_seen_at)}
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <AgentStatusBadge status={snapshot.agent.status} />
            <ContainmentStateBadge state={state} />
          </div>
        </div>
        <div className="space-y-2 rounded-2xl border border-white/10 bg-slate-950/60 p-4">
          <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500">
            Manual containment
          </p>
          <div className="flex flex-wrap gap-2">
            <button
              className="rounded-md bg-red-900/80 px-3 py-2 text-sm font-medium text-red-100 transition-colors hover:bg-red-800 disabled:cursor-not-allowed disabled:opacity-50"
              disabled={pendingActionKey === `${snapshot.agent.id}:trigger_fuse` || state === 'fuse'}
              onClick={() => void handleAction('trigger_fuse')}
            >
              {pendingActionKey === `${snapshot.agent.id}:trigger_fuse` ? 'Queuing…' : 'Trigger FUSE'}
            </button>
            <button
              className="rounded-md border border-white/10 bg-white/[0.03] px-3 py-2 text-sm font-medium text-slate-200 transition-colors hover:bg-white/[0.07] disabled:cursor-not-allowed disabled:opacity-50"
              disabled={pendingActionKey === `${snapshot.agent.id}:release_fuse` || state !== 'fuse'}
              onClick={() => void handleAction('release_fuse')}
            >
              {pendingActionKey === `${snapshot.agent.id}:release_fuse` ? 'Queuing…' : 'Release FUSE'}
            </button>
          </div>
          <p className="text-xs text-slate-500">
            {currentContainment
              ? `Current root ${currentContainment.watched_root} · score ${currentContainment.score}`
              : 'No containment transitions recorded yet'}
          </p>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Behavior events" value={snapshot.behaviorEvents.length} />
        <MetricCard
          label="Elevated behavior"
          value={elevatedBehaviorCount}
          detail="Events above observed severity"
          accent="amber"
        />
        <MetricCard
          label="Containment changes"
          value={snapshot.containmentEvents.length}
          detail={currentContainment ? `Latest ${formatRelativeTime(currentContainment.created_at)}` : 'No history yet'}
          accent="red"
        />
        <MetricCard
          label="Queued actions"
          value={pendingActions}
          detail={`${snapshot.relatedIncidents.length} related incidents`}
          accent="emerald"
        />
      </div>

      {error ? (
        <div className="rounded-2xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}

      <div className="grid gap-6 xl:grid-cols-[0.95fr_1.05fr]">
        <SectionPanel
          eyebrow="State"
          title="Current containment state"
          description={currentContainment?.reason ?? 'No containment state recorded yet.'}
        >
          <ContainmentStateTrack state={state} />
          <dl className="mt-4 grid gap-3 text-sm text-slate-300 md:grid-cols-2">
            <div className="rounded-2xl border border-white/10 bg-slate-950/60 p-4">
              <dt className="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500">
                Watched root
              </dt>
              <dd className="mt-2">{currentContainment?.watched_root ?? 'Not available'}</dd>
            </div>
            <div className="rounded-2xl border border-white/10 bg-slate-950/60 p-4">
              <dt className="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500">
                Last transition
              </dt>
              <dd className="mt-2">
                {currentContainment ? formatTimestamp(currentContainment.created_at) : 'Never'}
              </dd>
            </div>
          </dl>
        </SectionPanel>

        <SectionPanel
          eyebrow="Commands"
          title="Operator action queue"
          description="Dashboard-issued fuse requests and agent acknowledgements."
        >
          {actionHistory.length === 0 ? (
            <p className="text-sm text-slate-400">No operator actions have been queued yet.</p>
          ) : (
            <div className="space-y-3">
              {actionHistory.map((action) => (
                <div
                  key={action.id}
                  className="rounded-2xl border border-white/10 bg-slate-950/60 p-4"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-1">
                      <p className="font-medium text-white">{action.command_kind.replace('_', ' ')}</p>
                      <p className="text-sm text-slate-400">{action.reason}</p>
                      <p className="text-xs text-slate-500">
                        {action.result_message ?? 'Awaiting agent acknowledgement'}
                      </p>
                    </div>
                    <div className="text-right text-xs text-slate-500">
                      <p>{action.status}</p>
                      <p>{formatTimestamp(action.executed_at ?? action.updated_at)}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </SectionPanel>
      </div>

      <div className="grid gap-6 xl:grid-cols-[0.95fr_1.05fr]">
        <SectionPanel
          eyebrow="History"
          title="Containment history"
          description="Recent containment transitions for this host."
        >
          {containmentHistory.length === 0 ? (
            <p className="text-sm text-slate-400">No containment events have been reported yet.</p>
          ) : (
            <div className="space-y-3">
              {containmentHistory.map((event) => (
                <div
                  key={event.id}
                  className="rounded-2xl border border-white/10 bg-slate-950/60 p-4"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-2">
                      <div className="flex flex-wrap gap-2">
                        <ContainmentStateBadge state={event.state} />
                        {event.previous_state ? (
                          <span className="text-xs text-slate-500">
                            from {event.previous_state}
                          </span>
                        ) : null}
                      </div>
                      <p className="text-sm text-slate-400">{event.reason}</p>
                      <p className="text-xs text-slate-500">
                        Root {event.watched_root} · score {event.score}
                      </p>
                    </div>
                    <div className="text-right text-xs text-slate-500">
                      <p>{formatTimestamp(event.created_at)}</p>
                      <p>{formatRelativeTime(event.created_at)}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </SectionPanel>

        <SectionPanel
          eyebrow="Behavior"
          title="Behavior events"
          description="Recent eBPF/userland behavior events uploaded by this agent."
        >
          {behaviorEvents.length === 0 ? (
            <p className="text-sm text-slate-400">No behavior events have been uploaded yet.</p>
          ) : (
            <div className="space-y-3">
              {behaviorEvents.map((event) => (
                <div
                  key={event.id}
                  className="rounded-2xl border border-white/10 bg-slate-950/60 p-4"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-2">
                      <p className="font-medium text-white">
                        {event.process_name ?? event.exe_path ?? 'unknown process'}
                      </p>
                      <p className="text-sm text-slate-400">
                        {event.reasons.join(', ') || event.level}
                      </p>
                      <p className="text-xs text-slate-500">
                        Root {event.watched_root} · score {event.score} · pid {event.pid ?? 'n/a'}
                      </p>
                    </div>
                    <div className="text-right text-xs text-slate-500">
                      <p>{formatTimestamp(event.created_at)}</p>
                      <p>{formatRelativeTime(event.created_at)}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </SectionPanel>
      </div>

      <IncidentList
        incidents={snapshot.relatedIncidents.slice(0, 8)}
        title="Related incidents"
        description="Recent incidents that include this host in the reconstructed impact set."
        emptyMessage="No incidents currently reference this host."
      />
    </div>
  );
}
