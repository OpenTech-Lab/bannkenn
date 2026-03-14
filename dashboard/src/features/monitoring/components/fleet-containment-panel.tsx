import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { FleetAgentSummary } from '@/src/features/monitoring/types';
import { SectionPanel } from '@/src/features/monitoring/components/panel';
import {
  AgentStatusBadge,
  ContainmentStateBadge,
  ContainmentStateTrack,
} from '@/src/features/monitoring/components/status-badge';
import {
  agentLabel,
  formatRelativeTime,
  formatTimestamp,
} from '@/src/features/monitoring/utils';

type FleetContainmentPanelProps = {
  summaries: FleetAgentSummary[];
  pendingActionKey: string | null;
  onAction: (
    summary: FleetAgentSummary,
    commandKind: 'trigger_fuse' | 'release_fuse'
  ) => void | Promise<void>;
};

export function FleetContainmentPanel({
  summaries,
  pendingActionKey,
  onAction,
}: FleetContainmentPanelProps) {
  return (
    <SectionPanel
      eyebrow="Phase 4"
      title="Containment status panel"
      description="Per-host containment state, threat posture, and manual FUSE controls."
    >
      {summaries.length === 0 ? (
        <p className="text-sm text-slate-400">No agents are registered yet.</p>
      ) : (
        <div className="grid gap-4 xl:grid-cols-2">
          {summaries.map((summary) => {
            const state = summary.containment?.state ?? 'normal';
            const root = summary.containment?.watched_root ?? 'Awaiting first watched root';
            const triggerKey = `${summary.agent.id}:trigger_fuse`;
            const releaseKey = `${summary.agent.id}:release_fuse`;

            return (
              <article
                key={summary.agent.id}
                className="rounded-2xl border border-white/10 bg-slate-950/60 p-4"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <Link
                        href={`/agents/${summary.agent.id}`}
                        className="text-base font-semibold text-white transition-colors hover:text-sky-300"
                      >
                        {agentLabel(summary.agent)}
                      </Link>
                      <AgentStatusBadge status={summary.agent.status} />
                      <ContainmentStateBadge state={state} />
                    </div>
                    <p className="text-sm text-slate-400">
                      {summary.containment?.reason ?? 'No containment transition has been recorded.'}
                    </p>
                  </div>
                  <div className="text-right text-xs text-slate-500">
                    <p>{formatTimestamp(summary.containment?.updated_at ?? summary.agent.last_seen_at)}</p>
                    <p>{formatRelativeTime(summary.containment?.updated_at ?? summary.agent.last_seen_at)}</p>
                  </div>
                </div>

                <div className="mt-4">
                  <ContainmentStateTrack state={state} />
                </div>

                <dl className="mt-4 grid grid-cols-3 gap-3 text-xs text-slate-400">
                  <div>
                    <dt className="uppercase tracking-[0.18em] text-slate-500">Root</dt>
                    <dd className="mt-1 truncate text-slate-200">{root}</dd>
                  </div>
                  <div>
                    <dt className="uppercase tracking-[0.18em] text-slate-500">Score</dt>
                    <dd className="mt-1 text-slate-200">{summary.containment?.score ?? 0}</dd>
                  </div>
                  <div>
                    <dt className="uppercase tracking-[0.18em] text-slate-500">Incidents</dt>
                    <dd className="mt-1 text-slate-200">{summary.incidentCount}</dd>
                  </div>
                </dl>

                <div className="mt-4 flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    variant="destructive"
                    disabled={pendingActionKey === triggerKey || state === 'fuse'}
                    onClick={() => void onAction(summary, 'trigger_fuse')}
                  >
                    {pendingActionKey === triggerKey ? 'Queuing…' : 'Trigger FUSE'}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={pendingActionKey === releaseKey || state !== 'fuse'}
                    onClick={() => void onAction(summary, 'release_fuse')}
                  >
                    {pendingActionKey === releaseKey ? 'Queuing…' : 'Release FUSE'}
                  </Button>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </SectionPanel>
  );
}
