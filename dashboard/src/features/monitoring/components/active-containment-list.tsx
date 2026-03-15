import Link from 'next/link';
import { FleetAgentSummary } from '@/src/features/monitoring/types';
import { SectionPanel } from '@/src/features/monitoring/components/panel';
import { ContainmentStateBadge } from '@/src/features/monitoring/components/status-badge';
import {
  agentLabel,
  formatRelativeTime,
  formatTimestamp,
} from '@/src/features/monitoring/utils';

export function ActiveContainmentList({ summaries }: { summaries: FleetAgentSummary[] }) {
  return (
    <SectionPanel
      eyebrow="Enforcement"
      title="Active throttling events"
      description="Hosts currently sitting in THROTTLE or FUSE, ordered by overall pressure."
    >
      {summaries.length === 0 ? (
        <p className="text-sm text-slate-400">No hosts are actively throttled or fused.</p>
      ) : (
        <div className="space-y-3">
          {summaries.map((summary) => (
            <Link
              key={summary.agent.id}
              href={`/behavior/agents/${summary.agent.id}`}
              className="block rounded-2xl border border-white/10 bg-slate-950/60 p-4 transition-colors hover:border-sky-400/40"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <p className="font-semibold text-white">{agentLabel(summary.agent)}</p>
                    <ContainmentStateBadge state={summary.containment?.state ?? 'normal'} />
                  </div>
                  <p className="text-sm text-slate-400">
                    {summary.containment?.reason ?? 'Containment state unavailable'}
                  </p>
                  <p className="text-xs text-slate-500">
                    Root {summary.containment?.watched_root ?? 'unknown'} · score{' '}
                    {summary.containment?.score ?? 0}
                  </p>
                </div>
                <div className="text-right text-xs text-slate-500">
                  <p>{formatTimestamp(summary.containment?.updated_at)}</p>
                  <p>{formatRelativeTime(summary.containment?.updated_at)}</p>
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </SectionPanel>
  );
}
