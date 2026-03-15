import Link from 'next/link';
import { AgentStatus, IncidentTimelineEntry } from '@/src/features/monitoring/types';
import { SectionPanel } from '@/src/features/monitoring/components/panel';
import { SeverityBadge } from '@/src/features/monitoring/components/status-badge';
import { formatRelativeTime, formatTimestamp } from '@/src/features/monitoring/utils';

type IncidentTimelineProps = {
  timeline: IncidentTimelineEntry[];
  agents: AgentStatus[];
};

export function IncidentTimeline({ timeline, agents }: IncidentTimelineProps) {
  const agentIdByName = new Map(agents.map((agent) => [agent.name, agent.id] as const));

  return (
    <SectionPanel
      eyebrow="Timeline"
      title="Incident event timeline"
      description="Reconstructed cross-agent event history for this incident."
    >
      {timeline.length === 0 ? (
        <p className="text-sm text-slate-400">This incident does not have timeline entries yet.</p>
      ) : (
        <div className="space-y-3">
          {timeline.map((entry) => {
            const agentId = agentIdByName.get(entry.agent_name);

            return (
              <div
                key={entry.id}
                className="rounded-2xl border border-white/10 bg-slate-950/60 p-4"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={entry.severity} />
                      <span className="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500">
                        {entry.source_type.replace(/_/g, ' ')}
                      </span>
                      {agentId ? (
                        <Link
                          href={`/behavior/agents/${agentId}`}
                          className="text-xs text-sky-300 transition-colors hover:text-sky-200"
                        >
                          {entry.agent_name}
                        </Link>
                      ) : (
                        <span className="text-xs text-slate-400">{entry.agent_name}</span>
                      )}
                    </div>
                    <p className="font-medium text-white">{entry.message}</p>
                    <p className="text-sm text-slate-400">Root {entry.watched_root}</p>
                  </div>
                  <div className="text-right text-xs text-slate-500">
                    <p>{formatTimestamp(entry.created_at)}</p>
                    <p>{formatRelativeTime(entry.created_at)}</p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </SectionPanel>
  );
}
