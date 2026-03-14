import Link from 'next/link';
import { ActivityEntry } from '@/src/features/monitoring/types';
import { SectionPanel } from '@/src/features/monitoring/components/panel';
import { SeverityBadge } from '@/src/features/monitoring/components/status-badge';
import { formatRelativeTime, formatTimestamp } from '@/src/features/monitoring/utils';

const kindLabels: Record<ActivityEntry['kind'], string> = {
  behavior: 'Behavior',
  containment: 'Containment',
  alert: 'Alert',
};

export function ActivityTimeline({ entries }: { entries: ActivityEntry[] }) {
  return (
    <SectionPanel
      eyebrow="Timeline"
      title="Recent activity timeline"
      description="Behavior events, containment transitions, and alerts ordered by event time."
    >
      {entries.length === 0 ? (
        <p className="text-sm text-slate-400">No recent activity has been ingested yet.</p>
      ) : (
        <div className="space-y-4">
          {entries.map((entry) => {
            const content = (
              <>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500">
                    {kindLabels[entry.kind]}
                  </span>
                  <SeverityBadge severity={entry.severity} />
                  {entry.agentName ? (
                    <span className="text-xs text-slate-400">{entry.agentName}</span>
                  ) : null}
                </div>
                <div className="mt-2 flex items-start justify-between gap-4">
                  <div>
                    <p className="font-medium text-white">{entry.title}</p>
                    <p className="mt-1 text-sm text-slate-400">{entry.description}</p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {entry.tags.map((tag) => (
                        <span
                          key={tag}
                          className="rounded-full border border-white/10 px-2 py-1 text-[11px] text-slate-400"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="text-right text-xs text-slate-500">
                    <p>{formatTimestamp(entry.createdAt)}</p>
                    <p>{formatRelativeTime(entry.createdAt)}</p>
                  </div>
                </div>
              </>
            );

            return entry.href ? (
              <Link
                key={entry.id}
                href={entry.href}
                className="block rounded-2xl border border-white/10 bg-slate-950/60 p-4 transition-colors hover:border-sky-400/40"
              >
                {content}
              </Link>
            ) : (
              <div
                key={entry.id}
                className="rounded-2xl border border-white/10 bg-slate-950/60 p-4"
              >
                {content}
              </div>
            );
          })}
        </div>
      )}
    </SectionPanel>
  );
}
