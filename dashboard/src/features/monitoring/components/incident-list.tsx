import Link from 'next/link';
import { Incident } from '@/src/features/monitoring/types';
import { SectionPanel } from '@/src/features/monitoring/components/panel';
import {
  ContainmentStateBadge,
  SeverityBadge,
} from '@/src/features/monitoring/components/status-badge';
import { formatRelativeTime, formatTimestamp } from '@/src/features/monitoring/utils';

type IncidentListProps = {
  incidents: Incident[];
  title: string;
  description: string;
  emptyMessage: string;
};

export function IncidentList({
  incidents,
  title,
  description,
  emptyMessage,
}: IncidentListProps) {
  return (
    <SectionPanel eyebrow="Incidents" title={title} description={description}>
      {incidents.length === 0 ? (
        <p className="text-sm text-slate-400">{emptyMessage}</p>
      ) : (
        <div className="space-y-3">
          {incidents.map((incident) => (
            <Link
              key={incident.id}
              href={`/behavior/incidents/${incident.id}`}
              className="block rounded-2xl border border-white/10 bg-black/60 p-4 transition-colors hover:border-sky-400/40"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="font-semibold text-white">{incident.title}</p>
                    <SeverityBadge severity={incident.severity} />
                    {incident.latest_state ? (
                      <ContainmentStateBadge state={incident.latest_state} />
                    ) : null}
                  </div>
                  <p className="text-sm text-slate-400">{incident.summary}</p>
                  <p className="text-xs text-slate-500">
                    Agents {incident.affected_agents.join(', ') || 'none'} · roots{' '}
                    {incident.affected_roots.join(', ') || 'none'}
                  </p>
                </div>
                <div className="text-right text-xs text-slate-500">
                  <p>{formatTimestamp(incident.last_seen_at)}</p>
                  <p>{formatRelativeTime(incident.last_seen_at)}</p>
                  <p className="mt-2">
                    {incident.event_count} events · {incident.alert_count} alerts
                  </p>
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </SectionPanel>
  );
}
