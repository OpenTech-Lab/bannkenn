import Link from 'next/link';
import { FleetAgentSummary } from '@/src/features/monitoring/types';
import { SectionPanel } from '@/src/features/monitoring/components/panel';
import {
  AgentStatusBadge,
  ContainmentStateBadge,
} from '@/src/features/monitoring/components/status-badge';
import { agentLabel } from '@/src/features/monitoring/utils';

function heatClasses(heat: number) {
  if (heat >= 85) {
    return 'border-red-700/70 bg-red-950/60';
  }
  if (heat >= 60) {
    return 'border-orange-700/70 bg-orange-950/45';
  }
  if (heat >= 35) {
    return 'border-amber-700/70 bg-amber-950/35';
  }
  return 'border-slate-800 bg-black/70';
}

export function ThreatHeatmap({ summaries }: { summaries: FleetAgentSummary[] }) {
  return (
    <SectionPanel
      eyebrow="Fleet"
      title="Threat heatmap"
      description="Relative host pressure derived from containment state, incidents, alerts, and score."
    >
      {summaries.length === 0 ? (
        <p className="text-sm text-slate-400">No fleet telemetry is available yet.</p>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2">
          {summaries.map((summary) => (
            <Link
              key={summary.agent.id}
              href={`/behavior/agents/${summary.agent.id}`}
              className={`rounded-2xl border p-4 transition-colors hover:border-sky-400/40 ${heatClasses(
                summary.heat
              )}`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="space-y-2">
                  <p className="font-semibold text-white">{agentLabel(summary.agent)}</p>
                  <div className="flex flex-wrap gap-2">
                    <AgentStatusBadge status={summary.agent.status} />
                    <ContainmentStateBadge state={summary.containment?.state ?? 'normal'} />
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-2xl font-semibold text-white">{summary.heat}</p>
                  <p className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
                    Threat score
                  </p>
                </div>
              </div>
              <div className="mt-4 grid grid-cols-2 gap-2 text-xs text-slate-300">
                <div className="rounded-xl border border-white/10 bg-black/20 p-3">
                  <p className="text-slate-500">Incidents</p>
                  <p className="mt-1 text-lg font-semibold text-white">{summary.incidentCount}</p>
                </div>
                <div className="rounded-xl border border-white/10 bg-black/20 p-3">
                  <p className="text-slate-500">Alerts</p>
                  <p className="mt-1 text-lg font-semibold text-white">{summary.alertCount}</p>
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </SectionPanel>
  );
}
