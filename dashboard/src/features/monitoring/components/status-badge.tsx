import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { formatStateLabel, normalizeSeverity } from '@/src/features/monitoring/utils';

const stateClasses: Record<string, string> = {
  normal: 'border-slate-700 bg-slate-900/70 text-slate-200',
  suspicious: 'border-amber-700 bg-amber-950/50 text-amber-300',
  throttle: 'border-orange-700 bg-orange-950/50 text-orange-300',
  fuse: 'border-red-700 bg-red-950/60 text-red-300',
};

const agentStatusClasses: Record<string, string> = {
  online: 'border-emerald-700 bg-emerald-950/50 text-emerald-300',
  offline: 'border-red-700 bg-red-950/50 text-red-300',
  unknown: 'border-slate-700 bg-slate-900/70 text-slate-300',
};

const severityClasses: Record<string, string> = {
  low: 'border-slate-700 bg-slate-900/70 text-slate-200',
  medium: 'border-amber-700 bg-amber-950/50 text-amber-300',
  high: 'border-orange-700 bg-orange-950/50 text-orange-300',
  critical: 'border-red-700 bg-red-950/60 text-red-300',
};

export function ContainmentStateBadge({ state }: { state: string }) {
  return (
    <Badge className={cn('capitalize', stateClasses[state] ?? stateClasses.normal)}>
      {formatStateLabel(state)}
    </Badge>
  );
}

export function AgentStatusBadge({ status }: { status: string }) {
  return (
    <Badge className={cn('capitalize', agentStatusClasses[status] ?? agentStatusClasses.unknown)}>
      {status}
    </Badge>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const normalized = normalizeSeverity(severity);
  return (
    <Badge className={cn('capitalize', severityClasses[normalized])}>{normalized}</Badge>
  );
}

export function ContainmentStateTrack({ state }: { state: string }) {
  const states = ['normal', 'suspicious', 'throttle', 'fuse'];
  const activeIndex = Math.max(states.indexOf(state), 0);

  return (
    <div className="grid grid-cols-4 gap-2">
      {states.map((step, index) => {
        const isActive = index <= activeIndex;
        return (
          <div key={step} className="space-y-1">
            <div
              className={cn(
                'h-2 rounded-full border',
                isActive
                  ? stateClasses[step] ?? stateClasses.normal
                  : 'border-slate-800 bg-slate-900/60'
              )}
            />
            <p className="text-[10px] uppercase tracking-[0.18em] text-slate-500">
              {formatStateLabel(step)}
            </p>
          </div>
        );
      })}
    </div>
  );
}
