import { ReactNode } from 'react';
import { cn } from '@/lib/utils';

type SectionPanelProps = {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
  className?: string;
  children: ReactNode;
};

export function SectionPanel({
  eyebrow,
  title,
  description,
  actions,
  className,
  children,
}: SectionPanelProps) {
  return (
    <section
      className={cn(
        'rounded-2xl border border-white/10 bg-white/[0.03] p-5 shadow-[0_18px_80px_rgba(0,0,0,0.18)]',
        className
      )}
    >
      <div className="mb-4 flex items-start justify-between gap-4">
        <div className="space-y-1">
          {eyebrow ? (
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-400">
              {eyebrow}
            </p>
          ) : null}
          <h2 className="text-lg font-semibold text-white">{title}</h2>
          {description ? <p className="text-sm text-slate-400">{description}</p> : null}
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}

type MetricCardProps = {
  label: string;
  value: string | number;
  detail?: string;
  accent?: 'slate' | 'emerald' | 'amber' | 'red';
};

const accentClasses: Record<NonNullable<MetricCardProps['accent']>, string> = {
  slate: 'border-slate-800/80 bg-slate-900/60 text-slate-100',
  emerald: 'border-emerald-900/80 bg-emerald-950/40 text-emerald-100',
  amber: 'border-amber-900/80 bg-amber-950/40 text-amber-100',
  red: 'border-red-900/80 bg-red-950/40 text-red-100',
};

export function MetricCard({
  label,
  value,
  detail,
  accent = 'slate',
}: MetricCardProps) {
  return (
    <div className={cn('rounded-2xl border p-4', accentClasses[accent])}>
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-400">
        {label}
      </p>
      <p className="mt-3 text-3xl font-semibold">{value}</p>
      {detail ? <p className="mt-2 text-xs text-slate-400">{detail}</p> : null}
    </div>
  );
}
