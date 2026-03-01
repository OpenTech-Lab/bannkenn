'use client';

import Link from 'next/link';
import { useEffect, useMemo, useState } from 'react';
import { useParams } from 'next/navigation';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';

type AgentStatus = {
  id: number;
  name: string;
  nickname?: string;
  created_at: string;
  last_seen_at: string | null;
  status: 'online' | 'offline' | 'unknown';
  butterfly_shield_enabled?: boolean | null;
};

type TelemetryEvent = {
  id: number;
  ip: string;
  reason: string;
  level: 'alert' | 'block';
  source: string;
  log_path?: string | null;
  country?: string | null;
  asn_org?: string | null;
  created_at: string;
};

const FORECAST_WINDOW_HOURS = 6;

export default function AgentDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params?.id;
  const [agent, setAgent] = useState<AgentStatus | null>(null);
  const [telemetry, setTelemetry] = useState<TelemetryEvent[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id) return;

    let cancelled = false;

    async function load() {
      setLoading(true);
      try {
        const [agentRes, decisionsRes] = await Promise.all([
          fetch(`/api/agents/${id}`),
          fetch(`/api/agents/${id}/telemetry?limit=5000`),
        ]);

        if (!cancelled && agentRes.ok) {
          setAgent(await agentRes.json());
        }

        if (!cancelled && decisionsRes.ok) {
          const data = (await decisionsRes.json()) as TelemetryEvent[];
          setTelemetry(data);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, [id]);

  const scannedCount = telemetry.length;
  const riskyCount = telemetry.filter((d) => d.level === 'block').length;
  const alertCount = telemetry.filter((d) => d.level === 'alert').length;

  const reasonStats = useMemo(() => topBy(telemetry, (d) => normalizeReason(d.reason), 8), [telemetry]);
  const ipStats = useMemo(() => topBy(telemetry, (d) => d.ip, 8), [telemetry]);

  const hourlySeries = useMemo(() => {
    const now = new Date();
    const buckets = Array.from({ length: 24 }, (_, idx) => {
      const start = new Date(now);
      start.setMinutes(0, 0, 0);
      start.setHours(start.getHours() - (23 - idx));
      return { start, count: 0 };
    });

    for (const d of telemetry) {
      const t = new Date(d.created_at);
      const hour = new Date(t);
      hour.setMinutes(0, 0, 0);
      const bucket = buckets.find((b) => b.start.getTime() === hour.getTime());
      if (bucket) bucket.count += 1;
    }

    return buckets;
  }, [telemetry]);

  const forecastNextHour = useMemo(() => {
    const values = hourlySeries.map((x) => x.count);
    if (values.length === 0) return 0;
    const tail = values.slice(-FORECAST_WINDOW_HOURS);
    const avg = tail.reduce((sum, v) => sum + v, 0) / Math.max(tail.length, 1);
    const trend = tail.length >= 2 ? (tail[tail.length - 1] - tail[0]) / (tail.length - 1) : 0;
    return Math.max(0, Math.round(avg + trend));
  }, [hourlySeries]);

  if (loading) {
    return <div className="max-w-6xl mx-auto px-4 py-8 text-sm text-muted-foreground">Loading agent details…</div>;
  }

  if (!agent) {
    return (
      <div className="max-w-6xl mx-auto px-4 py-8 space-y-4">
        <p className="text-sm text-muted-foreground">Agent not found.</p>
        <Link href="/" className="text-sm text-blue-400 hover:text-blue-300">
          Back to home
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-8">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <p className="text-xs uppercase tracking-widest text-muted-foreground">Agent Detail</p>
          <h1 className="text-2xl font-bold mt-1">{agent.nickname ?? agent.name}</h1>
          <p className="text-xs text-muted-foreground mt-1">
            Registered {new Date(agent.created_at).toLocaleString()} · Last seen{' '}
            {agent.last_seen_at ? new Date(agent.last_seen_at).toLocaleString() : 'Never'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge
            variant={agent.status === 'online' ? 'default' : agent.status === 'offline' ? 'destructive' : 'secondary'}
            className={agent.status === 'online' ? 'bg-green-900/50 text-green-400 border-green-800' : ''}
          >
            {agent.status}
          </Badge>
          <Link href="/" className="text-sm text-blue-400 hover:text-blue-300">
            Back
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
        <StatCard label="Detected / Scanned" value={scannedCount} />
        <StatCard label="Risky Alerts" value={alertCount} accent="yellow" />
        <StatCard label="Real Risky (Blocked)" value={riskyCount} accent="red" />
        <StatCard
          label="Risk Rate"
          value={`${scannedCount > 0 ? Math.round((riskyCount / scannedCount) * 100) : 0}%`}
        />
        <StatCard label="Forecast Next Hour" value={forecastNextHour} accent="green" />
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <ChartCard title="Top Detection Reasons">
          <HorizontalBars data={reasonStats} />
        </ChartCard>
        <ChartCard title="Top Source IPs">
          <HorizontalBars data={ipStats} mono />
        </ChartCard>
      </div>

      <ChartCard title="24h Request Trend + Forecast">
        <TrendChart series={hourlySeries.map((s) => s.count)} forecast={forecastNextHour} />
      </ChartCard>

      <div>
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-3">
          Event Table (IP / Reason / Country / Organization / Time)
        </h2>
        <div className="rounded-xl border border-border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>IP</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead>Level</TableHead>
                <TableHead>Log Path</TableHead>
                <TableHead>Country</TableHead>
                <TableHead>Organization</TableHead>
                <TableHead>Timestamp</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {telemetry.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-12 text-muted-foreground">
                    No events from this agent yet
                  </TableCell>
                </TableRow>
              ) : (
                telemetry.slice(0, 200).map((d) => {
                  return (
                    <TableRow key={d.id}>
                      <TableCell className="font-mono text-xs">{d.ip}</TableCell>
                      <TableCell className="text-muted-foreground max-w-sm truncate">{d.reason}</TableCell>
                      <TableCell>
                        <Badge variant={d.level === 'block' ? 'destructive' : 'secondary'}>{d.level}</Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground max-w-sm truncate">
                        {d.log_path ?? '—'}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{d.country ?? 'Unknown'}</TableCell>
                      <TableCell className="text-xs text-muted-foreground max-w-xs truncate">
                        {d.asn_org ?? 'Unknown'}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                        {new Date(d.created_at).toLocaleString()}
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </div>
      </div>
    </div>
  );
}

function ChartCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-card border border-border rounded-xl px-4 py-4 space-y-4">
      <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">{title}</h2>
      {children}
    </div>
  );
}

function HorizontalBars({ data, mono }: { data: Array<{ label: string; value: number }>; mono?: boolean }) {
  const max = Math.max(...data.map((x) => x.value), 1);

  if (data.length === 0) {
    return <p className="text-sm text-muted-foreground">No data available</p>;
  }

  return (
    <div className="space-y-2">
      {data.map((item) => (
        <div key={item.label} className="space-y-1">
          <div className="flex items-center justify-between gap-4 text-xs">
            <span className={`${mono ? 'font-mono' : ''} truncate`}>{item.label}</span>
            <span className="text-muted-foreground tabular-nums">{item.value}</span>
          </div>
          <div className="h-2 bg-gray-900 rounded overflow-hidden">
            <div className="h-full bg-blue-500" style={{ width: `${(item.value / max) * 100}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function TrendChart({ series, forecast }: { series: number[]; forecast: number }) {
  const max = Math.max(...series, forecast, 1);

  return (
    <div className="space-y-2">
      <div className="h-40 rounded-lg bg-gray-950 border border-gray-800 p-3 flex items-end gap-1">
        {series.map((value, idx) => (
          <div
            key={idx}
            className="flex-1 bg-cyan-500/70 rounded-sm"
            style={{ height: `${Math.max(4, (value / max) * 100)}%` }}
            title={`${value} events`}
          />
        ))}
        <div
          className="flex-1 bg-emerald-500 rounded-sm border border-emerald-300"
          style={{ height: `${Math.max(4, (forecast / max) * 100)}%` }}
          title={`Forecast: ${forecast}`}
        />
      </div>
      <p className="text-xs text-muted-foreground">24 hourly bars + 1 forecast bar (green).</p>
    </div>
  );
}

function StatCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: string | number;
  accent?: 'red' | 'green' | 'yellow';
}) {
  return (
    <div className="bg-card border border-border rounded-xl px-5 py-4">
      <p className="text-xs text-muted-foreground uppercase tracking-widest mb-1">{label}</p>
      <p
        className={`text-3xl font-bold tabular-nums ${
          accent === 'red'
            ? 'text-red-400'
            : accent === 'green'
            ? 'text-green-400'
            : accent === 'yellow'
            ? 'text-yellow-300'
            : 'text-foreground'
        }`}
      >
        {value}
      </p>
    </div>
  );
}

function normalizeReason(reason: string): string {
  const text = reason.toLowerCase();
  if (text.includes('ssh')) return 'SSH';
  if (text.includes('rdp')) return 'RDP';
  if (text.includes('ftp')) return 'FTP';
  if (text.includes('smb')) return 'SMB';
  if (text.includes('database') || text.includes('mysql') || text.includes('postgres')) return 'Database';
  if (text.includes('mail') || text.includes('smtp') || text.includes('imap')) return 'Mail';
  if (text.includes('web') || text.includes('http')) return 'Web';
  return reason;
}

function topBy<T>(items: T[], keyFn: (item: T) => string, limit: number): Array<{ label: string; value: number }> {
  const counts = new Map<string, number>();
  for (const item of items) {
    const key = keyFn(item);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  return Array.from(counts.entries())
    .map(([label, value]) => ({ label, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, limit);
}
