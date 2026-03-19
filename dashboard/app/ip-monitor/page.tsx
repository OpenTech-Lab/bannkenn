'use client';

import Link from 'next/link';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { agentLabel } from '@/src/features/monitoring/utils';

interface CommunityFeed {
  source: string;
  source_label: string;
  kind: string;
  ip_count: number;
  first_seen_at: string;
  last_seen_at: string;
}

interface WhitelistEntry {
  id: number;
  ip: string;
  note: string | null;
  created_at: string;
}

interface Decision {
  id: number;
  ip: string;
  source: string;
  reason: string;
  action: string;
  created_at: string;
}

interface TelemetryLog {
  id: number;
  ip: string;
  level: string;
  source: string;
  reason: string;
  created_at: string;
}

interface AgentInfo {
  id: number;
  name: string;
  nickname?: string | null;
  status: string;
}

interface AgentTelemetrySummary {
  agent: AgentInfo;
  blocked: number;
  alert: number;
  listed: number;
  total: number;
}

export default function IpMonitorOverview() {
  const [feeds, setFeeds] = useState<CommunityFeed[]>([]);
  const [whitelist, setWhitelist] = useState<WhitelistEntry[]>([]);
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [telemetryLogs, setTelemetryLogs] = useState<TelemetryLog[]>([]);
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [feedsRes, whitelistRes, decisionsRes, telemetryRes, agentsRes] = await Promise.all([
        fetch('/api/community/feeds'),
        fetch('/api/whitelist'),
        fetch('/api/decisions?limit=10'),
        fetch('/api/telemetry?limit=1000'),
        fetch('/api/agents'),
      ]);

      if (feedsRes.ok) setFeeds(await feedsRes.json());
      if (whitelistRes.ok) setWhitelist(await whitelistRes.json());
      if (decisionsRes.ok) setDecisions(await decisionsRes.json());
      if (telemetryRes.ok) setTelemetryLogs(await telemetryRes.json());
      if (agentsRes.ok) setAgents(await agentsRes.json());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const totalCommunityIps = feeds.reduce((sum, f) => sum + f.ip_count, 0);

  const agentTelemetrySummaries = useMemo<AgentTelemetrySummary[]>(() => {
    const countsMap = new Map<string, { blocked: number; alert: number; listed: number }>();
    for (const log of telemetryLogs) {
      if (!countsMap.has(log.source)) {
        countsMap.set(log.source, { blocked: 0, alert: 0, listed: 0 });
      }
      const counts = countsMap.get(log.source)!;
      if (log.level === 'block') counts.blocked++;
      else if (log.level === 'alert') counts.alert++;
      else if (log.level === 'listed') counts.listed++;
    }

    return agents
      .map((agent) => {
        const counts = countsMap.get(agent.name) ?? { blocked: 0, alert: 0, listed: 0 };
        return {
          agent,
          ...counts,
          total: counts.blocked + counts.alert + counts.listed,
        };
      })
      .sort((a, b) => b.total - a.total);
  }, [telemetryLogs, agents]);

  if (loading) {
    return (
      <div className="px-6 py-8">
        <p className="text-sm text-muted-foreground">Loading IP Monitor overview...</p>
      </div>
    );
  }

  return (
    <div className="px-6 py-8 space-y-6">
      <div>
        <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">IP Monitor</p>
        <h1 className="text-2xl font-bold text-white mt-2">IP Activity Overview</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Summary of IP blocking, community feeds, and whitelist management.
        </p>
      </div>

      {/* Summary cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Community Feeds" value={feeds.length} />
        <StatCard label="Community IPs" value={totalCommunityIps} accent="red" />
        <StatCard label="Whitelisted" value={whitelist.length} accent="green" />
        <StatCard label="Recent Blocks" value={decisions.length} accent="orange" />
      </div>

      {/* Per-agent IP monitor summary */}
      {agentTelemetrySummaries.length > 0 && (
        <section className="space-y-4">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
            Per-Agent IP Monitor Activity
          </h2>
          <div className="rounded-lg border border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Agent</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Blocked</TableHead>
                  <TableHead className="text-right">Alert</TableHead>
                  <TableHead className="text-right">Listed</TableHead>
                  <TableHead className="text-right">Total</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {agentTelemetrySummaries.map((s) => (
                  <TableRow key={s.agent.id}>
                    <TableCell className="font-medium">
                      <Link
                        href={`/agents/${s.agent.id}#ip-monitor-logs`}
                        className="text-blue-400 hover:text-blue-300 hover:underline"
                      >
                        {agentLabel(s.agent)}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <Badge className={s.agent.status === 'online'
                        ? 'bg-emerald-950/50 text-emerald-300 border border-emerald-700'
                        : 'bg-red-950/50 text-red-300 border border-red-700'
                      }>
                        {s.agent.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {s.blocked > 0 ? (
                        <span className="text-orange-400">{s.blocked}</span>
                      ) : (
                        <span className="text-muted-foreground">0</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {s.alert > 0 ? (
                        <span className="text-red-400">{s.alert}</span>
                      ) : (
                        <span className="text-muted-foreground">0</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {s.listed > 0 ? (
                        <span className="text-amber-400">{s.listed}</span>
                      ) : (
                        <span className="text-muted-foreground">0</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right tabular-nums font-semibold">
                      {s.total > 0 ? (
                        <Link
                          href={`/agents/${s.agent.id}#ip-monitor-logs`}
                          className="text-white hover:text-blue-300 hover:underline"
                        >
                          {s.total}
                        </Link>
                      ) : (
                        <span className="text-muted-foreground">0</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </section>
      )}

      {/* Quick navigation cards */}
      <div className="grid gap-4 sm:grid-cols-3">
        <NavCard
          href="/ip-monitor/lookup"
          title="IP Lookup"
          description="Search risk history, block decisions, and community matches for any IP."
        />
        <NavCard
          href="/ip-monitor/community"
          title="Community IPs"
          description="Browse community threat feeds, agent blocks, and campaign auto-blocks."
        />
        <NavCard
          href="/ip-monitor/whitelist"
          title="Whitelist"
          description="Manage whitelisted IPs and CIDRs that bypass blocking."
        />
      </div>

      {/* Recent block decisions */}
      {decisions.length > 0 && (
        <section className="space-y-4">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
            Recent Block Decisions
          </h2>
          <div className="rounded-lg border border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Timestamp</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {decisions.map((d) => (
                  <TableRow key={d.id}>
                    <TableCell className="font-mono text-sm">
                      <Link
                        href={`/ip-monitor/lookup?ip=${encodeURIComponent(d.ip)}`}
                        className="text-blue-400 hover:text-blue-300 hover:underline"
                      >
                        {d.ip}
                      </Link>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{d.source}</TableCell>
                    <TableCell className="text-sm text-muted-foreground max-w-xs truncate">
                      {d.reason}
                    </TableCell>
                    <TableCell>
                      <Badge className="bg-red-950/70 text-red-300 border border-red-900/70">
                        {d.action}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(d.created_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </section>
      )}

      {/* Community feeds summary */}
      {feeds.length > 0 && (
        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
              Active Community Feeds
            </h2>
            <Link href="/ip-monitor/community" className="text-sm text-blue-400 hover:text-blue-300">
              View all
            </Link>
          </div>
          <div className="rounded-lg border border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Feed</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead className="text-right">IPs</TableHead>
                  <TableHead>Last Updated</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {feeds.map((feed) => (
                  <TableRow key={feed.source}>
                    <TableCell className="font-medium">{feed.source_label}</TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="text-xs">
                        {feed.kind}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right tabular-nums text-red-400">
                      {feed.ip_count.toLocaleString()}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(feed.last_seen_at).toLocaleDateString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </section>
      )}
    </div>
  );
}

function StatCard({
  label,
  value,
  accent = 'gray',
}: {
  label: string;
  value: number;
  accent?: 'gray' | 'red' | 'green' | 'orange';
}) {
  const accentClass =
    accent === 'red'
      ? 'text-red-400'
      : accent === 'green'
      ? 'text-emerald-400'
      : accent === 'orange'
      ? 'text-orange-400'
      : 'text-white';

  return (
    <div className="rounded-xl border border-border bg-card px-4 py-4">
      <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">{label}</p>
      <p className={`mt-3 text-3xl font-semibold tabular-nums ${accentClass}`}>
        {value.toLocaleString()}
      </p>
    </div>
  );
}

function NavCard({
  href,
  title,
  description,
}: {
  href: string;
  title: string;
  description: string;
}) {
  return (
    <Link
      href={href}
      className="rounded-xl border border-gray-800 bg-gray-900/40 p-5 hover:border-gray-600 hover:bg-gray-900/70 transition-all group block"
    >
      <h3 className="font-semibold text-white group-hover:text-blue-400 transition-colors">
        {title}
      </h3>
      <p className="text-xs text-gray-500 mt-2 leading-relaxed">{description}</p>
    </Link>
  );
}
