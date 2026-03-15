'use client';

import Link from 'next/link';
import { startTransition, useCallback, useEffect, useMemo, useState } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { toast } from 'sonner';
import {
  fetchDashboardSnapshot,
  updateAgentNickname,
  deleteAgent,
} from '@/src/features/monitoring/api';
import { AgentStatus, DashboardSnapshot } from '@/src/features/monitoring/types';
import {
  buildFleetAgentSummaries,
  formatRelativeTime,
  isActiveContainmentState,
  summarizeAlertCount,
} from '@/src/features/monitoring/utils';

interface CommunityFeed {
  source: string;
  source_label: string;
  kind: string;
  ip_count: number;
}

interface WhitelistEntry {
  id: number;
  ip: string;
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

const POLL_INTERVAL_MS = 30_000;

const SEVERITY_COLORS: Record<string, string> = {
  low: '#64748b',
  medium: '#f59e0b',
  high: '#f97316',
  critical: '#ef4444',
};

const STATE_COLORS: Record<string, string> = {
  normal: '#64748b',
  suspicious: '#f59e0b',
  throttle: '#f97316',
  fuse: '#ef4444',
};

export default function HomeDashboard() {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null);
  const [feeds, setFeeds] = useState<CommunityFeed[]>([]);
  const [whitelist, setWhitelist] = useState<WhitelistEntry[]>([]);
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [telemetryLogs, setTelemetryLogs] = useState<TelemetryLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [editingAgent, setEditingAgent] = useState<AgentStatus | null>(null);
  const [editNickname, setEditNickname] = useState('');
  const [editSaving, setEditSaving] = useState(false);
  const [deletingAgent, setDeletingAgent] = useState<AgentStatus | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);

  const refreshDashboard = useCallback(async () => {
    try {
      const [snap, decisionsRes, telemetryRes] = await Promise.all([
        fetchDashboardSnapshot(),
        fetch('/api/decisions?limit=5'),
        fetch('/api/telemetry?limit=500'),
      ]);

      const decisionsData = decisionsRes.ok ? await decisionsRes.json() : [];
      const telemetryData = telemetryRes.ok ? await telemetryRes.json() : [];

      startTransition(() => {
        setSnapshot(snap);
        setDecisions(decisionsData);
        setTelemetryLogs(telemetryData);
        setError(null);
        setLoading(false);
        setLastUpdated(new Date());
      });
    } catch (cause) {
      startTransition(() => {
        setError(cause instanceof Error ? cause.message : 'Failed to load dashboard');
        setLoading(false);
      });
    }
  }, []);

  const fetchOverviewMetadata = useCallback(async () => {
    try {
      const [feedsRes, whitelistRes] = await Promise.all([
        fetch('/api/community/feeds'),
        fetch('/api/whitelist'),
      ]);

      const feedsData = feedsRes.ok ? await feedsRes.json() : [];
      const whitelistData = whitelistRes.ok ? await whitelistRes.json() : [];

      startTransition(() => {
        setFeeds(feedsData);
        setWhitelist(whitelistData);
      });
    } catch {
      // Ignore metadata refresh failures; the live dashboard state is handled separately.
    }
  }, []);

  useEffect(() => {
    void refreshDashboard();
    void fetchOverviewMetadata();
    const id = window.setInterval(() => void refreshDashboard(), POLL_INTERVAL_MS);
    return () => window.clearInterval(id);
  }, [fetchOverviewMetadata, refreshDashboard]);

  async function handleEditSave() {
    if (!editingAgent) return;
    setEditSaving(true);
    try {
      await updateAgentNickname(editingAgent.id, editNickname);
      toast.success(`Nickname updated for ${editingAgent.name}`);
      setEditingAgent(null);
      void refreshDashboard();
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Failed to update nickname');
    } finally {
      setEditSaving(false);
    }
  }

  async function handleDelete() {
    if (!deletingAgent) return;
    setDeleteLoading(true);
    try {
      await deleteAgent(deletingAgent.id);
      toast.success(`Agent ${deletingAgent.nickname?.trim() || deletingAgent.name} deleted`);
      setDeletingAgent(null);
      void refreshDashboard();
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Failed to delete agent');
    } finally {
      setDeleteLoading(false);
    }
  }

  const summaries = useMemo(
    () => (snapshot ? buildFleetAgentSummaries(snapshot) : []),
    [snapshot]
  );

  // Per-agent telemetry counts: sum of block/listed/alert events
  const telemetryCountByAgent = useMemo(() => {
    const counts = new Map<string, number>();
    for (const log of telemetryLogs) {
      if (log.level === 'block' || log.level === 'listed' || log.level === 'alert') {
        counts.set(log.source, (counts.get(log.source) ?? 0) + 1);
      }
    }
    return counts;
  }, [telemetryLogs]);

  const onlineAgents = snapshot?.agents.filter((a) => a.status === 'online').length ?? 0;
  const activeContainment = summaries.filter((s) =>
    s.containment ? isActiveContainmentState(s.containment.state) : false
  ).length;
  const incidentCount = snapshot?.incidents.length ?? 0;
  const behaviorSpikes = snapshot?.behaviorEvents.filter((e) => e.level !== 'observed').length ?? 0;
  const elevatedAlerts = snapshot ? summarizeAlertCount(snapshot.alerts) : 0;
  const totalCommunityIps = feeds.reduce((sum, f) => sum + f.ip_count, 0);

  // Chart data: incidents by severity
  const severityData = useMemo(() => {
    if (!snapshot) return [];
    const counts: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
    for (const inc of snapshot.incidents) {
      const sev = inc.severity in counts ? inc.severity : 'low';
      counts[sev]++;
    }
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [snapshot]);

  // Chart data: containment state distribution
  const containmentData = useMemo(() => {
    const counts: Record<string, number> = { normal: 0, suspicious: 0, throttle: 0, fuse: 0 };
    for (const s of summaries) {
      const state = s.containment?.state ?? 'normal';
      if (state in counts) counts[state]++;
      else counts['normal']++;
    }
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [summaries]);

  if (loading) {
    return (
      <div className="max-w-6xl mx-auto px-4 py-8">
        <p className="text-sm text-muted-foreground">Loading dashboard...</p>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">Dashboard</p>
          <h1 className="text-2xl font-bold text-white mt-2">BannKenn Overview</h1>
          <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
            Comprehensive view of fleet status, IP blocking, behavior monitoring, and incidents.
          </p>
        </div>
        <div className="rounded-xl border border-border bg-card px-4 py-3 text-right">
          <p className="text-xs uppercase tracking-[0.25em] text-muted-foreground">Server Health</p>
          <p className={`mt-2 text-sm font-medium ${snapshot?.health.status === 'ok' ? 'text-emerald-400' : 'text-red-400'}`}>
            {snapshot?.health.status === 'ok' ? 'Online' : 'Unreachable'}
          </p>
          {lastUpdated && (
            <p className="mt-1 text-xs text-muted-foreground">
              Updated {lastUpdated.toLocaleTimeString()}
            </p>
          )}
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Top metric cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        <StatCard label="Agents" value={snapshot?.agents.length ?? 0} />
        <StatCard label="Online" value={onlineAgents} accent="green" />
        <StatCard label="Containment" value={activeContainment} accent="orange" />
        <StatCard label="Incidents" value={incidentCount} accent="red" />
        <StatCard label="Behavior Spikes" value={behaviorSpikes} accent="yellow" />
        <StatCard label="Community IPs" value={totalCommunityIps} accent="red" />
      </div>

      {/* Charts */}
      <div className="grid gap-4 lg:grid-cols-2">
        <section className="rounded-xl border border-border bg-card p-5 space-y-4">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
            Incidents by Severity
          </h2>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData} margin={{ top: 5, right: 10, left: -10, bottom: 5 }}>
                <XAxis
                  dataKey="name"
                  tick={{ fill: '#94a3b8', fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: '#64748b', fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                  allowDecimals={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    fontSize: 12,
                    color: '#e2e8f0',
                  }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry) => (
                    <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] ?? '#64748b'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="rounded-xl border border-border bg-card p-5 space-y-4">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
            Containment State Distribution
          </h2>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={containmentData} margin={{ top: 5, right: 10, left: -10, bottom: 5 }}>
                <XAxis
                  dataKey="name"
                  tick={{ fill: '#94a3b8', fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: '#64748b', fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                  allowDecimals={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    fontSize: 12,
                    color: '#e2e8f0',
                  }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {containmentData.map((entry) => (
                    <Cell key={entry.name} fill={STATE_COLORS[entry.name] ?? '#64748b'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>
      </div>

      {/* Fleet status table */}
      {summaries.length > 0 && (
        <section className="rounded-xl border border-border bg-card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
              Fleet Status
            </h2>
            <Link href="/behavior/fleet" className="text-sm text-blue-400 hover:text-blue-300">
              Manage fleet
            </Link>
          </div>
          <div className="rounded-lg border border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Agent</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Containment</TableHead>
                  <TableHead className="text-right">Heat</TableHead>
                  <TableHead className="text-right">IP Monitor</TableHead>
                  <TableHead className="text-right">Incidents</TableHead>
                  <TableHead>Last Seen</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {summaries.slice(0, 6).map((s) => (
                  <TableRow key={s.agent.id}>
                    <TableCell className="font-medium">
                      <Link
                        href={`/behavior/agents/${s.agent.id}`}
                        className="text-blue-400 hover:text-blue-300 hover:underline"
                      >
                        {s.agent.nickname?.trim() || s.agent.name}
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
                    <TableCell>
                      <Badge className={
                        s.containment?.state === 'fuse'
                          ? 'bg-red-950/60 text-red-300 border border-red-700'
                          : s.containment?.state === 'throttle'
                          ? 'bg-orange-950/50 text-orange-300 border border-orange-700'
                          : s.containment?.state === 'suspicious'
                          ? 'bg-amber-950/50 text-amber-300 border border-amber-700'
                          : 'bg-gray-900/70 text-gray-200 border border-gray-700'
                      }>
                        {s.containment?.state ?? 'normal'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      <span className={
                        s.heat >= 85 ? 'text-red-400' : s.heat >= 60 ? 'text-orange-400' : s.heat >= 35 ? 'text-amber-400' : 'text-gray-300'
                      }>
                        {s.heat}
                      </span>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {(() => {
                        const count = telemetryCountByAgent.get(s.agent.name) ?? 0;
                        return count > 0 ? (
                          <Link
                            href={`/behavior/agents/${s.agent.id}#ip-monitor-logs`}
                            className="text-blue-400 hover:text-blue-300 hover:underline"
                          >
                            {count}
                          </Link>
                        ) : (
                          <span className="text-muted-foreground">0</span>
                        );
                      })()}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {s.incidentCount > 0 ? (
                        <Link
                          href={`/behavior/agents/${s.agent.id}#related-incidents`}
                          className="text-blue-400 hover:text-blue-300 hover:underline"
                        >
                          {s.incidentCount}
                        </Link>
                      ) : (
                        <span className="text-muted-foreground">0</span>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                      {s.agent.last_seen_at ? formatRelativeTime(s.agent.last_seen_at) : 'Never'}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-7 px-2 text-xs"
                          onClick={() => {
                            setEditingAgent(s.agent);
                            setEditNickname(s.agent.nickname ?? '');
                          }}
                        >
                          Edit
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-7 px-2 text-xs text-red-400 border-red-900/50 hover:bg-red-950/40 hover:text-red-300"
                          onClick={() => setDeletingAgent(s.agent)}
                        >
                          Delete
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </section>
      )}

      {/* Two-column: Recent Incidents + Recent IP Blocks */}
      <div className="grid gap-4 lg:grid-cols-2">
        {/* Recent incidents */}
        <section className="rounded-xl border border-border bg-card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
              Recent Incidents
            </h2>
            <Link href="/behavior/incidents" className="text-sm text-blue-400 hover:text-blue-300">
              View all
            </Link>
          </div>
          {(snapshot?.incidents.length ?? 0) === 0 ? (
            <p className="text-sm text-muted-foreground py-6 text-center">No incidents yet.</p>
          ) : (
            <div className="rounded-lg border border-border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Title</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Last Seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {snapshot?.incidents.slice(0, 5).map((inc) => (
                    <TableRow key={inc.id}>
                      <TableCell className="font-medium">
                        <Link
                          href={`/behavior/incidents/${inc.id}`}
                          className="text-blue-400 hover:text-blue-300 hover:underline"
                        >
                          {inc.title}
                        </Link>
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={inc.severity} />
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                        {formatRelativeTime(inc.last_seen_at)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </section>

        {/* Recent IP blocks */}
        <section className="rounded-xl border border-border bg-card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
              Recent IP Blocks
            </h2>
            <Link href="/ip-monitor/lookup" className="text-sm text-blue-400 hover:text-blue-300">
              Lookup IP
            </Link>
          </div>
          {decisions.length === 0 ? (
            <p className="text-sm text-muted-foreground py-6 text-center">No recent blocks.</p>
          ) : (
            <div className="rounded-lg border border-border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>IP</TableHead>
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
                      <TableCell>
                        <Badge className="bg-red-950/70 text-red-300 border border-red-900/70">
                          {d.action}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                        {formatRelativeTime(d.created_at)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </section>
      </div>

      {/* IP Monitor summary */}
      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard label="Community Feeds" value={feeds.length} />
        <StatCard label="Whitelisted IPs" value={whitelist.length} accent="green" />
        <StatCard label="Elevated Alerts" value={elevatedAlerts} accent="orange" />
      </div>

      {/* Quick links */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <QuickLink href="/ip-monitor" title="IP Monitor" desc="IP blocking & feeds" />
        <QuickLink href="/ip-monitor/lookup" title="IP Lookup" desc="Search any IP" />
        <QuickLink href="/behavior" title="Behavior Monitor" desc="Fleet & containment" />
        <QuickLink href="/behavior/incidents" title="Incidents" desc={`${incidentCount} tracked`} />
      </div>

      <p className="text-center text-xs text-muted-foreground">
        Auto-refreshes every {POLL_INTERVAL_MS / 1000}s
      </p>

      {/* Edit nickname dialog */}
      <Dialog open={editingAgent !== null} onOpenChange={(open) => { if (!open) setEditingAgent(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Agent Nickname</DialogTitle>
            <DialogDescription>
              Change the display name for {editingAgent?.name}.
            </DialogDescription>
          </DialogHeader>
          <Input
            value={editNickname}
            onChange={(e) => setEditNickname(e.target.value)}
            placeholder="Enter nickname"
            onKeyDown={(e) => { if (e.key === 'Enter') void handleEditSave(); }}
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingAgent(null)}>Cancel</Button>
            <Button onClick={() => void handleEditSave()} disabled={editSaving}>
              {editSaving ? 'Saving...' : 'Save'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirmation dialog */}
      <AlertDialog open={deletingAgent !== null} onOpenChange={(open) => { if (!open) setDeletingAgent(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Agent</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete{' '}
              <span className="font-semibold text-white">
                {deletingAgent?.nickname?.trim() || deletingAgent?.name}
              </span>
              ? This action cannot be undone. All associated telemetry, decisions, and containment history will be removed.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteLoading}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => void handleDelete()}
              disabled={deleteLoading}
              className="bg-red-600 hover:bg-red-700 text-white"
            >
              {deleteLoading ? 'Deleting...' : 'Delete'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
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
  accent?: 'gray' | 'red' | 'green' | 'orange' | 'yellow';
}) {
  const accentClass =
    accent === 'red' ? 'text-red-400'
    : accent === 'green' ? 'text-emerald-400'
    : accent === 'orange' ? 'text-orange-400'
    : accent === 'yellow' ? 'text-yellow-400'
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

function SeverityBadge({ severity }: { severity: string }) {
  const cls =
    severity === 'critical' ? 'bg-red-950/60 text-red-300 border border-red-700'
    : severity === 'high' ? 'bg-orange-950/50 text-orange-300 border border-orange-700'
    : severity === 'medium' ? 'bg-amber-950/50 text-amber-300 border border-amber-700'
    : 'bg-gray-900/70 text-gray-200 border border-gray-700';
  return <Badge className={cls}>{severity}</Badge>;
}

function QuickLink({ href, title, desc }: { href: string; title: string; desc: string }) {
  return (
    <Link
      href={href}
      className="rounded-xl border border-gray-800 bg-gray-900/40 p-4 hover:border-gray-600 hover:bg-gray-900/70 transition-all group block"
    >
      <h3 className="font-semibold text-white group-hover:text-blue-400 transition-colors text-sm">
        {title}
      </h3>
      <p className="text-xs text-gray-500 mt-1">{desc}</p>
    </Link>
  );
}
