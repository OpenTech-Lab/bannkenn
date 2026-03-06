'use client';

import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { toast } from 'sonner';
import { Pencil, Trash2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
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
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogClose,
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
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';

interface Decision {
  id: number;
  ip: string;
  reason: string;
  action: string;
  source: string;
  created_at: string;
  expires_at: string | null;
}

interface AgentStatus {
  id: number;
  name: string;
  uuid?: string;
  nickname?: string;
  created_at: string;
  last_seen_at: string | null;
  status: 'online' | 'offline' | 'unknown';
  butterfly_shield_enabled?: boolean | null;
}

interface SshLoginEvent {
  id: number;
  ip: string;
  username: string;
  agent_name: string;
  country: string | null;
  asn_org: string | null;
  created_at: string;
}

const POLL_INTERVAL = 10_000;

export default function Dashboard() {
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [agents, setAgents] = useState<AgentStatus[]>([]);
  const [sshLogins, setSshLogins] = useState<SshLoginEvent[]>([]);
  const [health, setHealth] = useState<'ok' | 'error' | 'loading'>('loading');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  // Edit dialog state
  const [editingAgent, setEditingAgent] = useState<AgentStatus | null>(null);
  const [editNickname, setEditNickname] = useState('');
  const [editLoading, setEditLoading] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const [healthRes, decisionsRes, agentsRes, sshLoginsRes] = await Promise.all([
        fetch('/api/health'),
        fetch('/api/decisions'),
        fetch('/api/agents'),
        fetch('/api/ssh-logins'),
      ]);

      if (healthRes.ok) {
        const h = await healthRes.json();
        setHealth(h.status === 'ok' ? 'ok' : 'error');
      } else {
        setHealth('error');
      }

      if (decisionsRes.ok) {
        setDecisions(await decisionsRes.json());
      }

      if (agentsRes.ok) {
        setAgents(await agentsRes.json());
      }

      if (sshLoginsRes.ok) {
        setSshLogins(await sshLoginsRes.json());
      }

      setLastUpdated(new Date());
    } catch {
      setHealth('error');
    }
  }, []);

  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, POLL_INTERVAL);
    return () => clearInterval(id);
  }, [fetchData]);

  const openEdit = (agent: AgentStatus) => {
    setEditingAgent(agent);
    setEditNickname(agent.nickname ?? agent.name);
  };

  const handleRename = async () => {
    if (!editingAgent) return;
    setEditLoading(true);
    try {
      const res = await fetch(`/api/agents/${editingAgent.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nickname: editNickname.trim() }),
      });
      if (res.ok) {
        toast.success('Agent renamed successfully');
        setEditingAgent(null);
        fetchData();
      } else {
        toast.error('Failed to rename agent');
      }
    } catch {
      toast.error('Network error');
    } finally {
      setEditLoading(false);
    }
  };

  const handleRemove = async (agent: AgentStatus) => {
    try {
      const res = await fetch(`/api/agents/${agent.id}`, { method: 'DELETE' });
      if (res.ok) {
        toast.success(`Agent "${agent.nickname ?? agent.name}" removed`);
        fetchData();
      } else {
        toast.error('Failed to remove agent');
      }
    } catch {
      toast.error('Network error');
    }
  };

  const localDecisions = decisions.filter((d) => !d.source.endsWith('_feed'));
  const blocked = localDecisions.filter((d) => d.action === 'block').length;
  const onlineAgents = agents.filter((a) => a.status === 'online').length;
  const recentBlockedByIp = localDecisions
    .filter((d) => d.action === 'block')
    .filter((d, i, arr) => i === arr.findIndex((x) => x.ip === d.ip));

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">
            BannKenn<span className="text-red-500">.</span>
          </h1>
          <p className="text-muted-foreground text-sm mt-0.5">Self-hosted IPS Monitor</p>
        </div>
        <div className="flex items-center gap-3">
          {lastUpdated && (
            <span className="text-xs text-muted-foreground">
              Updated {lastUpdated.toLocaleTimeString()}
            </span>
          )}
          <Badge
            variant={health === 'ok' ? 'default' : health === 'error' ? 'destructive' : 'secondary'}
            className="gap-1.5"
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                health === 'ok'
                  ? 'bg-green-400'
                  : health === 'error'
                  ? 'bg-red-400'
                  : 'bg-gray-400'
              }`}
            />
            {health === 'ok'
              ? 'Server online'
              : health === 'error'
              ? 'Server offline'
              : 'Connecting…'}
          </Badge>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <StatCard label="Total decisions" value={localDecisions.length} />
        <StatCard label="Blocked IPs" value={blocked} accent="red" />
        <StatCard label="Registered agents" value={agents.length} />
        <StatCard label="Agents online" value={onlineAgents} accent="green" />
      </div>

      {/* SSH Access Notification — shown to all viewers */}
      {sshLogins.length > 0 && (
        <div>
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-3 flex items-center gap-2">
            <span className="inline-block w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
            SSH Access Events
          </h2>
          <div className="rounded-xl border border-amber-800/50 bg-amber-950/20 overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="border-amber-800/30">
                  <TableHead>User</TableHead>
                  <TableHead>Source IP</TableHead>
                  <TableHead>Agent</TableHead>
                  <TableHead>Country / ISP</TableHead>
                  <TableHead>Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sshLogins.map((ev) => (
                  <TableRow key={ev.id} className="border-amber-800/20">
                    <TableCell>
                      <Badge className="bg-amber-900/50 text-amber-300 border-amber-700 hover:bg-amber-900/50 font-mono">
                        SSH ACCESS
                      </Badge>
                      <span className="ml-2 font-mono text-amber-200">{ev.username}</span>
                    </TableCell>
                    <TableCell className="font-mono text-sm">{ev.ip}</TableCell>
                    <TableCell className="text-muted-foreground text-sm">{ev.agent_name}</TableCell>
                    <TableCell className="text-muted-foreground text-xs">
                      {[ev.country, ev.asn_org].filter(Boolean).join(' · ') || '—'}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-xs whitespace-nowrap">
                      {new Date(ev.created_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      )}

      {/* Agent Status table */}
      <div>
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-3">
          Agent Status
        </h2>
        <div className="rounded-xl border border-border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last Seen</TableHead>
                <TableHead>Registered</TableHead>
                <TableHead>ButterflyShield</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {agents.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-10 text-muted-foreground">
                    No agents registered
                  </TableCell>
                </TableRow>
              ) : (
                agents.map((agent) => (
                  <TableRow key={agent.id}>
                    <TableCell className="font-medium">
                      <Link
                        href={`/agents/${agent.id}`}
                        className="text-blue-400 hover:text-blue-300 hover:underline underline-offset-2"
                      >
                        {agent.nickname ?? agent.name}
                      </Link>
                      {agent.nickname && (
                        <span className="ml-1.5 text-xs text-muted-foreground">
                          ({agent.name})
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          agent.status === 'online'
                            ? 'default'
                            : agent.status === 'offline'
                            ? 'destructive'
                            : 'secondary'
                        }
                        className={
                          agent.status === 'online'
                            ? 'bg-green-900/50 text-green-400 border-green-800 hover:bg-green-900/50'
                            : ''
                        }
                      >
                        {agent.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-xs whitespace-nowrap">
                      {agent.last_seen_at
                        ? new Date(agent.last_seen_at).toLocaleString()
                        : 'Never'}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-xs whitespace-nowrap">
                      {new Date(agent.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      {agent.butterfly_shield_enabled === true ? (
                        <Badge className="bg-purple-900/50 text-purple-300 border-purple-800 hover:bg-purple-900/50 text-xs">
                          Active
                        </Badge>
                      ) : agent.butterfly_shield_enabled === false ? (
                        <span className="text-xs text-muted-foreground">Inactive</span>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => openEdit(agent)}
                          className="h-7 px-2 text-xs"
                        >
                          <Pencil className="h-3 w-3 mr-1" />
                          Edit
                        </Button>
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-7 px-2 text-xs text-destructive hover:text-destructive hover:bg-destructive/10"
                            >
                              <Trash2 className="h-3 w-3 mr-1" />
                              Remove
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>Remove agent?</AlertDialogTitle>
                              <AlertDialogDescription>
                                This will remove{' '}
                                <strong>{agent.nickname ?? agent.name}</strong> from the server.
                                The agent will need to re-register to appear again.
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Cancel</AlertDialogCancel>
                              <AlertDialogAction
                                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                onClick={() => handleRemove(agent)}
                              >
                                Remove
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </div>

      {/* Recent Decisions table */}
      <div>
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-3">
          Recent Decisions
        </h2>
        <div className="rounded-xl border border-border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>IP</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Time</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {recentBlockedByIp.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-12 text-muted-foreground">
                    No blocked IPs yet
                  </TableCell>
                </TableRow>
              ) : (
                recentBlockedByIp.map((d) => (
                  <TableRow key={d.id}>
                    <TableCell className="font-mono">{d.ip}</TableCell>
                    <TableCell>
                      <Badge
                        variant={d.action === 'block' ? 'destructive' : 'secondary'}
                      >
                        {d.action}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground max-w-xs truncate">
                      {d.reason}
                    </TableCell>
                    <TableCell className="text-muted-foreground">{d.source}</TableCell>
                    <TableCell className="text-muted-foreground text-xs whitespace-nowrap">
                      {new Date(d.created_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </div>

      <p className="text-center text-xs text-muted-foreground">
        Auto-refreshes every {POLL_INTERVAL / 1000}s · BannKenn
      </p>

      {/* Edit nickname dialog */}
      <Dialog open={!!editingAgent} onOpenChange={(open) => !open && setEditingAgent(null)}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle>Rename agent</DialogTitle>
          </DialogHeader>
          <div className="py-2">
            <Input
              value={editNickname}
              onChange={(e) => setEditNickname(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleRename();
                if (e.key === 'Escape') setEditingAgent(null);
              }}
              placeholder="Enter nickname"
              autoFocus
            />
          </div>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline" size="sm">
                Cancel
              </Button>
            </DialogClose>
            <Button size="sm" onClick={handleRename} disabled={editLoading || !editNickname.trim()}>
              {editLoading ? 'Saving…' : 'Save'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function StatCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: number;
  accent?: 'red' | 'green';
}) {
  return (
    <div className="bg-card border border-border rounded-xl px-5 py-4">
      <p className="text-xs text-muted-foreground uppercase tracking-widest mb-1">{label}</p>
      <p
        className={`text-3xl font-bold tabular-nums ${
          accent === 'red' ? 'text-red-400' : accent === 'green' ? 'text-green-400' : 'text-foreground'
        }`}
      >
        {value}
      </p>
    </div>
  );
}
