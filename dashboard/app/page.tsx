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

interface WhitelistEntry {
  id: number;
  ip: string;
  note: string | null;
  created_at: string;
}

const POLL_INTERVAL = 10_000;

export default function Dashboard() {
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [agents, setAgents] = useState<AgentStatus[]>([]);
  const [sshLogins, setSshLogins] = useState<SshLoginEvent[]>([]);
  const [whitelist, setWhitelist] = useState<WhitelistEntry[]>([]);
  const [activityTab, setActivityTab] = useState<'decisions' | 'ssh'>('decisions');
  const [health, setHealth] = useState<'ok' | 'error' | 'loading'>('loading');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  // Edit dialog state
  const [editingAgent, setEditingAgent] = useState<AgentStatus | null>(null);
  const [editNickname, setEditNickname] = useState('');
  const [editLoading, setEditLoading] = useState(false);
  const [whitelistIp, setWhitelistIp] = useState('');
  const [whitelistNote, setWhitelistNote] = useState('');
  const [editingWhitelistId, setEditingWhitelistId] = useState<number | null>(null);
  const [whitelistSaving, setWhitelistSaving] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const [healthRes, decisionsRes, agentsRes, sshLoginsRes, whitelistRes] = await Promise.all([
        fetch('/api/health'),
        fetch('/api/decisions'),
        fetch('/api/agents'),
        fetch('/api/ssh-logins'),
        fetch('/api/whitelist'),
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

      if (whitelistRes.ok) {
        setWhitelist(await whitelistRes.json());
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

  const resetWhitelistForm = () => {
    setWhitelistIp('');
    setWhitelistNote('');
    setEditingWhitelistId(null);
  };

  const openWhitelistEdit = (entry: WhitelistEntry) => {
    setWhitelistIp(entry.ip);
    setWhitelistNote(entry.note ?? '');
    setEditingWhitelistId(entry.id);
  };

  const handleWhitelistSave = async () => {
    if (!whitelistIp.trim()) return;
    setWhitelistSaving(true);
    try {
      const res = await fetch('/api/whitelist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip: whitelistIp.trim(),
          note: whitelistNote.trim() || undefined,
        }),
      });
      if (res.ok) {
        toast.success(editingWhitelistId ? 'Whitelist entry updated' : 'Whitelist entry added');
        resetWhitelistForm();
        fetchData();
      } else if (res.status === 400) {
        toast.error('Enter a valid IP address');
      } else {
        toast.error('Failed to save whitelist entry');
      }
    } catch {
      toast.error('Network error');
    } finally {
      setWhitelistSaving(false);
    }
  };

  const handleWhitelistRemove = async (entry: WhitelistEntry) => {
    try {
      const res = await fetch(`/api/whitelist/${entry.id}`, { method: 'DELETE' });
      if (res.ok) {
        toast.success(`Removed ${entry.ip} from whitelist`);
        if (editingWhitelistId === entry.id) {
          resetWhitelistForm();
        }
        fetchData();
      } else {
        toast.error('Failed to remove whitelist entry');
      }
    } catch {
      toast.error('Network error');
    }
  };

  const localDecisions = decisions.filter((d) => !isCommunitySource(d.source));
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

      {/* Whitelist */}
      <div>
        <div className="flex flex-col gap-2 mb-3 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">
              Whitelist
            </h2>
            <p className="text-xs text-muted-foreground mt-1">
              Whitelisted IPs or CIDRs are skipped by agents and removed from local firewall blocks on the next sync.
            </p>
          </div>
          <span className="text-xs text-muted-foreground">
            {whitelist.length} entr{whitelist.length === 1 ? 'y' : 'ies'}
          </span>
        </div>
        <div className="rounded-xl border border-border bg-card/30 p-4 space-y-4">
          <div className="grid gap-3 lg:grid-cols-[minmax(0,220px)_minmax(0,1fr)_auto]">
            <Input
              value={whitelistIp}
              onChange={(e) => setWhitelistIp(e.target.value)}
              placeholder="203.0.113.4 or 203.0.113.0/24"
              disabled={whitelistSaving || editingWhitelistId !== null}
            />
            <Input
              value={whitelistNote}
              onChange={(e) => setWhitelistNote(e.target.value)}
              placeholder="Office IP, home IP, monitoring node…"
              disabled={whitelistSaving}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleWhitelistSave();
              }}
            />
            <div className="flex gap-2">
              <Button
                size="sm"
                onClick={handleWhitelistSave}
                disabled={whitelistSaving || !whitelistIp.trim()}
              >
                {whitelistSaving ? 'Saving…' : editingWhitelistId ? 'Update note' : 'Add IP/CIDR'}
              </Button>
              {editingWhitelistId !== null && (
                <Button variant="outline" size="sm" onClick={resetWhitelistForm} disabled={whitelistSaving}>
                  Cancel
                </Button>
              )}
            </div>
          </div>
          {editingWhitelistId !== null && (
            <p className="text-xs text-muted-foreground">
              IP changes use remove + add. Edit mode updates the note for the selected entry.
            </p>
          )}
          <div className="rounded-lg border border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP</TableHead>
                  <TableHead>Note</TableHead>
                  <TableHead>Added</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {whitelist.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} className="text-center py-10 text-muted-foreground">
                      No whitelist entries yet
                    </TableCell>
                  </TableRow>
                ) : (
                  whitelist.map((entry) => (
                    <TableRow key={entry.id}>
                      <TableCell className="font-mono text-sm">{entry.ip}</TableCell>
                      <TableCell className="text-muted-foreground text-sm">
                        {entry.note?.trim() || '—'}
                      </TableCell>
                      <TableCell className="text-muted-foreground text-xs whitespace-nowrap">
                        {new Date(entry.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => openWhitelistEdit(entry)}
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
                                <AlertDialogTitle>Remove whitelist entry?</AlertDialogTitle>
                                <AlertDialogDescription>
                                  BannKenn will be allowed to block <strong>{entry.ip}</strong> again after agents sync.
                                </AlertDialogDescription>
                              </AlertDialogHeader>
                              <AlertDialogFooter>
                                <AlertDialogCancel>Cancel</AlertDialogCancel>
                                <AlertDialogAction
                                  className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                  onClick={() => handleWhitelistRemove(entry)}
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
      </div>

      {/* Recent Activity table */}
      <div>
        <div className="flex flex-col gap-3 mb-3 sm:flex-row sm:items-center sm:justify-between">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">
            Recent Activity
          </h2>
          <div className="inline-flex w-full rounded-lg border border-border bg-card/60 p-1 sm:w-auto">
            <button
              type="button"
              onClick={() => setActivityTab('decisions')}
              aria-pressed={activityTab === 'decisions'}
              className={`flex-1 rounded-md px-3 py-1.5 text-xs font-medium transition sm:flex-none ${
                activityTab === 'decisions'
                  ? 'bg-red-950/60 text-red-200 shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Recent Decisions
              <span className="ml-2 text-[11px] text-muted-foreground">{recentBlockedByIp.length}</span>
            </button>
            <button
              type="button"
              onClick={() => setActivityTab('ssh')}
              aria-pressed={activityTab === 'ssh'}
              className={`flex-1 rounded-md px-3 py-1.5 text-xs font-medium transition sm:flex-none ${
                activityTab === 'ssh'
                  ? 'bg-amber-950/60 text-amber-200 shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              SSH Access Events
              <span className="ml-2 text-[11px] text-muted-foreground">{sshLogins.length}</span>
            </button>
          </div>
        </div>
        <div className="rounded-xl border border-border overflow-hidden">
          {activityTab === 'decisions' ? (
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
                        <Badge variant={d.action === 'block' ? 'destructive' : 'secondary'}>
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
          ) : (
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
                {sshLogins.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-12 text-muted-foreground">
                      No SSH access events yet
                    </TableCell>
                  </TableRow>
                ) : (
                  sshLogins.map((ev) => (
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
                  ))
                )}
              </TableBody>
            </Table>
          )}
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

function isCommunitySource(source: string) {
  return source.endsWith('_feed') || source.startsWith('firehol_');
}
