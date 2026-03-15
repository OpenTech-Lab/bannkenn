'use client';

import { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import { Pencil, Trash2 } from 'lucide-react';
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

interface WhitelistEntry {
  id: number;
  ip: string;
  note: string | null;
  created_at: string;
}

const POLL_INTERVAL = 30_000;

export default function WhitelistPage() {
  const [whitelist, setWhitelist] = useState<WhitelistEntry[]>([]);
  const [whitelistIp, setWhitelistIp] = useState('');
  const [whitelistNote, setWhitelistNote] = useState('');
  const [editingWhitelistId, setEditingWhitelistId] = useState<number | null>(null);
  const [whitelistSaving, setWhitelistSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchWhitelist = useCallback(async () => {
    try {
      const res = await fetch('/api/whitelist');
      if (!res.ok) {
        setError('Failed to fetch whitelist');
        return;
      }

      setWhitelist(await res.json());
      setError(null);
      setLastUpdated(new Date());
    } catch {
      setError('Cannot reach server');
    }
  }, []);

  useEffect(() => {
    fetchWhitelist();
    const id = setInterval(fetchWhitelist, POLL_INTERVAL);
    return () => clearInterval(id);
  }, [fetchWhitelist]);

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
        fetchWhitelist();
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
        fetchWhitelist();
      } else {
        toast.error('Failed to remove whitelist entry');
      }
    } catch {
      toast.error('Network error');
    }
  };

  return (
    <div className="px-6 py-8 space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Whitelist</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Whitelisted IPs or CIDRs are skipped by agents and removed from local firewall blocks on the next sync.
          </p>
        </div>
        <div className="text-xs text-muted-foreground space-y-1 text-left sm:text-right">
          <p>
            {whitelist.length} entr{whitelist.length === 1 ? 'y' : 'ies'}
          </p>
          {lastUpdated && <p>Updated {lastUpdated.toLocaleTimeString()}</p>}
        </div>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 text-red-300 px-4 py-3 rounded-lg text-sm">
          {error}
        </div>
      )}

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

      <p className="text-center text-xs text-muted-foreground">
        Auto-refreshes every {POLL_INTERVAL / 1000}s
      </p>
    </div>
  );
}
