'use client';

import { useEffect, useState, useCallback } from 'react';

interface Decision {
  id: number;
  ip: string;
  reason: string;
  action: string;
  source: string;
  created_at: string;
  expires_at: string | null;
}

interface HealthStatus {
  status: string;
}

const POLL_INTERVAL = 10_000;

export default function Dashboard() {
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [health, setHealth] = useState<'ok' | 'error' | 'loading'>('loading');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const [healthRes, decisionsRes] = await Promise.all([
        fetch('/api/health'),
        fetch('/api/decisions'),
      ]);

      if (healthRes.ok) {
        const h: HealthStatus = await healthRes.json();
        setHealth(h.status === 'ok' ? 'ok' : 'error');
      } else {
        setHealth('error');
      }

      if (decisionsRes.ok) {
        const d: Decision[] = await decisionsRes.json();
        setDecisions(d);
        setError(null);
      } else {
        setError('Failed to fetch decisions');
      }

      setLastUpdated(new Date());
    } catch (e) {
      setHealth('error');
      setError('Cannot reach server');
    }
  }, []);

  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, POLL_INTERVAL);
    return () => clearInterval(id);
  }, [fetchData]);

  const blocked = decisions.filter((d) => d.action === 'block').length;

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">
            BannKenn<span className="text-red-500">.</span>
          </h1>
          <p className="text-gray-400 text-sm mt-0.5">Self-hosted IPS Monitor</p>
        </div>
        <div className="flex items-center gap-3">
          {lastUpdated && (
            <span className="text-xs text-gray-500">
              Updated {lastUpdated.toLocaleTimeString()}
            </span>
          )}
          <span
            className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium ${
              health === 'ok'
                ? 'bg-green-900/50 text-green-400 border border-green-800'
                : health === 'error'
                ? 'bg-red-900/50 text-red-400 border border-red-800'
                : 'bg-gray-800 text-gray-400 border border-gray-700'
            }`}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                health === 'ok' ? 'bg-green-400' : health === 'error' ? 'bg-red-400' : 'bg-gray-400'
              }`}
            />
            {health === 'ok' ? 'Server online' : health === 'error' ? 'Server offline' : 'Connecting…'}
          </span>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
        <StatCard label="Total decisions" value={decisions.length} />
        <StatCard label="Blocked IPs" value={blocked} accent="red" />
        <StatCard label="Sources" value={[...new Set(decisions.map((d) => d.source))].length} />
      </div>

      {/* Error banner */}
      {error && (
        <div className="bg-red-900/30 border border-red-800 text-red-300 px-4 py-3 rounded-lg text-sm">
          {error}
        </div>
      )}

      {/* Decisions table */}
      <div>
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-widest mb-3">
          Recent Decisions
        </h2>
        <div className="rounded-xl border border-gray-800 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-900 border-b border-gray-800">
                <Th>IP</Th>
                <Th>Action</Th>
                <Th>Reason</Th>
                <Th>Source</Th>
                <Th>Time</Th>
              </tr>
            </thead>
            <tbody>
              {decisions.length === 0 ? (
                <tr>
                  <td colSpan={5} className="text-center py-12 text-gray-600">
                    No decisions yet
                  </td>
                </tr>
              ) : (
                decisions.map((d) => (
                  <tr
                    key={d.id}
                    className="border-b border-gray-800/50 hover:bg-gray-900/40 transition-colors"
                  >
                    <td className="px-4 py-3 font-mono text-gray-200">{d.ip}</td>
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-medium ${
                          d.action === 'block'
                            ? 'bg-red-900/50 text-red-400'
                            : 'bg-yellow-900/50 text-yellow-400'
                        }`}
                      >
                        {d.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-400 max-w-xs truncate">{d.reason}</td>
                    <td className="px-4 py-3 text-gray-500">{d.source}</td>
                    <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">
                      {new Date(d.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Footer */}
      <p className="text-center text-xs text-gray-700">
        Auto-refreshes every {POLL_INTERVAL / 1000}s · BannKenn MVP
      </p>
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
  accent?: 'red';
}) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4">
      <p className="text-xs text-gray-500 uppercase tracking-widest mb-1">{label}</p>
      <p
        className={`text-3xl font-bold tabular-nums ${
          accent === 'red' ? 'text-red-400' : 'text-white'
        }`}
      >
        {value}
      </p>
    </div>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-widest">
      {children}
    </th>
  );
}
