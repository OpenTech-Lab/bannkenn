'use client';

import Link from 'next/link';
import {
  Suspense,
  type FormEvent,
  type ReactNode,
  useEffect,
  useState,
  useTransition,
} from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
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

type IpLookupEvent = {
  id: number;
  source: string;
  source_label: string;
  agent_id: number | null;
  reason: string;
  level: 'alert' | 'listed' | 'block';
  log_path: string | null;
  country: string | null;
  asn_org: string | null;
  created_at: string;
};

type IpLookupDecision = {
  id: number;
  source: string;
  source_label: string;
  agent_id: number | null;
  reason: string;
  action: string;
  country: string | null;
  asn_org: string | null;
  created_at: string;
  expires_at: string | null;
};

type IpLookupMachineSummary = {
  agent_id: number | null;
  source: string;
  source_label: string;
  event_count: number;
  alert_count: number;
  listed_count: number;
  block_count: number;
  first_seen_at: string;
  last_seen_at: string;
  last_reason: string;
};

type IpLookupCommunityMatch = {
  source: string;
  matched_entry: string;
  reason: string;
  sightings: number;
  first_seen_at: string;
  last_seen_at: string;
};

type IpLookupResponse = {
  ip: string;
  country: string | null;
  asn_org: string | null;
  local_history: IpLookupEvent[];
  decision_history: IpLookupDecision[];
  machine_summaries: IpLookupMachineSummary[];
  community_matches: IpLookupCommunityMatch[];
};

type SummaryTone = 'red' | 'orange' | 'yellow' | 'gray';

export default function IpLookupPage() {
  return (
    <Suspense fallback={<LookupPageFallback />}>
      <IpLookupPageContent />
    </Suspense>
  );
}

function IpLookupPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const queryIp = searchParams.get('ip')?.trim() ?? '';

  const [input, setInput] = useState(queryIp);
  const [result, setResult] = useState<IpLookupResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [refreshNonce, setRefreshNonce] = useState(0);
  const [isPending, startTransition] = useTransition();

  useEffect(() => {
    setInput(queryIp);
  }, [queryIp]);

  useEffect(() => {
    if (!queryIp) {
      setResult(null);
      setError(null);
      setLoading(false);
      return;
    }

    const controller = new AbortController();

    async function loadLookup() {
      setLoading(true);
      setError(null);

      try {
        const res = await fetch(`/api/ip-lookup?ip=${encodeURIComponent(queryIp)}`, {
          cache: 'no-store',
          signal: controller.signal,
        });
        const data = await res.json().catch(() => null);

        if (!res.ok) {
          throw new Error(
            typeof data?.error === 'string' ? data.error : 'Failed to fetch IP lookup'
          );
        }

        setResult(data as IpLookupResponse);
      } catch (err) {
        if (controller.signal.aborted) return;
        setResult(null);
        setError(err instanceof Error ? err.message : 'Failed to fetch IP lookup');
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      }
    }

    loadLookup();
    return () => controller.abort();
  }, [queryIp, refreshNonce]);

  const summary = result ? summarizeResult(result) : null;

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = input.trim();

    if (!trimmed) {
      startTransition(() => {
        router.push('/lookup');
      });
      return;
    }

    if (trimmed === queryIp) {
      setRefreshNonce((value) => value + 1);
      return;
    }

    startTransition(() => {
      router.push(`/lookup?ip=${encodeURIComponent(trimmed)}`);
    });
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">IP Lookup</p>
          <h1 className="text-3xl font-bold text-white mt-2">Search risk history by IP</h1>
          <p className="text-sm text-muted-foreground mt-2 max-w-2xl">
            Check whether an IP was blocked locally, why it was flagged, which machines saw it,
            and whether it exists on an ingested community list.
          </p>
        </div>
        <Link href="/community" className="text-sm text-blue-400 hover:text-blue-300">
          View community feeds
        </Link>
      </div>

      <div className="rounded-xl border border-border bg-card/30 p-4 space-y-3">
        <form onSubmit={handleSubmit} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto]">
          <Input
            value={input}
            onChange={(event) => setInput(event.target.value)}
            placeholder="203.0.113.44 or 2001:db8::44"
            autoComplete="off"
            spellCheck={false}
            className="font-mono"
          />
          <Button type="submit" disabled={loading || isPending}>
            {loading || isPending ? 'Searching…' : 'Search IP'}
          </Button>
        </form>
        <p className="text-xs text-muted-foreground">
          Searches exact IP history locally and checks community feed entries that match the IP
          directly or through a covering CIDR.
        </p>
      </div>

      {!queryIp ? (
        <EmptyState
          title="Enter an IP address"
          body="Use the search box above to inspect local detections, block decisions, and community list matches."
        />
      ) : loading ? (
        <EmptyState title="Searching…" body={`Loading history for ${queryIp}`} />
      ) : error ? (
        <div className="rounded-xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : result ? (
        <>
          <div className="grid gap-4 xl:grid-cols-[minmax(0,1.7fr)_minmax(0,1fr)]">
            <div className="rounded-xl border border-border bg-card p-5 space-y-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
                    Result Summary
                  </p>
                  <h2 className="text-2xl font-semibold mt-2 font-mono text-white">
                    {result.ip}
                  </h2>
                </div>
                <Badge className={summaryBadgeClass(summary?.tone ?? 'gray')}>
                  {summary?.label ?? 'No data'}
                </Badge>
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                <SummaryItem label="Country" value={result.country ?? 'Unknown'} />
                <SummaryItem label="Organization" value={result.asn_org ?? 'Unknown'} />
                <SummaryItem label="Latest reason" value={summary?.reason ?? 'No local risk reason found'} />
                <SummaryItem label="Latest timestamp" value={summary?.timestamp ?? '—'} />
              </div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-1">
              <StatCard label="Machines seen" value={result.machine_summaries.length} />
              <StatCard label="Local events" value={result.local_history.length} accent="yellow" />
              <StatCard label="Block decisions" value={result.decision_history.length} accent="red" />
              <StatCard
                label="Community matches"
                value={result.community_matches.length}
                accent="orange"
              />
            </div>
          </div>

          <SectionCard title="Machine History">
            <div className="rounded-lg border border-border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Machine</TableHead>
                    <TableHead>Latest Reason</TableHead>
                    <TableHead className="text-right">Events</TableHead>
                    <TableHead className="text-right">Alerts</TableHead>
                    <TableHead className="text-right">Listed</TableHead>
                    <TableHead className="text-right">Blocks</TableHead>
                    <TableHead>First Seen</TableHead>
                    <TableHead>Last Seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {result.machine_summaries.length === 0 ? (
                    <EmptyTableRow colSpan={8} message="This IP has not been seen by any local machine yet." />
                  ) : (
                    result.machine_summaries.map((machine) => (
                      <TableRow key={`${machine.source}-${machine.agent_id ?? 'na'}`}>
                        <TableCell className="font-medium">
                          <SourceCell
                            source={machine.source}
                            sourceLabel={machine.source_label}
                            agentId={machine.agent_id}
                          />
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground max-w-sm truncate">
                          {machine.last_reason}
                        </TableCell>
                        <TableCell className="text-right tabular-nums">{machine.event_count}</TableCell>
                        <TableCell className="text-right tabular-nums text-yellow-400">
                          {machine.alert_count}
                        </TableCell>
                        <TableCell className="text-right tabular-nums text-orange-400">
                          {machine.listed_count}
                        </TableCell>
                        <TableCell className="text-right tabular-nums text-red-400">
                          {machine.block_count}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                          {formatTimestamp(machine.first_seen_at)}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                          {formatTimestamp(machine.last_seen_at)}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </SectionCard>

          <div className="grid gap-4 xl:grid-cols-2">
            <SectionCard title="Local Risk Events">
              <div className="rounded-lg border border-border overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Machine</TableHead>
                      <TableHead>Reason</TableHead>
                      <TableHead>Level</TableHead>
                      <TableHead>Log Path</TableHead>
                      <TableHead>Timestamp</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {result.local_history.length === 0 ? (
                      <EmptyTableRow colSpan={5} message="No local telemetry events for this IP." />
                    ) : (
                      result.local_history.map((event) => (
                        <TableRow key={event.id}>
                          <TableCell className="font-medium">
                            <SourceCell
                              source={event.source}
                              sourceLabel={event.source_label}
                              agentId={event.agent_id}
                            />
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground max-w-sm truncate">
                            {event.reason}
                          </TableCell>
                          <TableCell>
                            <Badge className={levelBadgeClass(event.level)}>{event.level}</Badge>
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground max-w-xs truncate">
                            {event.log_path ?? '—'}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                            {formatTimestamp(event.created_at)}
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </SectionCard>

            <SectionCard title="Local Block Decisions">
              <div className="rounded-lg border border-border overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Source</TableHead>
                      <TableHead>Reason</TableHead>
                      <TableHead>Action</TableHead>
                      <TableHead>Timestamp</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {result.decision_history.length === 0 ? (
                      <EmptyTableRow colSpan={4} message="No local block decisions for this IP." />
                    ) : (
                      result.decision_history.map((decision) => (
                        <TableRow key={decision.id}>
                          <TableCell className="font-medium">
                            <SourceCell
                              source={decision.source}
                              sourceLabel={decision.source_label}
                              agentId={decision.agent_id}
                            />
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground max-w-sm truncate">
                            {decision.reason}
                          </TableCell>
                          <TableCell>
                            <Badge className="bg-red-950/70 text-red-300 border border-red-900/70">
                              {decision.action}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                            {formatTimestamp(decision.created_at)}
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </SectionCard>
          </div>

          <SectionCard title="Community List Matches">
            <div className="rounded-lg border border-border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Feed</TableHead>
                    <TableHead>Matched Entry</TableHead>
                    <TableHead>Reason</TableHead>
                    <TableHead className="text-right">Sightings</TableHead>
                    <TableHead>First Seen</TableHead>
                    <TableHead>Last Seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {result.community_matches.length === 0 ? (
                    <EmptyTableRow colSpan={6} message="This IP does not exist in the ingested community feeds." />
                  ) : (
                    result.community_matches.map((match) => (
                      <TableRow key={`${match.source}-${match.matched_entry}`}>
                        <TableCell className="font-medium">{formatCommunitySource(match.source)}</TableCell>
                        <TableCell className="font-mono text-xs">{match.matched_entry}</TableCell>
                        <TableCell className="text-sm text-muted-foreground max-w-sm truncate">
                          {match.reason}
                        </TableCell>
                        <TableCell className="text-right tabular-nums">{match.sightings}</TableCell>
                        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                          {formatTimestamp(match.first_seen_at)}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                          {formatTimestamp(match.last_seen_at)}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </SectionCard>
        </>
      ) : null}
    </div>
  );
}

function LookupPageFallback() {
  return (
    <div className="max-w-6xl mx-auto px-4 py-8">
      <EmptyState title="Loading IP lookup…" body="Preparing the lookup page." />
    </div>
  );
}

function SectionCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-xl border border-border bg-card p-5 space-y-4">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.3em]">
          {title}
        </h2>
      </div>
      {children}
    </section>
  );
}

function StatCard({
  label,
  value,
  accent = 'gray',
}: {
  label: string;
  value: number;
  accent?: 'gray' | 'yellow' | 'red' | 'orange';
}) {
  const accentClass =
    accent === 'red'
      ? 'text-red-400'
      : accent === 'yellow'
      ? 'text-yellow-400'
      : accent === 'orange'
      ? 'text-orange-400'
      : 'text-white';

  return (
    <div className="rounded-xl border border-border bg-card px-4 py-4">
      <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">{label}</p>
      <p className={`mt-3 text-3xl font-semibold tabular-nums ${accentClass}`}>{value}</p>
    </div>
  );
}

function SummaryItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border/70 bg-background/40 px-4 py-3">
      <p className="text-xs uppercase tracking-[0.25em] text-muted-foreground">{label}</p>
      <p className="mt-2 text-sm text-white break-words">{value}</p>
    </div>
  );
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-xl border border-dashed border-border bg-card/20 px-6 py-12 text-center">
      <h2 className="text-lg font-semibold text-white">{title}</h2>
      <p className="text-sm text-muted-foreground mt-2">{body}</p>
    </div>
  );
}

function EmptyTableRow({ colSpan, message }: { colSpan: number; message: string }) {
  return (
    <TableRow>
      <TableCell colSpan={colSpan} className="py-12 text-center text-sm text-muted-foreground">
        {message}
      </TableCell>
    </TableRow>
  );
}

function SourceCell({
  source,
  sourceLabel,
  agentId,
}: {
  source: string;
  sourceLabel: string;
  agentId: number | null;
}) {
  if (agentId !== null) {
    return (
      <>
        <Link href={`/agents/${agentId}`} className="text-blue-400 hover:text-blue-300 hover:underline">
          {sourceLabel}
        </Link>
        {sourceLabel !== source ? (
          <span className="ml-1.5 text-xs text-muted-foreground">({source})</span>
        ) : null}
      </>
    );
  }

  return <span>{sourceLabel}</span>;
}

function summarizeResult(result: IpLookupResponse) {
  const latestDecision = result.decision_history[0];
  if (latestDecision) {
    return {
      label: 'Blocked locally',
      tone: 'red' as SummaryTone,
      reason: latestDecision.reason,
      timestamp: formatTimestamp(latestDecision.created_at),
    };
  }

  const latestEvent = result.local_history[0];
  const latestCommunity = result.community_matches[0];
  if (latestEvent && latestCommunity) {
    return {
      label: 'Seen locally + listed',
      tone: 'orange' as SummaryTone,
      reason: `${latestEvent.reason} · also matched ${formatCommunitySource(latestCommunity.source)}`,
      timestamp: formatTimestamp(latestEvent.created_at),
    };
  }

  if (latestEvent) {
    return {
      label: 'Seen locally',
      tone: 'yellow' as SummaryTone,
      reason: latestEvent.reason,
      timestamp: formatTimestamp(latestEvent.created_at),
    };
  }

  if (latestCommunity) {
    return {
      label: 'On community list',
      tone: 'orange' as SummaryTone,
      reason: `${formatCommunitySource(latestCommunity.source)} matched ${latestCommunity.matched_entry}`,
      timestamp: formatTimestamp(latestCommunity.last_seen_at),
    };
  }

  return {
    label: 'No matches',
    tone: 'gray' as SummaryTone,
    reason: 'No local history or community match was found for this IP',
    timestamp: '—',
  };
}

function summaryBadgeClass(tone: SummaryTone) {
  if (tone === 'red') {
    return 'bg-red-950/70 text-red-300 border border-red-900/70';
  }
  if (tone === 'orange') {
    return 'bg-orange-950/70 text-orange-300 border border-orange-900/70';
  }
  if (tone === 'yellow') {
    return 'bg-yellow-950/70 text-yellow-300 border border-yellow-900/70';
  }
  return 'bg-secondary text-secondary-foreground border border-border';
}

function levelBadgeClass(level: IpLookupEvent['level']) {
  if (level === 'block') {
    return 'bg-red-950/70 text-red-300 border border-red-900/70';
  }
  if (level === 'listed') {
    return 'bg-orange-950/70 text-orange-300 border border-orange-900/70';
  }
  return 'bg-yellow-950/70 text-yellow-300 border border-yellow-900/70';
}

function formatTimestamp(value: string) {
  return new Date(value).toLocaleString();
}

function formatCommunitySource(source: string) {
  return source
    .replace(/_feed$/, '')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}
