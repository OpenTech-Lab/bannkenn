'use client';

import { useCallback, useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { ChevronRight, Globe, RefreshCw } from 'lucide-react';

interface CommunityFeed {
  source: string;
  ip_count: number;
  first_seen_at: string;
  last_seen_at: string;
}

interface FeedIp {
  ip: string;
  reason: string;
  sightings: number;
  first_seen_at: string;
  last_seen_at: string;
}

interface FeedMeta {
  title: string;
  description: string;
  tags: string[];
}

const FEED_META: Record<string, FeedMeta> = {
  ipsum_feed: {
    title: 'IPsum',
    description: 'Daily curated blocklist of IPs with multiple abuse reports aggregated from various threat intel sources.',
    tags: ['threat-intel', 'blocklist', 'daily'],
  },
  firehol_feed: {
    title: 'FireHOL',
    description: 'FireHOL IP lists — aggressive blocklists from FireHOL Level 1 & Level 3, targeting known attackers and botnets.',
    tags: ['firehol', 'botnet', 'attacker'],
  },
};

function getFeedMeta(source: string): FeedMeta {
  if (FEED_META[source]) return FEED_META[source];
  const title = source
    .replace(/_feed$/, '')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
  return { title, description: `Community feed: ${source}`, tags: ['community'] };
}

const POLL_INTERVAL = 30_000;

export default function CommunityPage() {
  const [feeds, setFeeds] = useState<CommunityFeed[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const [selectedFeed, setSelectedFeed] = useState<CommunityFeed | null>(null);
  const [feedIps, setFeedIps] = useState<FeedIp[]>([]);
  const [ipsLoading, setIpsLoading] = useState(false);

  const fetchFeeds = useCallback(async (showSpinner = false) => {
    if (showSpinner) setRefreshing(true);
    try {
      const res = await fetch('/api/community/feeds');
      if (!res.ok) {
        setError('Failed to fetch community feeds');
        return;
      }
      const data: CommunityFeed[] = await res.json();
      setFeeds(data);
      setError(null);
      setLastUpdated(new Date());
    } catch {
      setError('Cannot reach server');
    } finally {
      if (showSpinner) setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchFeeds();
    const id = setInterval(() => fetchFeeds(), POLL_INTERVAL);
    return () => clearInterval(id);
  }, [fetchFeeds]);

  const openFeed = useCallback(async (feed: CommunityFeed) => {
    setSelectedFeed(feed);
    setFeedIps([]);
    setIpsLoading(true);
    try {
      const res = await fetch(`/api/community/feeds/${encodeURIComponent(feed.source)}/ips`);
      if (res.ok) setFeedIps(await res.json());
    } finally {
      setIpsLoading(false);
    }
  }, []);

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Community IP Lists</h1>
          <p className="text-gray-400 text-sm mt-0.5">Threat intelligence feeds ingested automatically</p>
        </div>
        <div className="flex items-center gap-3">
          {lastUpdated && (
            <span className="text-xs text-gray-500">Updated {lastUpdated.toLocaleTimeString()}</span>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => fetchFeeds(true)}
            disabled={refreshing}
            className="gap-1.5 border-gray-700 text-gray-300 hover:text-white"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 text-red-300 px-4 py-3 rounded-lg text-sm">
          {error}
        </div>
      )}

      {/* Feed cards */}
      {feeds.length === 0 && !error ? (
        <div className="text-center py-20 text-gray-600">
          <Globe className="h-10 w-10 mx-auto mb-3 opacity-30" />
          <p>No community feeds ingested yet</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {feeds.map((feed) => {
            const meta = getFeedMeta(feed.source);
            return (
              <button
                key={feed.source}
                onClick={() => openFeed(feed)}
                className="text-left rounded-xl border border-gray-800 bg-gray-900/40 p-5 hover:border-gray-600 hover:bg-gray-900/70 transition-all group"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Globe className="h-4 w-4 text-gray-500 shrink-0 mt-0.5" />
                    <span className="font-semibold text-white group-hover:text-blue-400 transition-colors">
                      {meta.title}
                    </span>
                  </div>
                  <ChevronRight className="h-4 w-4 text-gray-600 group-hover:text-gray-400 shrink-0 mt-0.5 transition-colors" />
                </div>

                <p className="text-xs text-gray-500 mt-2 mb-3 leading-relaxed">{meta.description}</p>

                <div className="flex items-center justify-between">
                  <span className="text-2xl font-bold text-red-400 tabular-nums">
                    {feed.ip_count.toLocaleString()}
                    <span className="text-xs font-normal text-gray-500 ml-1">IPs</span>
                  </span>
                  <code className="text-xs text-gray-600 bg-gray-800 px-1.5 py-0.5 rounded">
                    {feed.source}
                  </code>
                </div>

                <div className="mt-3 flex flex-wrap gap-1.5">
                  {meta.tags.map((tag) => (
                    <Badge key={tag} variant="secondary" className="text-xs px-1.5 py-0 bg-gray-800 text-gray-400 border-gray-700">
                      {tag}
                    </Badge>
                  ))}
                </div>

                <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-gray-600">
                  <div>
                    <span className="text-gray-700">Added</span>
                    <p className="text-gray-500">{new Date(feed.first_seen_at).toLocaleDateString()}</p>
                  </div>
                  <div>
                    <span className="text-gray-700">Updated</span>
                    <p className="text-gray-500">{new Date(feed.last_seen_at).toLocaleDateString()}</p>
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      )}

      <p className="text-center text-xs text-gray-700">Auto-refreshes every {POLL_INTERVAL / 1000}s</p>

      {/* Detail dialog */}
      <Dialog open={!!selectedFeed} onOpenChange={(open) => { if (!open) setSelectedFeed(null); }}>
        <DialogContent className="max-w-3xl max-h-[80vh] flex flex-col bg-gray-950 border-gray-800">
          <DialogHeader>
            <DialogTitle className="text-white flex items-center gap-2">
              <Globe className="h-4 w-4 text-gray-400" />
              {selectedFeed ? getFeedMeta(selectedFeed.source).title : ''}
              {selectedFeed && (
                <Badge variant="secondary" className="ml-1 bg-gray-800 text-gray-400 border-gray-700 text-xs">
                  {selectedFeed.ip_count.toLocaleString()} IPs
                </Badge>
              )}
            </DialogTitle>
          </DialogHeader>

          <div className="overflow-auto flex-1 mt-2 rounded-lg border border-gray-800">
            {ipsLoading ? (
              <div className="text-center py-12 text-gray-600">Loading IPs...</div>
            ) : feedIps.length === 0 ? (
              <div className="text-center py-12 text-gray-600">No IPs found</div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="border-gray-800 bg-gray-900 hover:bg-gray-900">
                    <TableHead className="text-gray-500 text-xs uppercase tracking-widest">IP</TableHead>
                    <TableHead className="text-gray-500 text-xs uppercase tracking-widest">Reason</TableHead>
                    <TableHead className="text-gray-500 text-xs uppercase tracking-widest text-right">Sightings</TableHead>
                    <TableHead className="text-gray-500 text-xs uppercase tracking-widest">First Seen</TableHead>
                    <TableHead className="text-gray-500 text-xs uppercase tracking-widest">Last Seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {feedIps.map((ip) => (
                    <TableRow key={ip.ip} className="border-gray-800/50 hover:bg-gray-900/40">
                      <TableCell className="font-mono text-sm text-gray-200">{ip.ip}</TableCell>
                      <TableCell className="text-sm text-gray-400 max-w-xs truncate">{ip.reason}</TableCell>
                      <TableCell className="text-sm text-gray-300 tabular-nums text-right">{ip.sightings}</TableCell>
                      <TableCell className="text-xs text-gray-500 whitespace-nowrap">
                        {new Date(ip.first_seen_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell className="text-xs text-gray-500 whitespace-nowrap">
                        {new Date(ip.last_seen_at).toLocaleDateString()}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
