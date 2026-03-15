const SERVER_URL = process.env.BANNKENN_SERVER_URL ?? 'http://localhost:3022';
const CACHE_TTL_MS = 60_000;

let cachedFeeds: unknown = null;
let cachedAt = 0;

export async function GET() {
  const now = Date.now();
  if (cachedFeeds !== null && now - cachedAt < CACHE_TTL_MS) {
    return Response.json(cachedFeeds);
  }

  try {
    const res = await fetch(`${SERVER_URL}/api/v1/community/feeds`, { cache: 'no-store' });
    if (!res.ok) return Response.json({ error: 'Failed to fetch feeds' }, { status: 502 });
    const feeds = await res.json();
    cachedFeeds = feeds;
    cachedAt = now;
    return Response.json(feeds);
  } catch {
    return Response.json({ error: 'Server unavailable' }, { status: 503 });
  }
}
