import { NextRequest, NextResponse } from 'next/server';

type IpWhoisResponse = {
  success?: boolean;
  country?: string;
  connection?: {
    org?: string;
    isp?: string;
  };
};

const cache = new Map<string, { country: string; organization: string; cachedAt: number }>();
const CACHE_TTL_MS = 1000 * 60 * 60; // 1 hour

export async function GET(request: NextRequest) {
  const ip = request.nextUrl.searchParams.get('ip')?.trim();
  if (!ip) {
    return NextResponse.json({ error: 'Missing ip query param' }, { status: 400 });
  }

  const now = Date.now();
  const cached = cache.get(ip);
  if (cached && now - cached.cachedAt < CACHE_TTL_MS) {
    return NextResponse.json({ ip, country: cached.country, organization: cached.organization, cached: true });
  }

  try {
    const upstream = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      cache: 'no-store',
      signal: AbortSignal.timeout(2500),
    });

    if (!upstream.ok) {
      return NextResponse.json(
        { ip, country: 'Unknown', organization: 'Unknown', error: 'lookup_failed' },
        { status: 200 }
      );
    }

    const data = (await upstream.json()) as IpWhoisResponse;
    const country = data.country ?? 'Unknown';
    const organization = data.connection?.org ?? data.connection?.isp ?? 'Unknown';

    cache.set(ip, { country, organization, cachedAt: now });

    return NextResponse.json({ ip, country, organization, cached: false });
  } catch {
    return NextResponse.json(
      { ip, country: 'Unknown', organization: 'Unknown', error: 'lookup_unavailable' },
      { status: 200 }
    );
  }
}
