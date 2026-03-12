import { NextRequest, NextResponse } from 'next/server';

const SERVER_URL = process.env.BANNKENN_SERVER_URL ?? 'http://localhost:3022';

export async function GET(request: NextRequest) {
  const ip = request.nextUrl.searchParams.get('ip')?.trim();
  if (!ip) {
    return NextResponse.json({ error: 'Missing ip query param' }, { status: 400 });
  }

  const historyLimit = request.nextUrl.searchParams.get('history_limit') ?? '200';

  try {
    const res = await fetch(
      `${SERVER_URL}/api/v1/ip-lookup?ip=${encodeURIComponent(ip)}&history_limit=${encodeURIComponent(historyLimit)}`,
      { cache: 'no-store' }
    );

    if (!res.ok) {
      if (res.status === 400) {
        return NextResponse.json(
          { error: 'Enter a valid IPv4 or IPv6 address' },
          { status: 400 }
        );
      }

      return NextResponse.json({ error: 'Failed to fetch IP lookup' }, { status: res.status });
    }

    return NextResponse.json(await res.json());
  } catch {
    return NextResponse.json({ error: 'Server unavailable' }, { status: 503 });
  }
}
