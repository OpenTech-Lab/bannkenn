import { NextRequest } from 'next/server';

const SERVER_URL = process.env.BANNKENN_SERVER_URL ?? 'http://localhost:3022';

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ source: string }> }
) {
  try {
    const { source } = await params;
    const res = await fetch(`${SERVER_URL}/api/v1/community/feeds/${source}/ips`, {
      cache: 'no-store',
    });
    if (!res.ok) return Response.json({ error: 'Failed to fetch feed IPs' }, { status: 502 });
    return Response.json(await res.json());
  } catch {
    return Response.json({ error: 'Server unavailable' }, { status: 503 });
  }
}
