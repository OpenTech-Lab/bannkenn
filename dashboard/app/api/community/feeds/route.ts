const SERVER_URL = process.env.BANNKENN_SERVER_URL ?? 'http://localhost:3022';

export async function GET() {
  try {
    const res = await fetch(`${SERVER_URL}/api/v1/community/feeds`, { cache: 'no-store' });
    if (!res.ok) return Response.json({ error: 'Failed to fetch feeds' }, { status: 502 });
    return Response.json(await res.json());
  } catch {
    return Response.json({ error: 'Server unavailable' }, { status: 503 });
  }
}
