const SERVER_URL = process.env.BANNKENN_SERVER_URL ?? 'http://localhost:3022';

export async function GET() {
  try {
    const res = await fetch(`${SERVER_URL}/api/v1/community/ips`, { cache: 'no-store' });

    if (!res.ok) {
      return Response.json({ error: 'Failed to fetch community IPs' }, { status: 502 });
    }

    const data = await res.json();
    return Response.json(data);
  } catch {
    return Response.json({ error: 'Server unavailable' }, { status: 503 });
  }
}
