import { NextResponse } from 'next/server';

const SERVER_URL = process.env.BANNKENN_SERVER_URL ?? 'http://localhost:3022';

export async function GET() {
  try {
    const res = await fetch(`${SERVER_URL}/api/v1/decisions`, {
      next: { revalidate: 0 },
    });
    if (!res.ok) {
      return NextResponse.json({ error: 'upstream error' }, { status: res.status });
    }
    const data = await res.json();
    return NextResponse.json(data);
  } catch {
    return NextResponse.json({ error: 'server unreachable' }, { status: 502 });
  }
}
