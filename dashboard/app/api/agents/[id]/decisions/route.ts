import { NextRequest, NextResponse } from 'next/server';

const SERVER_URL = process.env.BANNKENN_SERVER_URL ?? 'http://localhost:3022';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const limit = request.nextUrl.searchParams.get('limit') ?? '1000';
    const res = await fetch(`${SERVER_URL}/api/v1/agents/${id}/decisions?limit=${limit}`, {
      cache: 'no-store',
    });

    if (!res.ok) {
      return NextResponse.json({ error: 'Failed to fetch agent decisions' }, { status: res.status });
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch {
    return NextResponse.json({ error: 'Server unavailable' }, { status: 503 });
  }
}
