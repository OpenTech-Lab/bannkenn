import { NextRequest, NextResponse } from 'next/server';

const SERVER_URL = process.env.BANNKENN_SERVER_URL ?? 'http://localhost:3022';

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const listRes = await fetch(`${SERVER_URL}/api/v1/agents`, { cache: 'no-store' });
    if (!listRes.ok) {
      return new NextResponse(null, { status: listRes.status });
    }
    const agents = (await listRes.json()) as Array<{ id: number }>;
    const numericId = Number(id);
    const agent = agents.find((a) => a.id === numericId);
    if (!agent) {
      return new NextResponse(null, { status: 404 });
    }
    return NextResponse.json(agent);
  } catch {
    return new NextResponse(null, { status: 503 });
  }
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const body = await request.json();
    const res = await fetch(`${SERVER_URL}/api/v1/agents/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return new NextResponse(null, { status: res.status });
  } catch {
    return new NextResponse(null, { status: 503 });
  }
}

export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const res = await fetch(`${SERVER_URL}/api/v1/agents/${id}`, {
      method: 'DELETE',
    });
    return new NextResponse(null, { status: res.status });
  } catch {
    return new NextResponse(null, { status: 503 });
  }
}
