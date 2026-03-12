import { NextRequest, NextResponse } from 'next/server';

const SERVER_URL = process.env.BANNKENN_SERVER_URL ?? 'http://localhost:3022';

export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const res = await fetch(`${SERVER_URL}/api/v1/whitelist/${id}`, {
      method: 'DELETE',
    });
    return new NextResponse(null, { status: res.status });
  } catch {
    return new NextResponse(null, { status: 503 });
  }
}
