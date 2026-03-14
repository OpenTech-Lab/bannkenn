import { NextRequest } from 'next/server';
import { proxyGet, proxyJson } from '@/src/server/upstream';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  return proxyGet(request, `/api/v1/agents/${id}/containment-actions`);
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  return proxyJson(request, `/api/v1/agents/${id}/containment-actions`, 'POST');
}
