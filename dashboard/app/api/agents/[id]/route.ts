import { NextRequest } from 'next/server';
import { proxyDelete, proxyGet, proxyJson } from '@/src/server/upstream';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  return proxyGet(request, `/api/v1/agents/${id}`);
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  return proxyJson(request, `/api/v1/agents/${id}`, 'PATCH');
}

export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  return proxyDelete(`/api/v1/agents/${id}`);
}
