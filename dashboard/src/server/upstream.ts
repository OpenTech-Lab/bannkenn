import { NextRequest, NextResponse } from 'next/server';

const SERVER_URL = process.env.BANNKENN_SERVER_URL ?? 'http://localhost:3022';

function buildUpstreamUrl(path: string, search?: URLSearchParams) {
  const url = new URL(path, SERVER_URL);
  if (search) {
    url.search = search.toString();
  }
  return url.toString();
}

async function relayResponse(response: Response) {
  if (response.status === 204) {
    return new NextResponse(null, { status: response.status });
  }

  const body = await response.text();
  return new NextResponse(body, {
    status: response.status,
    headers: {
      'Content-Type': response.headers.get('Content-Type') ?? 'application/json',
    },
  });
}

export async function proxyGet(request: NextRequest, path: string) {
  try {
    const response = await fetch(buildUpstreamUrl(path, request.nextUrl.searchParams), {
      cache: 'no-store',
    });
    return relayResponse(response);
  } catch {
    return NextResponse.json({ error: 'Server unavailable' }, { status: 503 });
  }
}

export async function proxyJson(request: NextRequest, path: string, method: 'POST' | 'PATCH') {
  try {
    const body = await request.json();
    const response = await fetch(buildUpstreamUrl(path), {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return relayResponse(response);
  } catch {
    return NextResponse.json({ error: 'Server unavailable' }, { status: 503 });
  }
}

export async function proxyDelete(path: string) {
  try {
    const response = await fetch(buildUpstreamUrl(path), { method: 'DELETE' });
    return relayResponse(response);
  } catch {
    return NextResponse.json({ error: 'Server unavailable' }, { status: 503 });
  }
}
