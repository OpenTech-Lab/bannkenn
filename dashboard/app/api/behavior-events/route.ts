import { NextRequest } from 'next/server';
import { proxyGet } from '@/src/server/upstream';

export async function GET(request: NextRequest) {
  return proxyGet(request, '/api/v1/behavior_events');
}
