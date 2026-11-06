import { NextResponse } from 'next/server';
import { getSystemHealthService } from '../../../lib/services/platform';

export async function GET() {
  try {
    const health = await getSystemHealthService();
    return NextResponse.json(health);
  } catch (e) {
    return NextResponse.json(
      { status: 'degraded', error: e instanceof Error ? e.message : 'Health check failed' },
      { status: 500 }
    );
  }
}

