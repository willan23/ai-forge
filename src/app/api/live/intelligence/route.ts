import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../../lib/auth/session';
import { executeLiveIntelligenceSearchService } from '../../../../lib/services/platform';
import { checkRateLimit } from '../../../../lib/security/rate-limit';

export async function POST(request: Request) {
  try {
    const ctx = await getAuthContext();
    const rl = checkRateLimit(
      {
        userId: ctx.userId,
        organizationId: ctx.organizationId,
        endpoint: 'POST /api/live/intelligence',
      },
      { windowMs: 60_000, maxRequests: 60 }
    );
    if (!rl.allowed) {
      return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
    }

    const body = (await request.json().catch(() => ({}))) as {
      mode?: 'search' | 'browse' | 'osv';
      query?: string;
      url?: string;
      package?: string;
      version?: string;
      ecosystem?: string;
    };

    const result = await executeLiveIntelligenceSearchService(ctx, {
      mode: body.mode ?? 'search',
      query: body.query,
      url: body.url,
      package: body.package,
      version: body.version,
      ecosystem: body.ecosystem,
    });

    return NextResponse.json(result);
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Live intelligence search failed' },
      { status: 400 }
    );
  }
}

