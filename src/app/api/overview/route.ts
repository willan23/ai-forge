import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../lib/auth/session';
import { getPlatformOverviewService } from '../../../lib/services/platform';
import { checkRateLimit } from '../../../lib/security/rate-limit';

export async function GET() {
  try {
    const ctx = await getAuthContext();
    const rl = checkRateLimit({
      userId: ctx.userId,
      organizationId: ctx.organizationId,
      endpoint: 'GET:/api/overview',
    });
    if (!rl.allowed) {
      return NextResponse.json({ error: 'rate_limit_exceeded' }, { status: 429 });
    }
    const overview = await getPlatformOverviewService(ctx);
    return NextResponse.json(overview);
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Failed to load overview' },
      { status: 500 }
    );
  }
}

