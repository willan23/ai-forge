import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../../lib/auth/session';
import { assertPermission } from '../../../../lib/auth/rbac';
import { checkRateLimit } from '../../../../lib/security/rate-limit';
import { assertCsrfOrigin, sanitizeApiError } from '../../../../lib/security/http-guards';
import { verifyEvidenceBundle } from '../../../../lib/domain/evidence/verify';

export async function POST(request: Request) {
  try {
    assertCsrfOrigin(request);
    const ctx = await getAuthContext();
    assertPermission(ctx, 'agent:read');

    const rl = checkRateLimit(
      {
        userId: ctx.userId,
        organizationId: ctx.organizationId,
        endpoint: 'POST:/api/evidence/verify',
      },
      { windowMs: 60_000, maxRequests: 60 }
    );
    if (!rl.allowed) {
      return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
    }

    const body = await request.json();
    const bundle = body.bundle ?? body;
    const report = verifyEvidenceBundle(bundle, {
      expectedReleaseDigest: body.expectedReleaseDigest,
      expectedPolicyDigest: body.expectedPolicyDigest,
    });
    return NextResponse.json(report);
  } catch (e) {
    const msg = sanitizeApiError(e, 'Verification failed');
    const status = msg.startsWith('Unauthorized')
      ? 401
      : msg.startsWith('Forbidden')
        ? 403
        : 400;
    return NextResponse.json({ error: msg }, { status });
  }
}
