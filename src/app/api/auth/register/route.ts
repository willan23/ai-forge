import { NextResponse } from 'next/server';
import { z } from 'zod';
import { registerOrganizationAndAdminUser } from '../../../../lib/auth/users';
import { checkRateLimit } from '../../../../lib/security/rate-limit';
import { assertCsrfOrigin, sanitizeApiError } from '../../../../lib/security/http-guards';

const RegisterSchema = z
  .object({
    name: z.string().min(2).max(120),
    email: z.string().email().max(180),
    password: z.string().min(8).max(128),
    organizationName: z.string().min(2).max(120),
    planTier: z.enum(['starter', 'growth', 'enterprise']).optional(),
  })
  .strict();

export async function POST(request: Request) {
  try {
    assertCsrfOrigin(request);
    const forwardedFor = request.headers.get('x-forwarded-for') ?? 'local';
    const rl = checkRateLimit(
      {
        userId: forwardedFor.slice(0, 64),
        organizationId: 'public_registration',
        endpoint: 'POST:/api/auth/register',
      },
      { maxRequests: 10, windowMs: 60_000 }
    );
    if (!rl.allowed) {
      return NextResponse.json({ error: 'rate_limit_exceeded' }, { status: 429 });
    }

    const body = RegisterSchema.parse(await request.json());
    const result = await registerOrganizationAndAdminUser(body);

    return NextResponse.json(result, { status: 201 });
  } catch (e) {
    const msg = sanitizeApiError(e, 'registration_failed');
    const status = msg.startsWith('Forbidden') ? 403 : 400;
    return NextResponse.json({ error: msg }, { status });
  }
}
