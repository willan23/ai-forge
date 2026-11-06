import { NextResponse } from 'next/server';
import { z } from 'zod';
import { getAuthContext } from '../../../../lib/auth/session';
import { assertPermission } from '../../../../lib/auth/rbac';
import {
  createStripeCheckoutSession,
  SAAS_BILLING_PLANS,
} from '../../../../lib/billing/stripe';
import { getTenantSaasConfig } from '../../../../lib/security/vault';
import { checkRateLimit } from '../../../../lib/security/rate-limit';
import { assertCsrfOrigin, sanitizeApiError } from '../../../../lib/security/http-guards';

const CheckoutRequestSchema = z
  .object({
    planTier: z.enum(['starter', 'growth', 'enterprise']),
    customerEmail: z.string().email().max(180).optional(),
  })
  .strict();

export async function GET() {
  try {
    const ctx = await getAuthContext();
    assertPermission(ctx, 'agent:read');
    const cfg = getTenantSaasConfig(ctx.organizationId);
    return NextResponse.json({
      activePlanTier: cfg.planTier,
      monthlyRunQuota: cfg.monthlyRunQuota,
      stripeLiveConfigured: Boolean(
        process.env.STRIPE_SECRET_KEY && process.env.STRIPE_SECRET_KEY.startsWith('sk_')
      ),
      plans: Object.values(SAAS_BILLING_PLANS),
    });
  } catch (e) {
    const msg = sanitizeApiError(e, 'Failed to load billing plans');
    const status = msg.startsWith('Unauthorized') ? 401 : msg.startsWith('Forbidden') ? 403 : 400;
    return NextResponse.json({ error: msg }, { status });
  }
}

export async function POST(request: Request) {
  try {
    assertCsrfOrigin(request);
    const ctx = await getAuthContext();
    assertPermission(ctx, 'policy:write');

    const rl = checkRateLimit(
      {
        userId: ctx.userId,
        organizationId: ctx.organizationId,
        endpoint: 'POST:/api/billing/checkout',
      },
      { maxRequests: 15, windowMs: 60_000 }
    );
    if (!rl.allowed) {
      return NextResponse.json({ error: 'rate_limit_exceeded' }, { status: 429 });
    }

    const body = CheckoutRequestSchema.parse(await request.json());
    const cfg = getTenantSaasConfig(ctx.organizationId);
    const url = new URL(request.url);
    const originUrl = `${url.protocol}//${url.host}`;

    const session = await createStripeCheckoutSession({
      organizationId: ctx.organizationId,
      organizationName: cfg.organizationName,
      planTier: body.planTier,
      customerEmail: body.customerEmail,
      originUrl,
    });

    return NextResponse.json(session, { status: 201 });
  } catch (e) {
    const msg = sanitizeApiError(e, 'Failed to create checkout session');
    const status = msg.startsWith('Unauthorized') ? 401 : msg.startsWith('Forbidden') ? 403 : 400;
    return NextResponse.json({ error: msg }, { status });
  }
}
