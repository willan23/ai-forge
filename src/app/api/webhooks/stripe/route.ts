import { NextResponse } from 'next/server';
import { z } from 'zod';
import {
  isStripeEventReplayed,
  resolveStripeWebhookSecret,
  verifyStripeWebhookSignature,
} from '../../../../lib/billing/stripe';
import { updateTenantSaasConfig } from '../../../../lib/security/vault';
import { getStore } from '../../../../lib/store';
import { checkRateLimit } from '../../../../lib/security/rate-limit';
import { sanitizeApiError } from '../../../../lib/security/http-guards';

const StripeEventSchema = z.object({
  id: z.string().min(3).max(128),
  type: z.enum([
    'checkout.session.completed',
    'customer.subscription.updated',
    'customer.subscription.deleted',
  ]),
  data: z.object({
    object: z.object({
      id: z.string().optional(),
      client_reference_id: z.string().optional().nullable(),
      metadata: z
        .object({
          organizationId: z.string().optional(),
          planTier: z.enum(['starter', 'growth', 'enterprise']).optional(),
        })
        .optional()
        .nullable(),
    }),
  }),
});

export async function POST(request: Request) {
  try {
    const forwardedFor = request.headers.get('x-forwarded-for') ?? 'stripe-webhook';
    const rl = checkRateLimit(
      {
        userId: forwardedFor.slice(0, 64),
        organizationId: 'stripe_webhook',
        endpoint: 'POST:/api/webhooks/stripe',
      },
      { maxRequests: 60, windowMs: 60_000 }
    );
    if (!rl.allowed) {
      return NextResponse.json({ error: 'rate_limit_exceeded' }, { status: 429 });
    }

    const rawBody = await request.text();
    const sigHeader = request.headers.get('stripe-signature');
    const webhookSecret = resolveStripeWebhookSecret();

    const sigCheck = verifyStripeWebhookSignature(rawBody, sigHeader, webhookSecret);
    if (!sigCheck.valid) {
      return NextResponse.json(
        { error: sigCheck.reason ?? 'invalid_stripe_signature' },
        { status: 401 }
      );
    }

    const parsed = StripeEventSchema.parse(JSON.parse(rawBody));

    if (isStripeEventReplayed(parsed.id)) {
      return NextResponse.json(
        { error: 'stripe_event_replay_detected', eventId: parsed.id },
        { status: 409 }
      );
    }

    const obj = parsed.data.object;
    const organizationId =
      obj.metadata?.organizationId ?? obj.client_reference_id ?? 'org_demo_wgf';

    const store = await getStore();

    if (parsed.type === 'customer.subscription.deleted') {
      const updated = updateTenantSaasConfig(organizationId, {
        planTier: 'starter',
      });
      await store.writeAudit({
        organizationId,
        actorType: 'system',
        actorId: 'stripe-webhook',
        action: 'billing.subscription_cancelled',
        targetType: 'organization',
        targetId: organizationId,
        metadataJson: {
          stripeEventId: parsed.id,
          planTier: 'starter',
          monthlyRunQuota: updated.monthlyRunQuota,
        },
      });
      return NextResponse.json({
        status: 'processed',
        eventId: parsed.id,
        organizationId,
        planTier: updated.planTier,
        monthlyRunQuota: updated.monthlyRunQuota,
      });
    }

    const targetPlanTier = obj.metadata?.planTier ?? 'growth';
    const updated = updateTenantSaasConfig(organizationId, {
      planTier: targetPlanTier,
    });

    await store.writeAudit({
      organizationId,
      actorType: 'system',
      actorId: 'stripe-webhook',
      action: 'billing.subscription_activated',
      targetType: 'organization',
      targetId: organizationId,
      metadataJson: {
        stripeEventId: parsed.id,
        eventType: parsed.type,
        planTier: updated.planTier,
        monthlyRunQuota: updated.monthlyRunQuota,
      },
    });

    return NextResponse.json({
      status: 'processed',
      eventId: parsed.id,
      organizationId,
      planTier: updated.planTier,
      monthlyRunQuota: updated.monthlyRunQuota,
    });
  } catch (e) {
    const msg = sanitizeApiError(e, 'Stripe webhook processing failed');
    return NextResponse.json({ error: msg }, { status: 400 });
  }
}
