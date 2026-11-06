import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export type SaasPlanTier = 'starter' | 'growth' | 'enterprise';

export interface SaasPlanCatalogEntry {
  tier: SaasPlanTier;
  name: string;
  monthlyPriceUsd: number;
  monthlyRunQuota: number;
  stripePriceEnvKey: string;
  features: string[];
}

export const SAAS_BILLING_PLANS: Record<SaasPlanTier, SaasPlanCatalogEntry> = {
  starter: {
    tier: 'starter',
    name: 'AI Forge Starter',
    monthlyPriceUsd: 99,
    monthlyRunQuota: 100,
    stripePriceEnvKey: 'STRIPE_PRICE_STARTER_ID',
    features: [
      '100 Governed Runs / month',
      '9-Rule Deterministic PEP',
      'SHA-256 Evidence Bundles',
    ],
  },
  growth: {
    tier: 'growth',
    name: 'AI Forge Growth',
    monthlyPriceUsd: 499,
    monthlyRunQuota: 1_000,
    stripePriceEnvKey: 'STRIPE_PRICE_GROWTH_ID',
    features: [
      '1,000 Governed Runs / month',
      'Live GitHub + OSV.dev Scanner',
      'Universal Agent Gateway SDK (Python/TS)',
    ],
  },
  enterprise: {
    tier: 'enterprise',
    name: 'AI Forge Enterprise',
    monthlyPriceUsd: 2_500,
    monthlyRunQuota: 10_000,
    stripePriceEnvKey: 'STRIPE_PRICE_ENTERPRISE_ID',
    features: [
      '10,000 Governed Runs / month',
      'Ed25519 Boardroom Compliance Certificates',
      'Four-Eyes HITL + PostgreSQL RLS + Priority SLA',
    ],
  },
};

const processedStripeEventIds = new Map<string, number>();
const EVENT_REPLAY_TTL_MS = 15 * 60 * 1000;
const MAX_PROCESSED_EVENTS = 5_000;

export function isStripeEventReplayed(eventId: string, nowMs = Date.now()): boolean {
  if (processedStripeEventIds.size > MAX_PROCESSED_EVENTS) {
    for (const [id, expiresAt] of processedStripeEventIds.entries()) {
      if (expiresAt <= nowMs) {
        processedStripeEventIds.delete(id);
      }
    }
  }
  const existingExpiry = processedStripeEventIds.get(eventId);
  if (existingExpiry && existingExpiry > nowMs) {
    return true;
  }
  processedStripeEventIds.set(eventId, nowMs + EVENT_REPLAY_TTL_MS);
  return false;
}

export function resetStripeEventReplayCacheForTests(): void {
  processedStripeEventIds.clear();
}

/**
 * Verifies Stripe's `Stripe-Signature` header (`t=<unix_ts>,v1=<hex_hmac>`).
 * Fails closed when the signature header or secret is missing, when the timestamp
 * drifts beyond `toleranceSeconds` (default 300s), or when the HMAC-SHA256 digest mismatches.
 */
export function verifyStripeWebhookSignature(
  rawBody: string,
  signatureHeader: string | null,
  webhookSecret: string | null | undefined,
  options?: { toleranceSeconds?: number; nowSeconds?: number }
): { valid: boolean; reason?: string; timestamp?: number } {
  if (!webhookSecret || webhookSecret.trim().length === 0) {
    return { valid: false, reason: 'stripe_webhook_secret_not_configured' };
  }
  if (!signatureHeader || signatureHeader.trim().length === 0) {
    return { valid: false, reason: 'missing_stripe_signature_header' };
  }

  const parts = signatureHeader.split(',').map((p) => p.trim());
  const timestampPart = parts.find((p) => p.startsWith('t='));
  const v1Parts = parts.filter((p) => p.startsWith('v1='));

  if (!timestampPart || v1Parts.length === 0) {
    return { valid: false, reason: 'malformed_stripe_signature_header' };
  }

  const timestamp = Number(timestampPart.slice(2));
  if (!Number.isFinite(timestamp) || timestamp <= 0) {
    return { valid: false, reason: 'invalid_signature_timestamp' };
  }

  const toleranceSeconds = options?.toleranceSeconds ?? 300;
  const nowSeconds = options?.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - timestamp) > toleranceSeconds) {
    return { valid: false, reason: 'stripe_signature_timestamp_out_of_tolerance' };
  }

  const signedPayload = `${timestamp}.${rawBody}`;
  const expectedHex = createHmac('sha256', webhookSecret).update(signedPayload).digest('hex');
  const expectedBuf = Buffer.from(expectedHex, 'hex');

  for (const v1 of v1Parts) {
    const candidateHex = v1.slice(3);
    try {
      const candidateBuf = Buffer.from(candidateHex, 'hex');
      if (
        candidateBuf.length === expectedBuf.length &&
        timingSafeEqual(candidateBuf, expectedBuf)
      ) {
        return { valid: true, timestamp };
      }
    } catch {
      // Ignore malformed hex candidate
    }
  }

  return { valid: false, reason: 'invalid_stripe_signature_hmac' };
}

/**
 * Helper to sign a Stripe webhook payload using `t=...,v1=...` format.
 */
export function computeStripeSignatureHeader(
  rawBody: string,
  webhookSecret: string,
  timestampSeconds = Math.floor(Date.now() / 1000)
): string {
  const hmacHex = createHmac('sha256', webhookSecret)
    .update(`${timestampSeconds}.${rawBody}`)
    .digest('hex');
  return `t=${timestampSeconds},v1=${hmacHex}`;
}

export function resolveStripeWebhookSecret(): string | null {
  if (process.env.STRIPE_WEBHOOK_SECRET) {
    return process.env.STRIPE_WEBHOOK_SECRET;
  }
  if (process.env.NODE_ENV !== 'production') {
    return 'whsec_aiforge_dev_stripe_secret_v1';
  }
  return null;
}

export async function createStripeCheckoutSession(input: {
  organizationId: string;
  organizationName: string;
  planTier: SaasPlanTier;
  customerEmail?: string;
  originUrl: string;
}): Promise<{
  sessionId: string;
  checkoutUrl: string;
  mode: 'stripe-live-api' | 'signed-sandbox-checkout';
  plan: SaasPlanCatalogEntry;
  simulatedWebhookEvent?: {
    rawBody: string;
    signatureHeader: string;
  };
}> {
  const plan = SAAS_BILLING_PLANS[input.planTier];
  const stripeSecretKey = process.env.STRIPE_SECRET_KEY;

  if (stripeSecretKey && stripeSecretKey.startsWith('sk_')) {
    const form = new URLSearchParams();
    form.set('mode', 'subscription');
    form.set('client_reference_id', input.organizationId);
    form.set('success_url', `${input.originUrl}/settings?billing=success&plan=${input.planTier}`);
    form.set('cancel_url', `${input.originUrl}/settings?billing=cancelled`);
    if (input.customerEmail) {
      form.set('customer_email', input.customerEmail);
    }
    form.set('metadata[organizationId]', input.organizationId);
    form.set('metadata[planTier]', input.planTier);
    form.set('line_items[0][quantity]', '1');

    const configuredPriceId = process.env[plan.stripePriceEnvKey];
    if (configuredPriceId) {
      form.set('line_items[0][price]', configuredPriceId);
    } else {
      form.set('line_items[0][price_data][currency]', 'usd');
      form.set('line_items[0][price_data][unit_amount]', String(plan.monthlyPriceUsd * 100));
      form.set('line_items[0][price_data][recurring][interval]', 'month');
      form.set('line_items[0][price_data][product_data][name]', plan.name);
    }

    const res = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${stripeSecretKey}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: form.toString(),
      redirect: 'error',
      signal: AbortSignal.timeout(10_000),
    });

    if (!res.ok) {
      throw new Error(`stripe_checkout_error_${res.status}`);
    }
    const data = (await res.json()) as { id: string; url: string };
    return {
      sessionId: data.id,
      checkoutUrl: data.url,
      mode: 'stripe-live-api',
      plan,
    };
  }

  // Signed sandbox checkout mode when STRIPE_SECRET_KEY is not set in local/self-hosted environment
  const sessionId = `cs_test_${randomBytes(10).toString('hex')}`;
  const eventPayload = {
    id: `evt_${randomBytes(10).toString('hex')}`,
    type: 'checkout.session.completed',
    created: Math.floor(Date.now() / 1000),
    data: {
      object: {
        id: sessionId,
        client_reference_id: input.organizationId,
        amount_total: plan.monthlyPriceUsd * 100,
        currency: 'usd',
        payment_status: 'paid',
        metadata: {
          organizationId: input.organizationId,
          planTier: input.planTier,
        },
      },
    },
  };
  const rawBody = JSON.stringify(eventPayload);
  const webhookSecret = resolveStripeWebhookSecret() ?? 'whsec_aiforge_dev_stripe_secret_v1';
  const signatureHeader = computeStripeSignatureHeader(rawBody, webhookSecret);

  return {
    sessionId,
    checkoutUrl: `${input.originUrl}/settings?billing=sandbox_ready&session_id=${sessionId}&plan=${input.planTier}`,
    mode: 'signed-sandbox-checkout',
    plan,
    simulatedWebhookEvent:
      process.env.NODE_ENV !== 'production'
        ? { rawBody, signatureHeader }
        : undefined,
  };
}

