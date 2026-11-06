import { NextResponse } from 'next/server';
import { demoAuthContext } from '../../../../lib/auth/session';
import {
  getDecryptedTenantSecret,
  verifyGitHubWebhookSignature,
} from '../../../../lib/security/vault';
import { checkRateLimit } from '../../../../lib/security/rate-limit';
import { sanitizeApiError } from '../../../../lib/security/http-guards';
import { executeLiveRepositoryAuditService } from '../../../../lib/services/platform';

const seenDeliveryIds = new Set<string>();

export async function POST(request: Request) {
  try {
    const ctx = demoAuthContext();
    const rl = checkRateLimit(
      {
        userId: 'github-webhook',
        organizationId: ctx.organizationId,
        endpoint: 'POST:/api/webhooks/github',
      },
      { windowMs: 60_000, maxRequests: 30 }
    );
    if (!rl.allowed) {
      return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
    }

    const rawBody = await request.text();
    const eventType = request.headers.get('x-github-event') ?? 'ping';
    const signature = request.headers.get('x-hub-signature-256');
    const deliveryId = request.headers.get('x-github-delivery');

    const secret =
      getDecryptedTenantSecret(ctx.organizationId, 'githubWebhookSecret') ??
      process.env.GITHUB_WEBHOOK_SECRET;

    // Fail-closed HMAC verification (ACH-03 / A45): require secret & valid X-Hub-Signature-256
    if (!secret) {
      return NextResponse.json(
        {
          error:
            'Unauthorized: GitHub Webhook secret is not configured in Tenant Vault or GITHUB_WEBHOOK_SECRET',
        },
        { status: 401 }
      );
    }

    const valid = verifyGitHubWebhookSignature(rawBody, signature, secret);
    if (!valid) {
      return NextResponse.json(
        { error: 'Unauthorized: Invalid X-Hub-Signature-256 HMAC signature' },
        { status: 401 }
      );
    }

    // Anti-replay deduplication by X-GitHub-Delivery header
    if (deliveryId) {
      if (seenDeliveryIds.has(deliveryId)) {
        return NextResponse.json(
          { error: 'Duplicate webhook delivery (replay blocked)' },
          { status: 409 }
        );
      }
      if (seenDeliveryIds.size >= 5000) {
        const oldest = seenDeliveryIds.values().next().value;
        if (oldest) seenDeliveryIds.delete(oldest);
      }
      seenDeliveryIds.add(deliveryId);
    }

    const payload = (rawBody ? JSON.parse(rawBody) : {}) as {
      action?: string;
      number?: number;
      pull_request?: { number?: number };
      repository?: { full_name?: string };
    };

    if (eventType === 'ping') {
      return NextResponse.json({
        ok: true,
        event: 'ping',
        message: 'AI Forge GitHub Webhook receiver active and verified.',
      });
    }

    if (
      eventType === 'pull_request' &&
      ['opened', 'synchronize', 'reopened'].includes(payload.action ?? '')
    ) {
      const repo = payload.repository?.full_name ?? 'expressjs/express';
      const prNumber = payload.pull_request?.number ?? payload.number;

      const auditResult = await executeLiveRepositoryAuditService(ctx, {
        repo,
        prNumber,
        packageToScan: 'lodash',
      });

      return NextResponse.json({
        ok: true,
        event: eventType,
        action: payload.action,
        repo,
        prNumber,
        runId: auditResult.run.id,
        bundleDigest: auditResult.evidenceBundle.integrity.bundleDigest,
        approvalId: auditResult.approval.id,
      });
    }

    return NextResponse.json({
      ok: true,
      event: eventType,
      ignored: true,
      reason: 'Event or action does not trigger an automated PR security audit',
    });
  } catch (e) {
    return NextResponse.json(
      { error: sanitizeApiError(e, 'Webhook processing failed') },
      { status: 400 }
    );
  }
}
