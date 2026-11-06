import { NextResponse } from 'next/server';
import { z } from 'zod';
import { getAuthContext } from '../../../lib/auth/session';
import { assertPermission } from '../../../lib/auth/rbac';
import {
  getTenantSaasConfig,
  updateTenantSaasConfig,
  createGatewayApiKey,
  revokeGatewayApiKey,
  dispatchGovernanceWebhookAlert,
} from '../../../lib/security/vault';
import { checkRateLimit } from '../../../lib/security/rate-limit';
import { assertCsrfOrigin, sanitizeApiError } from '../../../lib/security/http-guards';
import { getStore } from '../../../lib/store';
import { listAgentsService } from '../../../lib/services/platform';

const SettingsPostSchema = z
  .object({
    action: z
      .enum(['update_config', 'create_key', 'revoke_key', 'test_webhook'])
      .optional(),
    organizationName: z.string().min(1).max(128).optional(),
    planTier: z.enum(['starter', 'growth', 'enterprise']).optional(),
    secrets: z
      .object({
        githubToken: z.string().max(512).optional(),
        openaiApiKey: z.string().max(512).optional(),
        nvidiaApiKey: z.string().max(512).optional(),
        geminiApiKey: z.string().max(512).optional(),
        webhookUrl: z.string().max(1024).optional(),
        githubWebhookSecret: z.string().max(512).optional(),
      })
      .strict()
      .optional(),
    keyName: z.string().min(1).max(128).optional(),
    keyId: z.string().min(1).max(128).optional(),
  })
  .strict();

function sanitizeConfigForClient(organizationId: string, usedRunsCount: number) {
  const cfg = getTenantSaasConfig(organizationId);
  return {
    organizationId: cfg.organizationId,
    organizationName: cfg.organizationName,
    planTier: cfg.planTier,
    monthlyRunQuota: cfg.monthlyRunQuota,
    usedRunsThisMonth: usedRunsCount,
    updatedAt: cfg.updatedAt,
    secretsStatus: {
      githubToken: cfg.secrets.githubToken?.maskedPreview ?? null,
      openaiApiKey: cfg.secrets.openaiApiKey?.maskedPreview ?? null,
      nvidiaApiKey: cfg.secrets.nvidiaApiKey?.maskedPreview ?? null,
      geminiApiKey: cfg.secrets.geminiApiKey?.maskedPreview ?? null,
      webhookUrl: cfg.secrets.webhookUrl?.maskedPreview ?? null,
      githubWebhookSecret: cfg.secrets.githubWebhookSecret?.maskedPreview ?? null,
    },
    apiKeys: cfg.apiKeys.map((k) => ({
      id: k.id,
      name: k.name,
      prefix: k.prefix,
      scopes: k.scopes,
      createdAt: k.createdAt,
      lastUsedAt: k.lastUsedAt ?? null,
      revoked: k.revoked,
    })),
  };
}

async function countOrganizationRuns(ctx: Awaited<ReturnType<typeof getAuthContext>>) {
  const store = await getStore();
  await store.ensureSeed();
  const agents = await listAgentsService(ctx);
  let count = 0;
  for (const agent of agents) {
    const runs = await store.listRuns(agent.id);
    count += runs.length;
  }
  return count;
}

export async function GET() {
  try {
    const ctx = await getAuthContext();
    assertPermission(ctx, 'agent:read');

    const rl = checkRateLimit(
      {
        userId: ctx.userId,
        organizationId: ctx.organizationId,
        endpoint: 'GET:/api/settings',
      },
      { windowMs: 60_000, maxRequests: 60 }
    );
    if (!rl.allowed) {
      return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
    }

    const usedRuns = await countOrganizationRuns(ctx);
    return NextResponse.json(sanitizeConfigForClient(ctx.organizationId, usedRuns));
  } catch (e) {
    const msg = sanitizeApiError(e, 'Failed to load settings');
    const status = msg.startsWith('Unauthorized')
      ? 401
      : msg.startsWith('Forbidden')
        ? 403
        : 400;
    return NextResponse.json({ error: msg }, { status });
  }
}

export async function POST(request: Request) {
  try {
    assertCsrfOrigin(request);
    const ctx = await getAuthContext();
    // Enforce administrative RBAC permission (fixes ACH-02 BFLA)
    assertPermission(ctx, 'policy:write');

    const rl = checkRateLimit(
      {
        userId: ctx.userId,
        organizationId: ctx.organizationId,
        endpoint: 'POST:/api/settings',
      },
      { windowMs: 60_000, maxRequests: 30 }
    );
    if (!rl.allowed) {
      return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
    }

    const rawBody = await request.json().catch(() => ({}));
    const parsed = SettingsPostSchema.safeParse(rawBody);
    if (!parsed.success) {
      return NextResponse.json(
        {
          error: `Invalid request schema: ${parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`,
        },
        { status: 400 }
      );
    }

    const body = parsed.data;
    const store = await getStore();
    const usedRuns = await countOrganizationRuns(ctx);

    if (body.action === 'create_key') {
      const created = createGatewayApiKey(
        ctx.organizationId,
        body.keyName ?? 'External Agent Key'
      );
      await store.writeAudit({
        organizationId: ctx.organizationId,
        actorType: 'user',
        actorId: ctx.userId,
        action: 'vault.api_key_created',
        targetType: 'api_key',
        targetId: created.record.id,
        metadataJson: { name: created.record.name, prefix: created.record.prefix },
      });
      return NextResponse.json({
        createdKey: created.rawKey,
        record: created.record,
        config: sanitizeConfigForClient(ctx.organizationId, usedRuns),
      });
    }

    if (body.action === 'revoke_key' && body.keyId) {
      revokeGatewayApiKey(ctx.organizationId, body.keyId);
      await store.writeAudit({
        organizationId: ctx.organizationId,
        actorType: 'user',
        actorId: ctx.userId,
        action: 'vault.api_key_revoked',
        targetType: 'api_key',
        targetId: body.keyId,
      });
      return NextResponse.json({
        revoked: true,
        config: sanitizeConfigForClient(ctx.organizationId, usedRuns),
      });
    }

    if (body.action === 'test_webhook') {
      const res = await dispatchGovernanceWebhookAlert(ctx.organizationId, {
        title: 'AI Forge Governance Alert Test',
        severity: 'info',
        eventType: 'webhook.test_ping',
        details: {
          organizationId: ctx.organizationId,
          triggeredBy: ctx.userId,
        },
      });
      return NextResponse.json({
        webhookTest: res,
        config: sanitizeConfigForClient(ctx.organizationId, usedRuns),
      });
    }

    updateTenantSaasConfig(ctx.organizationId, {
      organizationName: body.organizationName,
      planTier: body.planTier,
      secrets: body.secrets,
    });

    await store.writeAudit({
      organizationId: ctx.organizationId,
      actorType: 'user',
      actorId: ctx.userId,
      action: 'vault.config_updated',
      targetType: 'organization',
      targetId: ctx.organizationId,
      metadataJson: {
        planTier: body.planTier,
        updatedSecretFields: Object.keys(body.secrets ?? {}).filter((k) =>
          Boolean(body.secrets?.[k as keyof typeof body.secrets])
        ),
      },
    });

    return NextResponse.json({
      updated: true,
      config: sanitizeConfigForClient(ctx.organizationId, usedRuns),
    });
  } catch (e) {
    const msg = sanitizeApiError(e, 'Failed to update settings');
    const status = msg.startsWith('Unauthorized')
      ? 401
      : msg.startsWith('Forbidden')
        ? 403
        : 400;
    return NextResponse.json({ error: msg }, { status });
  }
}
