import { NextResponse } from 'next/server';
import { z } from 'zod';
import { getAuthContext } from '../../../../../lib/auth/session';
import { validateGatewayApiKey } from '../../../../../lib/security/vault';
import { checkRateLimit } from '../../../../../lib/security/rate-limit';
import { sanitizeApiError } from '../../../../../lib/security/http-guards';
import { authorizeExternalAgentActionService } from '../../../../../lib/services/platform';
import type { AuthContext } from '../../../../../lib/auth/rbac';

const GatewayAuthorizeSchema = z
  .object({
    externalAgentId: z.string().min(1).max(128).optional(),
    externalRunId: z.string().min(1).max(128).optional(),
    capability: z.string().min(1).max(128),
    action: z.string().min(1).max(128),
    effect: z.enum(['read', 'write', 'delete', 'network']).optional(),
    resource: z.string().min(1).max(512),
    dataClassification: z.enum(['public', 'internal', 'confidential', 'restricted']).optional(),
    currentCostUsd: z.number().min(0).max(100_000).optional(),
    currentToolCalls: z.number().int().min(0).max(10_000).optional(),
    egressDomain: z.string().max(256).optional(),
    purpose: z.string().max(512).optional(),
  })
  .strict();

async function resolveGatewayAuthContext(request: Request): Promise<AuthContext> {
  const authHeader = request.headers.get('authorization');
  if (authHeader?.startsWith('Bearer aiforge_live_')) {
    const token = authHeader.slice('Bearer '.length).trim();
    const record = validateGatewayApiKey(token);
    if (!record) {
      throw new Error('Unauthorized: Invalid or revoked AI Forge Gateway API Key');
    }
    return {
      userId: `apikey:${record.id}`,
      email: `${record.name}@gateway.aiforge.local`,
      organizationId: record.organizationId,
      workspaceIds: ['ws_demo_default'],
      role: 'operator',
    };
  }
  return getAuthContext();
}

export async function POST(request: Request) {
  try {
    const ctx = await resolveGatewayAuthContext(request);
    const rl = checkRateLimit(
      {
        userId: ctx.userId,
        organizationId: ctx.organizationId,
        endpoint: 'POST:/api/v1/gateway/authorize',
      },
      { windowMs: 60_000, maxRequests: 120 }
    );
    if (!rl.allowed) {
      return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
    }

    const rawBody = await request.json().catch(() => ({}));
    const parsed = GatewayAuthorizeSchema.safeParse(rawBody);
    if (!parsed.success) {
      return NextResponse.json(
        {
          error: `Invalid request schema: ${parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`,
        },
        { status: 400 }
      );
    }

    const body = parsed.data;
    const result = await authorizeExternalAgentActionService(ctx, {
      externalAgentId: body.externalAgentId,
      externalRunId: body.externalRunId,
      capability: body.capability,
      action: body.action,
      effect: body.effect ?? 'read',
      resource: body.resource,
      dataClassification: body.dataClassification,
      currentCostUsd: body.currentCostUsd,
      currentToolCalls: body.currentToolCalls,
      egressDomain: body.egressDomain,
      purpose: body.purpose,
    });

    return NextResponse.json(result);
  } catch (e) {
    const msg = sanitizeApiError(e, 'Gateway authorization failed');
    const status =
      msg.includes('API Key') || msg.startsWith('Unauthorized')
        ? 401
        : msg.startsWith('Forbidden')
          ? 403
          : 400;
    return NextResponse.json({ error: msg }, { status });
  }
}
