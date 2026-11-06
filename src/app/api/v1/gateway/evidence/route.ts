import { NextResponse } from 'next/server';
import { z } from 'zod';
import { getAuthContext } from '../../../../../lib/auth/session';
import { validateGatewayApiKey } from '../../../../../lib/security/vault';
import { checkRateLimit } from '../../../../../lib/security/rate-limit';
import { sanitizeApiError } from '../../../../../lib/security/http-guards';
import { sealExternalAgentEvidenceService } from '../../../../../lib/services/platform';
import type { AuthContext } from '../../../../../lib/auth/rbac';

const GatewayEvidenceSchema = z
  .object({
    externalRunId: z.string().min(1).max(128).optional(),
    externalAgentId: z.string().min(1).max(128).optional(),
    status: z.enum(['succeeded', 'failed', 'blocked']).optional(),
    inputPayload: z.record(z.string(), z.unknown()).optional(),
    outputPayload: z.record(z.string(), z.unknown()).optional(),
    policyDecisions: z
      .array(
        z
          .object({
            action: z.string().min(1).max(128),
            resource: z.string().max(512).optional(),
            decision: z.enum(['allow', 'deny', 'approval_required']),
            reasonCode: z.string().min(1).max(128),
            timestamp: z.string().optional(),
          })
          .strict()
      )
      .max(500)
      .optional(),
    toolCalls: z
      .array(
        z
          .object({
            capability: z.string().min(1).max(128),
            action: z.string().min(1).max(128),
            status: z.enum(['succeeded', 'failed', 'blocked']),
            latencyMs: z.number().min(0).max(600_000),
            costUsd: z.number().min(0).max(10_000).optional(),
          })
          .strict()
      )
      .max(500)
      .optional(),
    cost: z
      .object({
        totalUsd: z.number().min(0).max(100_000),
        inputTokens: z.number().int().min(0).max(10_000_000),
        outputTokens: z.number().int().min(0).max(10_000_000),
      })
      .strict()
      .optional(),
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
        endpoint: 'POST:/api/v1/gateway/evidence',
      },
      { windowMs: 60_000, maxRequests: 60 }
    );
    if (!rl.allowed) {
      return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
    }

    const rawBody = await request.json().catch(() => ({}));
    const parsed = GatewayEvidenceSchema.safeParse(rawBody);
    if (!parsed.success) {
      return NextResponse.json(
        {
          error: `Invalid request schema: ${parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`,
        },
        { status: 400 }
      );
    }

    const result = await sealExternalAgentEvidenceService(ctx, parsed.data);
    return NextResponse.json(result);
  } catch (e) {
    const msg = sanitizeApiError(e, 'Gateway evidence sealing failed');
    const status =
      msg.includes('API Key') || msg.startsWith('Unauthorized')
        ? 401
        : msg.startsWith('Forbidden')
          ? 403
          : 400;
    return NextResponse.json({ error: msg }, { status });
  }
}
