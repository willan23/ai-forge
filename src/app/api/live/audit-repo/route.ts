import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../../lib/auth/session';
import { executeLiveRepositoryAuditService } from '../../../../lib/services/platform';
import { checkRateLimit } from '../../../../lib/security/rate-limit';

export async function POST(request: Request) {
  try {
    const ctx = await getAuthContext();
    const rl = checkRateLimit(
      {
        userId: ctx.userId,
        organizationId: ctx.organizationId,
        endpoint: 'POST /api/live/audit-repo',
      },
      { windowMs: 60_000, maxRequests: 30 }
    );
    if (!rl.allowed) {
      return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
    }

    const body = (await request.json().catch(() => ({}))) as {
      agentId?: string;
      repo?: string;
      prNumber?: number;
      packageToScan?: string;
      versionToScan?: string;
      searchQuery?: string;
    };

    const repo = (body.repo ?? 'expressjs/express').trim();
    if (!repo.includes('/')) {
      return NextResponse.json(
        { error: 'Repository must be in owner/repo format (e.g. expressjs/express)' },
        { status: 400 }
      );
    }

    const result = await executeLiveRepositoryAuditService(ctx, {
      agentId: body.agentId,
      repo,
      prNumber: body.prNumber ? Number(body.prNumber) : undefined,
      packageToScan: body.packageToScan,
      versionToScan: body.versionToScan,
      searchQuery: body.searchQuery,
    });

    return NextResponse.json(result);
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Live repository audit failed' },
      { status: 400 }
    );
  }
}

