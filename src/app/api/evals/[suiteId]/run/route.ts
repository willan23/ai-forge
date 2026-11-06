import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../../../lib/auth/session';
import { assertOrganizationAccess, assertPermission } from '../../../../../lib/auth/rbac';
import { checkRateLimit } from '../../../../../lib/security/rate-limit';
import { assertCsrfOrigin, sanitizeApiError } from '../../../../../lib/security/http-guards';
import { getStore } from '../../../../../lib/store';
import { runEvalSuite } from '../../../../../lib/domain/eval/runner';
import { DEMO_EVAL_SCENARIOS, DEMO_EVAL_GATES } from '../../../../../fixtures/demo-evals';

export async function POST(
  request: Request,
  { params }: { params: Promise<{ suiteId: string }> }
) {
  try {
    assertCsrfOrigin(request);
    const { suiteId } = await params;
    const ctx = await getAuthContext();
    assertPermission(ctx, 'agent:read');

    const rl = checkRateLimit(
      {
        userId: ctx.userId,
        organizationId: ctx.organizationId,
        endpoint: `POST:/api/evals/${suiteId}/run`,
      },
      { windowMs: 60_000, maxRequests: 30 }
    );
    if (!rl.allowed) {
      return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
    }

    const body = await request.json();
    const store = await getStore();

    const releaseDigest = body.releaseDigest as string | undefined;
    if (!releaseDigest) {
      return NextResponse.json({ error: 'releaseDigest required' }, { status: 400 });
    }

    const release = await store.getReleaseByDigest(releaseDigest);
    if (!release) {
      return NextResponse.json({ error: 'Release not found' }, { status: 404 });
    }

    const agent = await store.getAgent(release.agentId);
    if (!agent) return NextResponse.json({ error: 'Agent not found' }, { status: 404 });
    const workspace = await store.getWorkspace(agent.workspaceId);
    if (!workspace) {
      return NextResponse.json({ error: 'Workspace not found' }, { status: 404 });
    }
    assertOrganizationAccess(ctx, workspace.organizationId);

    const result = runEvalSuite({
      suite: suiteId,
      version: body.version ?? '0.1.0',
      releaseDigest,
      scenarios: DEMO_EVAL_SCENARIOS,
      gates: DEMO_EVAL_GATES,
    });

    return NextResponse.json({
      mode: 'demo-simulation',
      suiteId,
      results: result.results,
      scorecard: result.scorecard,
    });
  } catch (e) {
    const msg = sanitizeApiError(e, 'Evaluation run failed');
    const status = msg.startsWith('Unauthorized')
      ? 401
      : msg.startsWith('Forbidden')
        ? 403
        : 400;
    return NextResponse.json({ error: msg }, { status });
  }
}
