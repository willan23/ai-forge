import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../../../lib/auth/session';
import { startRunService } from '../../../../../lib/services/platform';
import { getStore } from '../../../../../lib/store';
import { getAgentService } from '../../../../../lib/services/platform';

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ agentId: string }> }
) {
  try {
    const { agentId } = await params;
    const ctx = await getAuthContext();
    await getAgentService(ctx, agentId);
    const store = await getStore();
    const runs = await store.listRuns(agentId);
    return NextResponse.json({ runs });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Error' },
      { status: 403 }
    );
  }
}

export async function POST(
  request: Request,
  { params }: { params: Promise<{ agentId: string }> }
) {
  try {
    const { agentId } = await params;
    const ctx = await getAuthContext();
    const body = await request.json().catch(() => ({}));
    const result = await startRunService(ctx, agentId, {
      releaseId: body.releaseId,
      releaseDigest: body.releaseDigest,
      resource: body.resource,
      fixture: body.fixture,
      prNumber: body.prNumber,
    });
    return NextResponse.json({
      mode: 'demo-simulation',
      run: result.run,
      status: result.result.status,
      releaseDigest: result.release.releaseDigest,
      policyDecisions: result.result.policyDecisions,
      toolInvocations: result.result.toolInvocations,
      events: result.result.events,
      approval: result.approval,
      output: result.result.output,
      evidenceBundle: result.result.evidenceBundle,
      evidenceJson: result.evidenceJson,
      inputHash: result.result.inputHash,
      outputHash: result.result.outputHash,
    });
  } catch (e) {
    const message = e instanceof Error ? e.message : 'Error';
    const status = message === 'kill_switch_active' ? 423 : 400;
    return NextResponse.json({ error: message }, { status });
  }
}
