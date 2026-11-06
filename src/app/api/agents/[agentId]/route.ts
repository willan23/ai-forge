import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../../lib/auth/session';
import { getAgentService, setKillSwitchService } from '../../../../lib/services/platform';
import { getStore } from '../../../../lib/store';

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ agentId: string }> }
) {
  try {
    const { agentId } = await params;
    const ctx = await getAuthContext();
    const agent = await getAgentService(ctx, agentId);
    if (!agent) return NextResponse.json({ error: 'Not found' }, { status: 404 });
    const store = await getStore();
    const [commits, releases, runs, caps, policyBundle, proposals, workspace] = await Promise.all([
      store.listCommits(agentId),
      store.listReleases(agentId),
      store.listRuns(agentId),
      store.listCapabilities(agent.workspaceId),
      store.getPolicyBundle(agent.workspaceId),
      store.listChangeProposals(agentId),
      store.getWorkspace(agent.workspaceId),
    ]);
    return NextResponse.json({
      agent,
      workspace,
      commits,
      releases,
      runs,
      capabilities: caps,
      policyBundle,
      proposals,
    });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Error' },
      { status: 403 }
    );
  }
}

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ agentId: string }> }
) {
  try {
    const { agentId } = await params;
    const ctx = await getAuthContext();
    const body = await request.json();
    if (typeof body.killSwitch === 'boolean') {
      const agent = await setKillSwitchService(ctx, agentId, body.killSwitch);
      return NextResponse.json({ agent });
    }
    return NextResponse.json({ error: 'No supported fields' }, { status: 400 });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Error' },
      { status: 400 }
    );
  }
}
