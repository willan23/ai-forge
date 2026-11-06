import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../lib/auth/session';
import {
  createAgentService,
  listAgentsService,
  listWorkspacesService,
} from '../../../lib/services/platform';
import { computeDigest } from '../../../lib/domain/manifest/digest';
import { getStore } from '../../../lib/store';

export async function GET(request: Request) {
  try {
    const ctx = await getAuthContext();
    const { searchParams } = new URL(request.url);
    const workspaceId = searchParams.get('workspaceId') ?? undefined;

    const [agents, workspaces] = await Promise.all([
      listAgentsService(ctx, workspaceId),
      listWorkspacesService(ctx),
    ]);
    const wsMap = new Map(workspaces.map((w) => [w.id, w]));
    const store = await getStore();

    const enriched = await Promise.all(
      agents.map(async (a) => {
        const [releases, commits, runs] = await Promise.all([
          store.listReleases(a.id),
          store.listCommits(a.id),
          store.listRuns(a.id),
        ]);
        const last = releases[0];
        const headCommit = commits[0];
        const ws = wsMap.get(a.workspaceId);
        return {
          ...a,
          workspaceName: ws?.name ?? 'Platform Security',
          environment: ws?.environment ?? 'development',
          autonomyLevel: headCommit?.manifestJson?.spec?.autonomy?.level ?? 2,
          approvalPolicy: headCommit?.manifestJson?.spec?.autonomy?.approvalPolicy ?? 'risk-based',
          lastReleaseDigest: last?.releaseDigest ?? null,
          lastReleaseVersion: last?.version ?? null,
          lastReleaseStatus: last?.status ?? null,
          runCount: runs.length,
          storeMode: store.mode,
        };
      })
    );
    return NextResponse.json({
      agents: enriched,
      workspaces,
      storeMode: store.mode,
    });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Failed to list agents' },
      { status: 403 }
    );
  }
}

export async function POST(request: Request) {
  try {
    const ctx = await getAuthContext();
    const body = await request.json();
    if (!body.slug || !body.name) {
      return NextResponse.json({ error: 'slug and name are required' }, { status: 400 });
    }
    const agent = await createAgentService(ctx, {
      slug: body.slug,
      name: body.name,
      workspaceId: body.workspaceId,
      manifest: body.manifest,
    });
    return NextResponse.json({
      agent,
      manifestDigest: body.manifest ? computeDigest(body.manifest) : null,
    });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Failed to create agent' },
      { status: 400 }
    );
  }
}
