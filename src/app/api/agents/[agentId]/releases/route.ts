import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../../../lib/auth/session';
import { createReleaseService, listReleasesService } from '../../../../../lib/services/platform';

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ agentId: string }> }
) {
  try {
    const { agentId } = await params;
    const ctx = await getAuthContext();
    const releases = await listReleasesService(ctx, agentId);
    return NextResponse.json({ releases });
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
    const body = await request.json();
    if (!body.commitId) {
      return NextResponse.json({ error: 'commitId required' }, { status: 400 });
    }
    const result = await createReleaseService(ctx, agentId, {
      commitId: body.commitId,
      runEvals: body.runEvals,
    });
    if (!result.ok) {
      return NextResponse.json(result, { status: 422 });
    }
    return NextResponse.json(result);
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Error' },
      { status: 400 }
    );
  }
}
