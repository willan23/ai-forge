import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../../../lib/auth/session';
import { createCommitService, listCommitsService } from '../../../../../lib/services/platform';

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ agentId: string }> }
) {
  try {
    const { agentId } = await params;
    const ctx = await getAuthContext();
    const commits = await listCommitsService(ctx, agentId);
    return NextResponse.json({ commits });
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
    const result = await createCommitService(ctx, agentId, {
      manifest: body.manifest,
      message: body.message ?? 'Update manifest',
      branchName: body.branchName,
    });
    if (!result.ok) {
      return NextResponse.json(result, { status: 400 });
    }
    return NextResponse.json(result);
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Error' },
      { status: 400 }
    );
  }
}
