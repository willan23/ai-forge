import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../../../../lib/auth/session';
import { getReleaseService } from '../../../../../../lib/services/platform';

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ agentId: string; releaseId: string }> }
) {
  try {
    const { agentId, releaseId } = await params;
    const ctx = await getAuthContext();
    const release = await getReleaseService(ctx, agentId, releaseId);
    if (!release) return NextResponse.json({ error: 'Not found' }, { status: 404 });
    return NextResponse.json({ release });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Error' },
      { status: 403 }
    );
  }
}
