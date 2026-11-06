import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../../../../lib/auth/session';
import { getRunDetailService } from '../../../../../../lib/services/platform';

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ agentId: string; runId: string }> }
) {
  try {
    const { agentId, runId } = await params;
    const ctx = await getAuthContext();
    const detail = await getRunDetailService(ctx, agentId, runId);
    if (!detail) return NextResponse.json({ error: 'Not found' }, { status: 404 });
    return NextResponse.json(detail);
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Error' },
      { status: 403 }
    );
  }
}
