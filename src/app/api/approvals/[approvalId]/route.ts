import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../../lib/auth/session';
import { decideApprovalService } from '../../../../lib/services/platform';
import { getStore } from '../../../../lib/store';

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ approvalId: string }> }
) {
  try {
    const { approvalId } = await params;
    const ctx = await getAuthContext();
    const store = await getStore();
    const approval = await store.getApproval(approvalId);
    if (!approval || approval.organizationId !== ctx.organizationId) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 });
    }
    return NextResponse.json({ approval });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Error' },
      { status: 403 }
    );
  }
}

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ approvalId: string }> }
) {
  try {
    const { approvalId } = await params;
    const ctx = await getAuthContext();
    const body = await request.json();
    if (!body.decision || !body.reason) {
      return NextResponse.json({ error: 'decision and reason required' }, { status: 400 });
    }
    const approval = await decideApprovalService(ctx, approvalId, {
      decision: body.decision,
      reason: body.reason,
    });
    return NextResponse.json({ approval });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Error' },
      { status: 400 }
    );
  }
}
