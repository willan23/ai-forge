import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../lib/auth/session';
import { listApprovalsService } from '../../../lib/services/platform';

export async function GET() {
  try {
    const ctx = await getAuthContext();
    const approvals = await listApprovalsService(ctx);
    return NextResponse.json({ approvals });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Error' },
      { status: 403 }
    );
  }
}
