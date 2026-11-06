import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../../lib/auth/session';
import { generateExecutiveAuditReportService } from '../../../../lib/services/platform';

export async function GET(
  _request: Request,
  context: { params: Promise<{ runId: string }> }
) {
  try {
    const ctx = await getAuthContext();
    const { runId } = await context.params;
    const data = await generateExecutiveAuditReportService(ctx, runId);
    return NextResponse.json(data);
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Failed to generate Executive Audit Report' },
      { status: 400 }
    );
  }
}

