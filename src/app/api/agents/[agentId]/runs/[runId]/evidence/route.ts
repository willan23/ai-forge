import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../../../../../lib/auth/session';
import { exportEvidenceService } from '../../../../../../../lib/services/platform';
import { sanitizeApiError } from '../../../../../../../lib/security/http-guards';

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ agentId: string; runId: string }> }
) {
  try {
    const { agentId, runId } = await params;
    const ctx = await getAuthContext();
    const evidence = await exportEvidenceService(ctx, agentId, runId);
    if (!evidence) return NextResponse.json({ error: 'Not found' }, { status: 404 });

    const safeFilenameId = runId.replace(/[^a-zA-Z0-9_-]/g, '');
    return new NextResponse(evidence.json, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="evidence-${safeFilenameId}.json"`,
      },
    });
  } catch (e) {
    return NextResponse.json(
      { error: sanitizeApiError(e, 'Failed to export evidence') },
      { status: 400 }
    );
  }
}
