import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../../../lib/auth/session';
import {
  createChangeProposalService,
  decideChangeProposalService,
  listChangeProposalsService,
} from '../../../../../lib/services/platform';

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ agentId: string }> }
) {
  try {
    const { agentId } = await params;
    const ctx = await getAuthContext();
    const proposals = await listChangeProposalsService(ctx, agentId);
    return NextResponse.json({ proposals });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Failed to list change proposals' },
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
    const result = await createChangeProposalService(ctx, agentId, {
      manifest: body.manifest,
      message: body.message ?? 'Change proposal',
      branchName: body.branchName,
    });
    if (!result.ok) {
      return NextResponse.json(result, { status: 400 });
    }
    return NextResponse.json(result);
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Failed to create change proposal' },
      { status: 400 }
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
    if (!body.proposalId || !body.status) {
      return NextResponse.json({ error: 'proposalId and status required' }, { status: 400 });
    }
    const proposal = await decideChangeProposalService(
      ctx,
      agentId,
      body.proposalId,
      body.status
    );
    return NextResponse.json({ proposal });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Failed to update proposal' },
      { status: 400 }
    );
  }
}

