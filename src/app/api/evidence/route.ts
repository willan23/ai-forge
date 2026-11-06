import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../lib/auth/session';
import { searchEvidenceBundlesService } from '../../../lib/services/platform';

export async function GET(request: Request) {
  try {
    const ctx = await getAuthContext();
    const { searchParams } = new URL(request.url);
    const query = searchParams.get('query') ?? undefined;
    const decision = searchParams.get('decision') ?? undefined;
    const status = searchParams.get('status') ?? undefined;

    const items = await searchEvidenceBundlesService(ctx, { query, decision, status });
    return NextResponse.json({ items });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Failed to list evidence bundles' },
      { status: 400 }
    );
  }
}

