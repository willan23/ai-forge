import { NextResponse } from 'next/server';
import { z } from 'zod';
import { getAuthContext } from '../../../lib/auth/session';
import { assertPermission } from '../../../lib/auth/rbac';
import {
  inviteOrganizationMember,
  listOrganizationMembers,
  revokeOrganizationMember,
  updateOrganizationMemberRole,
} from '../../../lib/auth/users';
import { getTenantSaasConfig } from '../../../lib/security/vault';
import { checkRateLimit } from '../../../lib/security/rate-limit';
import { assertCsrfOrigin, sanitizeApiError } from '../../../lib/security/http-guards';

const TeamActionSchema = z
  .object({
    action: z.enum(['invite', 'update_role', 'revoke']),
    email: z.string().email().max(180).optional(),
    name: z.string().min(2).max(120).optional(),
    role: z.enum(['admin', 'operator', 'auditor', 'viewer']).optional(),
    temporaryPassword: z.string().min(8).max(128).optional(),
    targetUserId: z.string().min(2).max(120).optional(),
  })
  .strict();

export async function GET() {
  try {
    const ctx = await getAuthContext();
    assertPermission(ctx, 'agent:read');
    const rl = checkRateLimit({
      userId: ctx.userId,
      organizationId: ctx.organizationId,
      endpoint: 'GET:/api/team',
    });
    if (!rl.allowed) {
      return NextResponse.json({ error: 'rate_limit_exceeded' }, { status: 429 });
    }
    const members = listOrganizationMembers(ctx.organizationId);
    return NextResponse.json({ members });
  } catch (e) {
    const msg = sanitizeApiError(e, 'Failed to list team members');
    const status = msg.startsWith('Unauthorized') ? 401 : msg.startsWith('Forbidden') ? 403 : 400;
    return NextResponse.json({ error: msg }, { status });
  }
}

export async function POST(request: Request) {
  try {
    assertCsrfOrigin(request);
    const ctx = await getAuthContext();
    assertPermission(ctx, 'policy:write');

    const rl = checkRateLimit(
      {
        userId: ctx.userId,
        organizationId: ctx.organizationId,
        endpoint: 'POST:/api/team',
      },
      { maxRequests: 25, windowMs: 60_000 }
    );
    if (!rl.allowed) {
      return NextResponse.json({ error: 'rate_limit_exceeded' }, { status: 429 });
    }

    const body = TeamActionSchema.parse(await request.json());
    const tenantCfg = getTenantSaasConfig(ctx.organizationId);

    if (body.action === 'invite') {
      if (!body.email || !body.name || !body.role || !body.temporaryPassword) {
        return NextResponse.json(
          { error: 'missing_required_invite_fields' },
          { status: 400 }
        );
      }
      const created = await inviteOrganizationMember({
        organizationId: ctx.organizationId,
        organizationName: tenantCfg.organizationName,
        invitedByUserId: ctx.userId,
        email: body.email,
        name: body.name,
        role: body.role,
        temporaryPassword: body.temporaryPassword,
      });
      return NextResponse.json(
        { member: created, members: listOrganizationMembers(ctx.organizationId) },
        { status: 201 }
      );
    }

    if (body.action === 'update_role') {
      if (!body.targetUserId || !body.role) {
        return NextResponse.json(
          { error: 'missing_target_user_or_role' },
          { status: 400 }
        );
      }
      const updated = await updateOrganizationMemberRole({
        organizationId: ctx.organizationId,
        actorUserId: ctx.userId,
        targetUserId: body.targetUserId,
        newRole: body.role,
      });
      return NextResponse.json({
        member: updated,
        members: listOrganizationMembers(ctx.organizationId),
      });
    }

    if (body.action === 'revoke') {
      if (!body.targetUserId) {
        return NextResponse.json({ error: 'missing_target_user_id' }, { status: 400 });
      }
      await revokeOrganizationMember({
        organizationId: ctx.organizationId,
        actorUserId: ctx.userId,
        targetUserId: body.targetUserId,
      });
      return NextResponse.json({
        revoked: body.targetUserId,
        members: listOrganizationMembers(ctx.organizationId),
      });
    }

    return NextResponse.json({ error: 'invalid_action' }, { status: 400 });
  } catch (e) {
    const msg = sanitizeApiError(e, 'Team operation failed');
    const status = msg.startsWith('Unauthorized') ? 401 : msg.startsWith('Forbidden') ? 403 : 400;
    return NextResponse.json({ error: msg }, { status });
  }
}
