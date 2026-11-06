/**
 * RBAC helpers — organization/workspace scoped authorization.
 */

export type Role = 'owner' | 'admin' | 'operator' | 'viewer' | 'auditor';

export interface AuthContext {
  userId: string;
  email: string;
  organizationId: string;
  workspaceIds: string[];
  role: Role;
}

const ROLE_PERMISSIONS: Record<Role, Set<string>> = {
  owner: new Set(['*']),
  admin: new Set([
    'agent:read',
    'agent:write',
    'release:publish',
    'run:execute',
    'approval:decide',
    'policy:write',
    'evidence:export',
    'killswitch:toggle',
  ]),
  operator: new Set(['agent:read', 'run:execute', 'evidence:export', 'approval:request']),
  viewer: new Set(['agent:read', 'evidence:export']),
  auditor: new Set(['agent:read', 'evidence:export', 'audit:read']),
};

export function hasPermission(ctx: AuthContext, permission: string): boolean {
  const perms = ROLE_PERMISSIONS[ctx.role];
  return perms.has('*') || perms.has(permission);
}

export function assertPermission(ctx: AuthContext, permission: string): void {
  if (!hasPermission(ctx, permission)) {
    throw new Error(`Forbidden: missing permission ${permission}`);
  }
}

/**
 * Tenancy enforcement — ensure workspace belongs to the caller's organization scope.
 */
export function assertWorkspaceAccess(ctx: AuthContext, workspaceId: string): void {
  if (!ctx.workspaceIds.includes(workspaceId) && ctx.role !== 'owner') {
    throw new Error('Forbidden: workspace is outside tenant scope');
  }
}

export function assertOrganizationAccess(ctx: AuthContext, organizationId: string): void {
  if (ctx.organizationId !== organizationId) {
    throw new Error('Forbidden: organization mismatch (tenant isolation)');
  }
}
