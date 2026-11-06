import { getServerSession } from 'next-auth';
import { authOptions } from './config';
import type { AuthContext } from './rbac';
import { DEMO_ORG, DEMO_WORKSPACE } from '../../fixtures/demo-agents';
import { getStore } from '../store';

export type { AuthContext };

export function demoAuthContext(): AuthContext {
  return {
    userId: 'user_admin_demo',
    email: 'ciso@wgf.security',
    organizationId: DEMO_ORG.id,
    workspaceIds: [DEMO_WORKSPACE.id],
    role: 'admin',
  };
}

/**
 * Resolve auth context from NextAuth session.
 * Dynamically loads the authenticated user's tenant workspaces so newly registered
 * Self-Serve SaaS organizations operate in their own isolated tenant context.
 */
export async function getAuthContext(): Promise<AuthContext> {
  try {
    const session = await getServerSession(authOptions);
    if (session?.user) {
      const user = session.user as {
        id?: string;
        email?: string | null;
        name?: string | null;
        role?: string;
        organizationId?: string;
      };
      const orgId = user.organizationId ?? DEMO_ORG.id;
      let workspaceIds = [DEMO_WORKSPACE.id];
      try {
        const store = await getStore();
        await store.ensureSeed();
        let workspaces = await store.listWorkspaces(orgId);
        if (workspaces.length === 0 && orgId !== DEMO_ORG.id) {
          await store.provisionOrganization({
            id: orgId,
            name: user.name ?? 'Enterprise Organization',
            slug: orgId.replace(/^org_/, '').replace(/_/g, '-'),
            plan: 'growth',
            ownerId: user.id ?? 'user_admin',
          });
          workspaces = await store.listWorkspaces(orgId);
        }
        if (workspaces.length > 0) {
          workspaceIds = workspaces.map((w) => w.id);
        }
      } catch {
        // Fallback if store is initializing
      }

      return {
        userId: user.id ?? 'session-user',
        email: user.email ?? 'unknown@local',
        organizationId: orgId,
        workspaceIds,
        role: (user.role as AuthContext['role']) ?? 'viewer',
      };
    }
  } catch {
    // next-auth may fail without NEXTAUTH_URL in unit tests — fall through to environment check
  }

  const isProd = process.env.NODE_ENV === 'production';
  const requireAuth = process.env.AI_FORGE_REQUIRE_AUTH === '1';
  const allowDemoInProd = process.env.AI_FORGE_ALLOW_DEMO_AUTH === '1';

  if (requireAuth || (isProd && !allowDemoInProd)) {
    throw new Error('Unauthorized: valid session required');
  }

  return demoAuthContext();
}
