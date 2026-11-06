import { getServerSession } from 'next-auth';
import { authOptions } from './config';
import type { AuthContext } from './rbac';
import { DEMO_ORG, DEMO_WORKSPACE } from '../../fixtures/demo-agents';

export type { AuthContext };

export function demoAuthContext(): AuthContext {
  return {
    userId: 'user_admin_demo',
    email: 'admin@demo.local',
    organizationId: DEMO_ORG.id,
    workspaceIds: [DEMO_WORKSPACE.id],
    role: 'admin',
  };
}

/**
 * Resolve auth context from NextAuth session.
 * Fail-closed in production (SEC-06 / ACH-01): never falls back to demoAuthContext()
 * when NODE_ENV === 'production' unless AI_FORGE_ALLOW_DEMO_AUTH === '1' is explicitly set.
 */
export async function getAuthContext(): Promise<AuthContext> {
  try {
    const session = await getServerSession(authOptions);
    if (session?.user) {
      const user = session.user as {
        id?: string;
        email?: string | null;
        role?: string;
        organizationId?: string;
      };
      return {
        userId: user.id ?? 'session-user',
        email: user.email ?? 'unknown@local',
        organizationId: user.organizationId ?? DEMO_ORG.id,
        workspaceIds: [DEMO_WORKSPACE.id],
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
