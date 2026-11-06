import type { NextAuthOptions } from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import { scryptSync, timingSafeEqual } from 'node:crypto';
import { getStore } from '../store';
import { authenticateRegisteredUser } from './users';

const PASSWORD_KDF_SALT = 'ai-forge-scrypt-auth-salt-v1';

export function hashPasswordScrypt(password: string, salt = PASSWORD_KDF_SALT): string {
  return scryptSync(password, salt, 64).toString('hex');
}

export function verifyPasswordScrypt(
  candidatePassword: string,
  expectedHashHex: string,
  salt = PASSWORD_KDF_SALT
): boolean {
  try {
    const candidateBuf = scryptSync(candidatePassword, salt, 64);
    const expectedBuf = Buffer.from(expectedHashHex, 'hex');
    if (candidateBuf.length !== expectedBuf.length) return false;
    return timingSafeEqual(candidateBuf, expectedBuf);
  } catch {
    return false;
  }
}

export function resolveAuthSecret(): string {
  const configured = process.env.AUTH_SECRET ?? process.env.NEXTAUTH_SECRET;
  if (
    process.env.NODE_ENV === 'production' &&
    process.env.AI_FORGE_ALLOW_DEMO_AUTH !== '1' &&
    (!configured || configured === 'dev-only-change-me' || configured.length < 16)
  ) {
    throw new Error(
      'Missing or insecure AUTH_SECRET in production environment (SEC-05 / A23).'
    );
  }
  return configured ?? 'dev-only-change-me-local-development-secret';
}

const DEMO_USERS: Record<
  string,
  {
    passwordHashHex: string;
    id: string;
    name: string;
    role: string;
    organizationId: string;
  }
> = {
  'ciso@wgf.security': {
    passwordHashHex: hashPasswordScrypt('WgfSec!2026'),
    id: 'user_admin_demo',
    name: 'Enterprise CISO (Admin)',
    role: 'admin',
    organizationId: 'org_demo_wgf',
  },
  'secops@wgf.security': {
    passwordHashHex: hashPasswordScrypt('WgfOps!2026'),
    id: 'user_operator_demo',
    name: 'SecOps Lead (Operator)',
    role: 'operator',
    organizationId: 'org_demo_wgf',
  },
  'admin@demo.local': {
    passwordHashHex: hashPasswordScrypt('demo-admin'),
    id: 'user_admin_demo',
    name: 'Enterprise CISO (Admin)',
    role: 'admin',
    organizationId: 'org_demo_wgf',
  },
  'operator@demo.local': {
    passwordHashHex: hashPasswordScrypt('demo-operator'),
    id: 'user_operator_demo',
    name: 'SecOps Lead (Operator)',
    role: 'operator',
    organizationId: 'org_demo_wgf',
  },
};

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: 'Demo Credentials',
      credentials: {
        email: { label: 'Email', type: 'email' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials.password) return null;

        const normalizedEmail = credentials.email.toLowerCase().trim();

        // 1. Check real registered / invited tenant users first (works in all environments)
        const registered = authenticateRegisteredUser(normalizedEmail, credentials.password);
        if (registered) {
          try {
            const store = await getStore();
            await store.writeAudit({
              organizationId: registered.organizationId,
              actorType: 'user',
              actorId: registered.id,
              action: 'auth.login_succeeded',
              targetType: 'session',
              metadataJson: { role: registered.role },
            });
          } catch {
            // Ignore audit failure
          }
          return {
            id: registered.id,
            email: registered.email,
            name: registered.name,
            role: registered.role,
            organizationId: registered.organizationId,
          };
        }

        // 2. Block fallback demo credentials in production unless explicitly permitted for sandbox
        if (
          process.env.NODE_ENV === 'production' &&
          process.env.AI_FORGE_ALLOW_DEMO_AUTH !== '1'
        ) {
          return null;
        }

        const user = DEMO_USERS[normalizedEmail];
        if (!user || !verifyPasswordScrypt(credentials.password, user.passwordHashHex)) {
          try {
            const store = await getStore();
            await store.writeAudit({
              organizationId: 'org_demo_wgf',
              actorType: 'user',
              actorId: normalizedEmail.slice(0, 64),
              action: 'auth.login_failed',
              targetType: 'session',
              metadataJson: { reason: 'invalid_credentials' },
            });
          } catch {
            // Ignore audit failure during auth
          }
          return null;
        }

        try {
          const store = await getStore();
          await store.writeAudit({
            organizationId: user.organizationId,
            actorType: 'user',
            actorId: user.id,
            action: 'auth.login_succeeded',
            targetType: 'session',
            metadataJson: { role: user.role },
          });
        } catch {
          // Ignore audit failure
        }

        return {
          id: user.id,
          email: normalizedEmail,
          name: user.name,
          role: user.role,
          organizationId: user.organizationId,
        };
      },
    }),
  ],
  session: {
    strategy: 'jwt',
    maxAge: 8 * 60 * 60, // 8 hours absolute session TTL (SEC-07)
    updateAge: 60 * 60,
  },
  cookies: {
    sessionToken: {
      name:
        process.env.NODE_ENV === 'production'
          ? '__Secure-next-auth.session-token'
          : 'next-auth.session-token',
      options: {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        secure: process.env.NODE_ENV === 'production',
      },
    },
  },
  pages: {
    signIn: '/login',
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        const u = user as { role?: string; organizationId?: string };
        token.role = u.role;
        token.organizationId = u.organizationId;
        token.sub = user.id;
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        const s = session.user as {
          id?: string;
          role?: string;
          organizationId?: string;
        };
        s.id = token.sub;
        s.role = token.role as string;
        s.organizationId = token.organizationId as string;
      }
      return session;
    },
  },
  secret: resolveAuthSecret(),
};

/** True when enterprise OIDC env vars are present (ready to wire a provider). */
export function isOidcConfigured(): boolean {
  return Boolean(
    process.env.OIDC_ISSUER && process.env.OIDC_CLIENT_ID && process.env.OIDC_CLIENT_SECRET
  );
}
