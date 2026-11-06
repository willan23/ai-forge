import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import type { Role } from './rbac';
import { getStore } from '../store';
import { updateTenantSaasConfig } from '../security/vault';

export interface TenantUserRecord {
  id: string;
  email: string;
  name: string;
  role: Role;
  organizationId: string;
  organizationName: string;
  saltHex: string;
  passwordHashHex: string;
  status: 'active' | 'invited' | 'revoked';
  createdAt: string;
  lastLoginAt: string | null;
}

export type PublicTeamMember = Omit<TenantUserRecord, 'saltHex' | 'passwordHashHex'>;

const globalUsers = globalThis as unknown as {
  __aiForgeTenantUsers?: Map<string, TenantUserRecord>;
};

function getUsersFilePath(): string {
  const baseDir = process.env.AI_FORGE_DATA_DIR ?? path.join(process.cwd(), '.data');
  return path.join(baseDir, 'users', 'tenant-users.json');
}

function hashWithSalt(password: string, saltHex: string): string {
  return scryptSync(password, Buffer.from(saltHex, 'hex'), 64).toString('hex');
}

function verifyWithSalt(candidatePassword: string, saltHex: string, expectedHashHex: string): boolean {
  try {
    const candidateBuf = scryptSync(candidatePassword, Buffer.from(saltHex, 'hex'), 64);
    const expectedBuf = Buffer.from(expectedHashHex, 'hex');
    if (candidateBuf.length !== expectedBuf.length) return false;
    return timingSafeEqual(candidateBuf, expectedBuf);
  } catch {
    return false;
  }
}

function createDefaultOrgMembers(): TenantUserRecord[] {
  const now = '2026-01-01T00:00:00.000Z';
  const defaultSalt = Buffer.from('ai-forge-default-team-salt-v1').toString('hex');
  return [
    {
      id: 'user_admin_demo',
      email: 'admin@demo.local',
      name: 'Enterprise CISO (Admin)',
      role: 'admin',
      organizationId: 'org_demo_wgf',
      organizationName: 'Acme Enterprise Security',
      saltHex: defaultSalt,
      passwordHashHex: hashWithSalt('demo-admin', defaultSalt),
      status: 'active',
      createdAt: now,
      lastLoginAt: now,
    },
    {
      id: 'user_operator_demo',
      email: 'operator@demo.local',
      name: 'SecOps Lead (Operator)',
      role: 'operator',
      organizationId: 'org_demo_wgf',
      organizationName: 'Acme Enterprise Security',
      saltHex: defaultSalt,
      passwordHashHex: hashWithSalt('demo-operator', defaultSalt),
      status: 'active',
      createdAt: now,
      lastLoginAt: null,
    },
    {
      id: 'user_auditor_demo',
      email: 'auditor@demo.local',
      name: 'External Compliance Auditor',
      role: 'auditor',
      organizationId: 'org_demo_wgf',
      organizationName: 'Acme Enterprise Security',
      saltHex: defaultSalt,
      passwordHashHex: hashWithSalt('demo-auditor', defaultSalt),
      status: 'active',
      createdAt: now,
      lastLoginAt: null,
    },
  ];
}

function loadUsersMap(): Map<string, TenantUserRecord> {
  if (globalUsers.__aiForgeTenantUsers) {
    return globalUsers.__aiForgeTenantUsers;
  }
  const map = new Map<string, TenantUserRecord>();
  for (const seed of createDefaultOrgMembers()) {
    map.set(seed.email.toLowerCase(), seed);
  }

  if (!process.env.VITEST) {
    try {
      const file = getUsersFilePath();
      if (fs.existsSync(file)) {
        const parsed = JSON.parse(fs.readFileSync(file, 'utf8')) as TenantUserRecord[];
        if (Array.isArray(parsed)) {
          for (const u of parsed) {
            if (u && u.email) {
              map.set(u.email.toLowerCase(), u);
            }
          }
        }
      }
    } catch {
      // Ignore read failure in ephemeral environments
    }
  }

  globalUsers.__aiForgeTenantUsers = map;
  return map;
}

function saveUsersMap(): void {
  if (process.env.VITEST) return;
  try {
    const map = loadUsersMap();
    const file = getUsersFilePath();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify([...map.values()], null, 2), 'utf8');
    fs.renameSync(tmp, file);
  } catch {
    // Ignore write failure
  }
}

export function resetTenantUserStoreForTests(): void {
  globalUsers.__aiForgeTenantUsers = undefined;
}

function toPublicMember(u: TenantUserRecord): PublicTeamMember {
  return {
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role,
    organizationId: u.organizationId,
    organizationName: u.organizationName,
    status: u.status,
    createdAt: u.createdAt,
    lastLoginAt: u.lastLoginAt,
  };
}

function slugifyOrganization(name: string): string {
  const cleaned = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32);
  return cleaned || 'tenant-org';
}

/**
 * Self-serve SaaS onboarding: registers a new Organization, provisions its isolated
 * workspaces and default governed Security PR Auditor agent, and creates the initial
 * Admin user with a per-user CSPRNG salt + scrypt password hash.
 */
export async function registerOrganizationAndAdminUser(input: {
  name: string;
  email: string;
  password: string;
  organizationName: string;
  planTier?: 'starter' | 'growth' | 'enterprise';
}): Promise<{
  user: PublicTeamMember;
  organization: { id: string; name: string; slug: string; planTier: string };
  workspaceId: string;
  agentId: string;
}> {
  const email = input.email.toLowerCase().trim();
  const name = input.name.trim();
  const orgName = input.organizationName.trim();

  if (!email.includes('@') || email.length < 5) {
    throw new Error('invalid_email');
  }
  if (input.password.length < 8) {
    throw new Error('password_too_short_min_8_chars');
  }
  if (name.length < 2) {
    throw new Error('invalid_name');
  }
  if (orgName.length < 2) {
    throw new Error('invalid_organization_name');
  }

  const map = loadUsersMap();
  if (map.has(email)) {
    throw new Error('email_already_registered');
  }

  const suffix = randomBytes(3).toString('hex');
  const slug = `${slugifyOrganization(orgName)}-${suffix}`;
  const organizationId = `org_${slug.replace(/-/g, '_')}`;
  const userId = `usr_${randomBytes(6).toString('hex')}`;
  const saltHex = randomBytes(16).toString('hex');
  const passwordHashHex = hashWithSalt(input.password, saltHex);
  const now = new Date().toISOString();
  const planTier = input.planTier ?? 'starter';

  const record: TenantUserRecord = {
    id: userId,
    email,
    name,
    role: 'admin',
    organizationId,
    organizationName: orgName,
    saltHex,
    passwordHashHex,
    status: 'active',
    createdAt: now,
    lastLoginAt: null,
  };

  map.set(email, record);
  saveUsersMap();

  const store = await getStore();
  const provisioned = await store.provisionOrganization({
    id: organizationId,
    name: orgName,
    slug,
    plan: planTier,
    ownerId: userId,
  });

  updateTenantSaasConfig(organizationId, {
    organizationName: orgName,
    planTier,
  });

  await store.writeAudit({
    organizationId,
    actorType: 'user',
    actorId: userId,
    action: 'auth.organization_registered',
    targetType: 'organization',
    targetId: organizationId,
    metadataJson: {
      email,
      organizationName: orgName,
      planTier,
      workspaceId: provisioned.workspace.id,
    },
  });

  return {
    user: toPublicMember(record),
    organization: {
      id: organizationId,
      name: orgName,
      slug,
      planTier,
    },
    workspaceId: provisioned.workspace.id,
    agentId: provisioned.agent.id,
  };
}

/**
 * Authenticates a registered tenant user against their per-user scrypt password hash.
 */
export function authenticateRegisteredUser(
  email: string,
  candidatePassword: string
): PublicTeamMember | null {
  const normalized = email.toLowerCase().trim();
  const map = loadUsersMap();
  const user = map.get(normalized);
  if (!user || user.status === 'revoked') {
    return null;
  }
  // Block built-in demo accounts in production unless explicitly permitted
  if (
    normalized.endsWith('@demo.local') &&
    process.env.NODE_ENV === 'production' &&
    process.env.AI_FORGE_ALLOW_DEMO_AUTH !== '1'
  ) {
    return null;
  }
  if (!verifyWithSalt(candidatePassword, user.saltHex, user.passwordHashHex)) {
    return null;
  }
  user.lastLoginAt = new Date().toISOString();
  if (user.status === 'invited') {
    user.status = 'active';
  }
  saveUsersMap();
  return toPublicMember(user);
}

export function listOrganizationMembers(organizationId: string): PublicTeamMember[] {
  const map = loadUsersMap();
  return [...map.values()]
    .filter((u) => u.organizationId === organizationId && u.status !== 'revoked')
    .map(toPublicMember);
}

export async function inviteOrganizationMember(input: {
  organizationId: string;
  organizationName: string;
  invitedByUserId: string;
  email: string;
  name: string;
  role: Role;
  temporaryPassword: string;
}): Promise<PublicTeamMember> {
  const email = input.email.toLowerCase().trim();
  if (!email.includes('@')) {
    throw new Error('invalid_email');
  }
  if (input.temporaryPassword.length < 8) {
    throw new Error('password_too_short_min_8_chars');
  }
  const map = loadUsersMap();
  const existing = map.get(email);
  if (existing && existing.status !== 'revoked') {
    throw new Error('email_already_registered');
  }

  const saltHex = randomBytes(16).toString('hex');
  const record: TenantUserRecord = {
    id: `usr_${randomBytes(6).toString('hex')}`,
    email,
    name: input.name.trim(),
    role: input.role,
    organizationId: input.organizationId,
    organizationName: input.organizationName,
    saltHex,
    passwordHashHex: hashWithSalt(input.temporaryPassword, saltHex),
    status: 'invited',
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  };
  map.set(email, record);
  saveUsersMap();

  const store = await getStore();
  await store.writeAudit({
    organizationId: input.organizationId,
    actorType: 'user',
    actorId: input.invitedByUserId,
    action: 'team.member_invited',
    targetType: 'user',
    targetId: record.id,
    metadataJson: { email: record.email, role: record.role },
  });

  return toPublicMember(record);
}

export async function updateOrganizationMemberRole(input: {
  organizationId: string;
  actorUserId: string;
  targetUserId: string;
  newRole: Role;
}): Promise<PublicTeamMember> {
  const map = loadUsersMap();
  const target = [...map.values()].find(
    (u) => u.id === input.targetUserId && u.organizationId === input.organizationId && u.status !== 'revoked'
  );
  if (!target) {
    throw new Error('member_not_found');
  }

  if (target.role === 'admin' && input.newRole !== 'admin') {
    const activeAdmins = [...map.values()].filter(
      (u) => u.organizationId === input.organizationId && u.status !== 'revoked' && u.role === 'admin'
    );
    if (activeAdmins.length <= 1) {
      throw new Error('cannot_demote_last_admin');
    }
  }

  const previousRole = target.role;
  target.role = input.newRole;
  saveUsersMap();

  const store = await getStore();
  await store.writeAudit({
    organizationId: input.organizationId,
    actorType: 'user',
    actorId: input.actorUserId,
    action: 'team.member_role_updated',
    targetType: 'user',
    targetId: target.id,
    metadataJson: { previousRole, newRole: input.newRole },
  });

  return toPublicMember(target);
}

export async function revokeOrganizationMember(input: {
  organizationId: string;
  actorUserId: string;
  targetUserId: string;
}): Promise<void> {
  const map = loadUsersMap();
  const target = [...map.values()].find(
    (u) => u.id === input.targetUserId && u.organizationId === input.organizationId && u.status !== 'revoked'
  );
  if (!target) {
    throw new Error('member_not_found');
  }

  if (target.role === 'admin') {
    const activeAdmins = [...map.values()].filter(
      (u) => u.organizationId === input.organizationId && u.status !== 'revoked' && u.role === 'admin'
    );
    if (activeAdmins.length <= 1) {
      throw new Error('cannot_revoke_last_admin');
    }
  }

  target.status = 'revoked';
  saveUsersMap();

  const store = await getStore();
  await store.writeAudit({
    organizationId: input.organizationId,
    actorType: 'user',
    actorId: input.actorUserId,
    action: 'team.member_revoked',
    targetType: 'user',
    targetId: target.id,
    metadataJson: { email: target.email },
  });
}

