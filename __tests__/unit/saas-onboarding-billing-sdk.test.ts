import { beforeEach, describe, expect, it } from 'vitest';
import {
  authenticateRegisteredUser,
  inviteOrganizationMember,
  listOrganizationMembers,
  registerOrganizationAndAdminUser,
  resetTenantUserStoreForTests,
  revokeOrganizationMember,
  updateOrganizationMemberRole,
} from '../../src/lib/auth/users';
import {
  computeStripeSignatureHeader,
  createStripeCheckoutSession,
  resetStripeEventReplayCacheForTests,
  verifyStripeWebhookSignature,
} from '../../src/lib/billing/stripe';
import { POST as stripeWebhookPost } from '../../src/app/api/webhooks/stripe/route';
import { POST as gatewayAuthorizePost } from '../../src/app/api/v1/gateway/authorize/route';
import { POST as gatewayEvidencePost } from '../../src/app/api/v1/gateway/evidence/route';
import {
  AiForgeGatewayClient,
  AiForgePolicyDeniedError,
} from '../../src/sdk/typescript';
import {
  createGatewayApiKey,
  getTenantSaasConfig,
  resetVaultForTests,
  updateTenantSaasConfig,
} from '../../src/lib/security/vault';
import { resetMemoryStore } from '../../src/lib/store/memory';
import { clearStoreCache, getStore } from '../../src/lib/store';
import {
  decideApprovalService,
  demoAuthContext,
  startRunService,
} from '../../src/lib/services/platform';

describe('Real SaaS Onboarding, Team RBAC, Stripe Webhook Billing, BYOK GitHub Write & Official SDK', () => {
  beforeEach(() => {
    resetMemoryStore();
    clearStoreCache();
    resetVaultForTests();
    resetTenantUserStoreForTests();
    resetStripeEventReplayCacheForTests();
  });

  it('provisions a new SaaS organization, authenticates with scrypt, and enforces last-admin protection', async () => {
    const onboarding = await registerOrganizationAndAdminUser({
      name: 'Sofia Costa',
      email: 'sofia@novasec.io',
      password: 'StrongPassword!2026',
      organizationName: 'NovaSec Cyber Defense',
      planTier: 'growth',
    });

    expect(onboarding.user.role).toBe('admin');
    expect(onboarding.organization.name).toBe('NovaSec Cyber Defense');
    expect(onboarding.organization.planTier).toBe('growth');

    // Verify workspaces & default governed agent were provisioned in the store
    const store = await getStore();
    const workspaces = await store.listWorkspaces(onboarding.organization.id);
    expect(workspaces.length).toBe(3);
    const agent = await store.getAgent(onboarding.agentId);
    expect(agent?.slug).toBe('security-pr-auditor');

    // Authenticate with valid & invalid passwords
    expect(authenticateRegisteredUser('sofia@novasec.io', 'wrong-pass')).toBeNull();
    const authUser = authenticateRegisteredUser('sofia@novasec.io', 'StrongPassword!2026');
    expect(authUser?.id).toBe(onboarding.user.id);

    // Protect last admin from demotion or revocation
    await expect(
      updateOrganizationMemberRole({
        organizationId: onboarding.organization.id,
        actorUserId: onboarding.user.id,
        targetUserId: onboarding.user.id,
        newRole: 'viewer',
      })
    ).rejects.toThrow(/cannot_demote_last_admin/);

    await expect(
      revokeOrganizationMember({
        organizationId: onboarding.organization.id,
        actorUserId: onboarding.user.id,
        targetUserId: onboarding.user.id,
      })
    ).rejects.toThrow(/cannot_revoke_last_admin/);

    // Invite a second team member and verify listing
    const invited = await inviteOrganizationMember({
      organizationId: onboarding.organization.id,
      organizationName: onboarding.organization.name,
      invitedByUserId: onboarding.user.id,
      email: 'ops@novasec.io',
      name: 'Miguel Ops',
      role: 'operator',
      temporaryPassword: 'OpsTempPassword!99',
    });
    expect(invited.role).toBe('operator');
    expect(listOrganizationMembers(onboarding.organization.id).length).toBe(2);
  });

  it('verifies Stripe HMAC-SHA256 webhook signatures, prevents event replay, and activates tenant quota', async () => {
    const secret = 'whsec_aiforge_dev_stripe_secret_v1';
    const session = await createStripeCheckoutSession({
      organizationId: 'org_demo_wgf',
      organizationName: 'Acme Enterprise Security',
      planTier: 'enterprise',
      originUrl: 'http://localhost:3000',
    });
    expect(session.simulatedWebhookEvent).toBeDefined();

    const { rawBody, signatureHeader } = session.simulatedWebhookEvent!;

    // Reject invalid signature
    const badRes = await stripeWebhookPost(
      new Request('http://localhost:3000/api/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': 't=12345,v1=deadbeef' },
        body: rawBody,
      })
    );
    expect(badRes.status).toBe(401);

    // Reject expired timestamp beyond 300s tolerance
    const expiredSig = computeStripeSignatureHeader(
      rawBody,
      secret,
      Math.floor(Date.now() / 1000) - 900
    );
    const expiredCheck = verifyStripeWebhookSignature(rawBody, expiredSig, secret);
    expect(expiredCheck.valid).toBe(false);
    expect(expiredCheck.reason).toBe('stripe_signature_timestamp_out_of_tolerance');

    // Accept valid Stripe signature and upgrade tenant plan to enterprise (10,000 runs)
    const okRes = await stripeWebhookPost(
      new Request('http://localhost:3000/api/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': signatureHeader },
        body: rawBody,
      })
    );
    expect(okRes.status).toBe(200);
    const okData = await okRes.json();
    expect(okData.planTier).toBe('enterprise');
    expect(okData.monthlyRunQuota).toBe(10_000);
    expect(getTenantSaasConfig('org_demo_wgf').monthlyRunQuota).toBe(10_000);

    // Reject replay of the same Stripe event ID
    const replayRes = await stripeWebhookPost(
      new Request('http://localhost:3000/api/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': signatureHeader },
        body: rawBody,
      })
    );
    expect(replayRes.status).toBe(409);
  });

  it('connects HITL approval execution to the tenant BYOK Vault and formats attested Markdown review', async () => {
    updateTenantSaasConfig('org_demo_wgf', {
      secrets: { githubToken: 'ghp_test_byok_vault_token_1234567890' },
    });

    const ctx = demoAuthContext();
    const started = await startRunService(ctx, 'agent_security_pr_auditor', {
      fixture: 'sqli',
      resource: 'org-approved/payments-api',
      prNumber: 42,
    });
    expect(started.approval).not.toBeNull();

    const decided = await decideApprovalService(ctx, started.approval!.id, {
      decision: 'approved',
      reason: 'Verified SQLi finding and approved PR review comment.',
    });

    expect(decided.decision).toBe('approved');
    expect(decided.draftExecutionReceipt).not.toBeNull();
    expect(decided.draftExecutionReceipt?.body).toContain('AI Forge Governed Security Audit Review');
    expect(decided.draftExecutionReceipt?.body).toContain('Attested with Ed25519 + SHA-256 Evidence Bundle');
  });

  it('governs tool calls end-to-end via the official @aiforge/sdk TypeScript client', async () => {
    const { rawKey } = createGatewayApiKey('org_demo_wgf', 'TS SDK Integration Key');

    const localFetch: typeof fetch = async (input, init) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/api/v1/gateway/authorize')) {
        return gatewayAuthorizePost(new Request(url, init));
      }
      if (url.endsWith('/api/v1/gateway/evidence')) {
        return gatewayEvidencePost(new Request(url, init));
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    const client = new AiForgeGatewayClient({
      baseUrl: 'http://localhost:3000',
      apiKey: rawKey,
      fetchImpl: localFetch,
    });

    // 1. Governed read tool succeeds and receives HMAC-SHA256 signed credential
    const readPrTool = client.guardTool(
      {
        capability: 'github-pr-reader',
        action: 'pull-request:read',
        effect: 'read',
        resolveResource: (args: { repo: string }) => args.repo,
      },
      async (args, cred) => {
        expect(cred.signature).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
        return { repo: args.repo, diffLoaded: true };
      }
    );

    const readResult = await readPrTool({ repo: 'org-approved/payments-api' });
    expect(readResult.diffLoaded).toBe(true);

    // 2. Governed write tool is intercepted by HITL gate (approval_required)
    const commentPrTool = client.guardTool(
      {
        capability: 'github-draft-comment',
        action: 'pull-request:draft-comment',
        effect: 'write',
        resolveResource: (args: { repo: string }) => args.repo,
      },
      async () => ({ posted: true })
    );

    await expect(commentPrTool({ repo: 'org-approved/payments-api' })).rejects.toThrow(
      AiForgePolicyDeniedError
    );

    // 3. Submit EvidenceBundle and verify Ed25519 signature + SHA-256 bundleDigest
    const sealed = await client.submitEvidence({
      status: 'succeeded',
      inputPayload: { repo: 'org-approved/payments-api' },
      outputPayload: { findings: 1 },
      costUsd: 0.0021,
      inputTokens: 150,
      outputTokens: 90,
    });

    expect(sealed.evidenceBundle.integrity.bundleDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(sealed.evidenceBundle.integrity.signature).toMatch(/^ed25519:/);
    expect(sealed.verification.valid).toBe(true);
    expect(client.getRecordedDecisions().length).toBe(2);
    expect(client.getRecordedToolCalls().length).toBe(2);
  });
});

