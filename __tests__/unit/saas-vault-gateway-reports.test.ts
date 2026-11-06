import { describe, it, expect, beforeEach } from 'vitest';
import { createHmac } from 'node:crypto';
import {
  encryptSecretAes256Gcm,
  decryptSecretAes256Gcm,
  getTenantSaasConfig,
  updateTenantSaasConfig,
  getDecryptedTenantSecret,
  createGatewayApiKey,
  revokeGatewayApiKey,
  validateGatewayApiKey,
  verifyGitHubWebhookSignature,
  resetVaultForTests,
} from '../../src/lib/security/vault';
import {
  demoAuthContext,
  authorizeExternalAgentActionService,
  sealExternalAgentEvidenceService,
  generateExecutiveAuditReportService,
} from '../../src/lib/services/platform';

describe('SaaS Tenant Vault, Universal Agent Gateway & Executive Audit Reports', () => {
  beforeEach(() => {
    resetVaultForTests();
  });

  it('encrypts and decrypts secrets with AES-256-GCM and masks preview safely', () => {
    const secret = 'ghp_1234567890abcdefghijklmnopqrstuvwx';
    const encrypted = encryptSecretAes256Gcm(secret);

    expect(encrypted.ciphertext).not.toContain('ghp_');
    expect(encrypted.maskedPreview).toBe('ghp_••••••••uvwx');

    const decrypted = decryptSecretAes256Gcm(encrypted);
    expect(decrypted).toBe(secret);
  });

  it('stores encrypted BYOK secrets per tenant and updates plan quotas', () => {
    const orgId = 'org_acme_test';
    const initial = getTenantSaasConfig(orgId);
    expect(initial.planTier).toBe('enterprise');

    const updated = updateTenantSaasConfig(orgId, {
      organizationName: 'FinTech Global Corp',
      planTier: 'growth',
      secrets: {
        githubToken: 'ghp_secret_token_99999999',
        nvidiaApiKey: 'nvapi-secret-key-88888888',
      },
    });

    expect(updated.organizationName).toBe('FinTech Global Corp');
    expect(updated.planTier).toBe('growth');
    expect(updated.monthlyRunQuota).toBe(1000);
    expect(updated.secrets.githubToken?.maskedPreview).toBe('ghp_••••••••9999');

    expect(getDecryptedTenantSecret(orgId, 'githubToken')).toBe('ghp_secret_token_99999999');
    expect(getDecryptedTenantSecret(orgId, 'nvidiaApiKey')).toBe('nvapi-secret-key-88888888');
  });

  it('creates, validates, and revokes aiforge_live_ Gateway API keys', () => {
    const orgId = 'org_gateway_test';
    const { rawKey, record } = createGatewayApiKey(orgId, 'LangChain Production Agent');

    expect(rawKey.startsWith('aiforge_live_')).toBe(true);
    expect(record.keyHashSha256).toHaveLength(64);

    const validated = validateGatewayApiKey(rawKey);
    expect(validated).not.toBeNull();
    expect(validated?.id).toBe(record.id);
    expect(validated?.organizationId).toBe(orgId);

    const revoked = revokeGatewayApiKey(orgId, record.id);
    expect(revoked).toBe(true);
    expect(validateGatewayApiKey(rawKey)).toBeNull();
  });

  it('verifies GitHub Webhook HMAC-SHA256 signatures accurately', () => {
    const secret = 'whsec_test_secret_2026';
    const payload = JSON.stringify({ action: 'opened', number: 42 });
    const validSig =
      'sha256=' + createHmac('sha256', secret).update(payload, 'utf8').digest('hex');

    expect(verifyGitHubWebhookSignature(payload, validSig, secret)).toBe(true);
    expect(verifyGitHubWebhookSignature(payload, 'sha256=deadbeef', secret)).toBe(false);
    expect(verifyGitHubWebhookSignature(payload, null, secret)).toBe(false);
  });

  it('authorizes scoped external agent read calls, gates writes with HITL approval, and blocks undeclared tools', async () => {
    const ctx = demoAuthContext();

    // 1. Scoped read -> allow + short-lived delegated credential
    const readAuth = await authorizeExternalAgentActionService(ctx, {
      capability: 'github-pr-reader',
      action: 'pull-request:read',
      effect: 'read',
      resource: 'org-approved/payments-api',
    });
    expect(readAuth.decision).toBe('allow');
    expect(readAuth.delegatedCredential).not.toBeNull();
    expect(readAuth.delegatedCredential?.capability).toBe('github-pr-reader');

    // 2. External write -> approval_required
    const writeAuth = await authorizeExternalAgentActionService(ctx, {
      capability: 'github-draft-comment',
      action: 'pull-request:draft-comment',
      effect: 'write',
      resource: 'org-approved/payments-api',
    });
    expect(writeAuth.decision).toBe('approval_required');
    expect(writeAuth.approvalRequest).not.toBeNull();

    // 3. Undeclared capability or out-of-scope resource -> deny
    const deniedAuth = await authorizeExternalAgentActionService(ctx, {
      capability: 'shell-exec',
      action: 'bash:run',
      effect: 'write',
      resource: 'production-db',
    });
    expect(deniedAuth.decision).toBe('deny');
    expect(deniedAuth.delegatedCredential).toBeNull();
  });

  it('seals external agent telemetry into an Ed25519 + SHA-256 verified EvidenceBundle and generates an Executive Audit Report', async () => {
    const ctx = demoAuthContext();

    const sealed = await sealExternalAgentEvidenceService(ctx, {
      externalRunId: 'ext_run_unit_test_01',
      status: 'succeeded',
      policyDecisions: [
        {
          action: 'pull-request:read',
          resource: 'org-approved/payments-api',
          decision: 'allow',
          reasonCode: 'ALLOWED_BY_POLICY',
        },
        {
          action: 'network:egress',
          resource: 'evil.example.com',
          decision: 'deny',
          reasonCode: 'EGRESS_DOMAIN_DENIED',
        },
      ],
      toolCalls: [
        {
          capability: 'github-pr-reader',
          action: 'pull-request:read',
          status: 'succeeded',
          latencyMs: 42,
          costUsd: 0.0012,
        },
      ],
      cost: {
        totalUsd: 0.0012,
        inputTokens: 450,
        outputTokens: 180,
      },
    });

    expect(sealed.verification.valid).toBe(true);
    expect(sealed.evidenceBundle.integrity.algorithm).toBe('Ed25519');
    expect(sealed.evidenceBundle.integrity.signature).toBeTruthy();

    const execReport = await generateExecutiveAuditReportService(ctx, sealed.run.id);
    expect(execReport.report.run.id).toBe('ext_run_unit_test_01');
    expect(execReport.report.governanceScore.overallScore).toBeGreaterThanOrEqual(95);
    expect(execReport.report.governanceScore.grade).toBe('A+');
    expect(execReport.report.cryptographicCertificate.verified).toBe(true);
    expect(execReport.report.complianceMatrix.length).toBe(8);
  });
});
