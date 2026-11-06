import { describe, it, expect, beforeEach } from 'vitest';
import { createHmac } from 'node:crypto';
import { hashPasswordScrypt, verifyPasswordScrypt } from '../../src/lib/auth/config';
import { getAuthContext } from '../../src/lib/auth/session';
import { assertPermission } from '../../src/lib/auth/rbac';
import {
  updateTenantSaasConfig,
  dispatchGovernanceWebhookAlert,
  resetVaultForTests,
} from '../../src/lib/security/vault';
import { DemoCredentialBroker } from '../../src/lib/domain/runtime/credential-broker';
import { createApprovalRequest, decideApproval } from '../../src/lib/domain/approval/service';
import { matchesResourcePattern } from '../../src/lib/domain/policy/engine';
import {
  verifyCsrfOrigin,
  isSafeCallbackPath,
  sanitizeApiError,
} from '../../src/lib/security/http-guards';
import { POST as githubWebhookPost } from '../../src/app/api/webhooks/github/route';
import { getStore, resetMemoryStore } from '../../src/lib/store';

describe('Security Audit Remediation Plan Verification (REM-01 through REM-06)', () => {
  beforeEach(() => {
    resetVaultForTests();
    resetMemoryStore();
    delete process.env.AI_FORGE_REQUIRE_AUTH;
    delete process.env.GITHUB_WEBHOOK_SECRET;
  });

  it('REM-01: hashes and verifies passwords with scrypt + timingSafeEqual and fails closed when auth is required', async () => {
    const hash = hashPasswordScrypt('super-secret-password');
    expect(hash).toHaveLength(128);
    expect(verifyPasswordScrypt('super-secret-password', hash)).toBe(true);
    expect(verifyPasswordScrypt('wrong-password', hash)).toBe(false);

    process.env.AI_FORGE_REQUIRE_AUTH = '1';
    await expect(getAuthContext()).rejects.toThrow(/Unauthorized/);
    delete process.env.AI_FORGE_REQUIRE_AUTH;
  });

  it('REM-02: enforces administrative policy:write permission for Vault & Settings mutations (blocks BFLA)', () => {
    const viewerCtx = {
      userId: 'u_viewer',
      email: 'viewer@acme.local',
      organizationId: 'org_demo_wgf',
      workspaceIds: ['ws_demo_default'],
      role: 'viewer' as const,
    };
    const operatorCtx = {
      ...viewerCtx,
      userId: 'u_op',
      role: 'operator' as const,
    };
    const adminCtx = {
      ...viewerCtx,
      userId: 'u_admin',
      role: 'admin' as const,
    };

    expect(() => assertPermission(viewerCtx, 'policy:write')).toThrow(/Forbidden/);
    expect(() => assertPermission(operatorCtx, 'policy:write')).toThrow(/Forbidden/);
    expect(() => assertPermission(adminCtx, 'policy:write')).not.toThrow();
  });

  it('REM-03: fails closed on unsigned GitHub webhooks, verifies HMAC-SHA256, and blocks replay deliveries', async () => {
    const body = JSON.stringify({ Zen: 'Keep it logically awesome.' });

    // 1. No webhook secret configured -> 401 Fail-Closed
    const unconfiguredReq = new Request('http://localhost:3000/api/webhooks/github', {
      method: 'POST',
      headers: { 'x-github-event': 'ping' },
      body,
    });
    const unconfiguredRes = await githubWebhookPost(unconfiguredReq);
    expect(unconfiguredRes.status).toBe(401);

    // 2. Configure secret in Vault and send valid HMAC + delivery ID -> 200 OK
    const secret = 'whsec_production_hmac_secret_2026';
    updateTenantSaasConfig('org_demo_wgf', {
      secrets: { githubWebhookSecret: secret },
    });

    const sig = 'sha256=' + createHmac('sha256', secret).update(body, 'utf8').digest('hex');
    const validReq = new Request('http://localhost:3000/api/webhooks/github', {
      method: 'POST',
      headers: {
        'x-github-event': 'ping',
        'x-hub-signature-256': sig,
        'x-github-delivery': 'delivery-uuid-001',
      },
      body,
    });
    const validRes = await githubWebhookPost(validReq);
    expect(validRes.status).toBe(200);

    // 3. Replay exact same X-GitHub-Delivery ID -> 409 Conflict
    const replayReq = new Request('http://localhost:3000/api/webhooks/github', {
      method: 'POST',
      headers: {
        'x-github-event': 'ping',
        'x-hub-signature-256': sig,
        'x-github-delivery': 'delivery-uuid-001',
      },
      body,
    });
    const replayRes = await githubWebhookPost(replayReq);
    expect(replayRes.status).toBe(409);
  });

  it('REM-03: blocks SSRF webhook URLs (private IPs, cloud metadata, .internal/.local, HTTP)', async () => {
    expect(() =>
      updateTenantSaasConfig('org_demo_wgf', {
        secrets: { webhookUrl: 'http://127.0.0.1:8080/internal' },
      })
    ).toThrow(/Invalid webhookUrl/);

    expect(() =>
      updateTenantSaasConfig('org_demo_wgf', {
        secrets: { webhookUrl: 'https://169.254.169.254/latest/meta-data/' },
      })
    ).toThrow(/Invalid webhookUrl/);

    expect(() =>
      updateTenantSaasConfig('org_demo_wgf', {
        secrets: { webhookUrl: 'https://metadata.google.internal/computeMetadata/v1/' },
      })
    ).toThrow(/Invalid webhookUrl/);

    process.env.AI_FORGE_WEBHOOK_URL = 'https://10.0.0.5/hook';
    const alertRes = await dispatchGovernanceWebhookAlert('org_demo_wgf', {
      title: 'Test',
      severity: 'info',
      eventType: 'test',
      details: {},
    });
    expect(alertRes.sent).toBe(false);
    expect(alertRes.mode).toContain('blocked_ssrf');
    delete process.env.AI_FORGE_WEBHOOK_URL;
  });

  it('REM-03: signs DelegatedCredentials with HMAC-SHA256 and detects tampering', () => {
    const broker = new DemoCredentialBroker();
    const cred = broker.issue({
      runId: 'run_1',
      releaseDigest: 'sha256:' + 'a'.repeat(64),
      capability: 'github-pr-reader',
      action: 'pull-request:read',
      resource: 'org-approved/payments-api',
      purpose: 'audit',
    });

    expect(cred.signature?.startsWith('hmac-sha256:')).toBe(true);
    expect(broker.validate(cred, 'pull-request:read', 'org-approved/payments-api').valid).toBe(
      true
    );

    // Tamper with resource while keeping original signature
    const tampered = { ...cred, resource: 'evil-org/secrets' };
    const check = broker.validate(tampered, 'pull-request:read', 'evil-org/secrets');
    expect(check.valid).toBe(false);
    expect(check.reason).toBe('invalid_credential_signature');
  });

  it('REM-04: verifies CSRF Origin header, blocks open redirect callbacks, and enforces Four-Eyes HITL approval', () => {
    const goodReq = new Request('https://aiforge.example.com/api/settings', {
      method: 'POST',
      headers: {
        host: 'aiforge.example.com',
        origin: 'https://aiforge.example.com',
      },
    });
    expect(verifyCsrfOrigin(goodReq).valid).toBe(true);

    const csrfAttackReq = new Request('https://aiforge.example.com/api/settings', {
      method: 'POST',
      headers: {
        host: 'aiforge.example.com',
        origin: 'https://evil-attacker.example.com',
      },
    });
    expect(verifyCsrfOrigin(csrfAttackReq).valid).toBe(false);

    // Open redirect guard
    expect(isSafeCallbackPath('/reports')).toBe('/reports');
    expect(isSafeCallbackPath('//evil.example.com')).toBe('/');
    expect(isSafeCallbackPath('https://evil.example.com/phish')).toBe('/');

    // Error sanitizer masks internal paths
    expect(
      sanitizeApiError(
        new Error('ENOENT: no such file or directory, open C:\\secret\\db.json'),
        'Generic error'
      )
    ).toBe('Generic error');

    // Four-eyes HITL enforcement
    const req = createApprovalRequest({
      organizationId: 'org_demo_wgf',
      resourceType: 'tool_invocation',
      resourceId: 'run_123',
      requestedBy: 'user_alice',
      impactSummary: 'Write PR comment',
      permissions: ['pull-request:draft-comment'],
    });

    expect(() =>
      decideApproval(
        req,
        {
          approvalId: req.id,
          decision: 'approved',
          reason: 'Self-approving my own request',
          approverId: 'user_alice',
        },
        { enforceFourEyes: true }
      )
    ).toThrow(/four_eyes_violation/);

    const approvedByBob = decideApproval(
      req,
      {
        approvalId: req.id,
        decision: 'approved',
        reason: 'Reviewed and approved by second security officer',
        approverId: 'user_bob',
      },
      { enforceFourEyes: true }
    );
    expect(approvedByBob.decision).toBe('approved');
  });

  it('REM-05 & REM-06: escapes regex metacharacters in matchesResourcePattern and chains SHA-256 digests in AuditLog', async () => {
    expect(matchesResourcePattern('org.approved/repo+1', ['org.approved/repo+1'])).toBe(true);
    expect(matchesResourcePattern('orgXapproved/repo+1', ['org.approved/repo+1'])).toBe(false);

    const store = await getStore();
    await store.ensureSeed();

    await store.writeAudit({
      organizationId: 'org_demo_wgf',
      actorType: 'user',
      actorId: 'u_1',
      action: 'test.event_one',
    });
    await store.writeAudit({
      organizationId: 'org_demo_wgf',
      actorType: 'user',
      actorId: 'u_1',
      action: 'test.event_two',
    });

    const logs = await store.listAuditLogs('org_demo_wgf', 5);
    const latest = logs[0]?.metadataJson as Record<string, string>;
    const previous = logs[1]?.metadataJson as Record<string, string>;

    expect(latest.auditEntryDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(latest.previousAuditDigest).toBe(previous.auditEntryDigest);
  });
});

