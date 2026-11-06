import { expect, test } from '@playwright/test';

test.describe('AI Forge end-to-end governance & cryptographic evidence journey', () => {
  test('loads console shell, 5-second trust chain, and security audit CTA', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await expect(page.getByRole('button', { name: /Run Security Audit/i })).toBeVisible();
    await expect(
      page.getByRole('heading', { name: /Narrativa de Confiança \(5-Second Verification Chain\)/i })
    ).toBeVisible();
    await expect(
      page.getByRole('heading', { name: /Postura de Segurança Integral & Remediação Ativa \(REM-01 a REM-06\)/i })
    ).toBeVisible();
    await expect(
      page.getByRole('heading', { name: /Trilha de Auditoria Imutável Encadeada \(SHA-256 Hash Chain · REM-06\)/i })
    ).toBeVisible();
    await expect(page.getByRole('link', { name: /Agents/i })).toBeVisible();
    await expect(page.getByRole('link', { name: /Login/i })).toBeVisible();
  });

  test('executes Security PR Auditor run, inspects 8 agent tabs, policy suite, approvals, and tamper detection', async ({
    page,
  }) => {
    await page.goto('/');

    // 1. Run Security Audit from Overview
    await page.getByRole('button', { name: /Run Security Audit/i }).click();
    await expect(page.getByText(/Policy Decisions \(PEP Audit Trail\)/i)).toBeVisible({
      timeout: 15000,
    });
    await expect(page.getByText(/Release digest resolvido/i)).toBeVisible();

    // 2. Navigate to Agent Detail and verify all 8 mandatory tabs exist
    await page.goto('/agents/agent_security_pr_auditor');
    await expect(
      page.getByRole('heading', { name: 'Security PR Auditor', exact: true })
    ).toBeVisible();
    for (const tabName of [
      'Overview',
      'Manifest',
      'Releases',
      'Evals',
      'Capabilities',
      'Policies',
      'Runs',
      'Evidence',
    ]) {
      await expect(page.getByRole('tab', { name: new RegExp(`^${tabName}`, 'i') })).toBeVisible();
    }

    // 3. Navigate to Manifest Editor and test adversarial preset + semantic diff
    await page.goto('/agents/agent_security_pr_auditor/manifest');
    await expect(page.getByRole('heading', { name: /Manifest editor/i })).toBeVisible();
    await page
      .getByRole('button', { name: /Load Adversarial Candidate/i })
      .click();
    await expect(page.getByText(/CRITICAL/i).first()).toBeVisible();

    // 4. Navigate to Policy Center and run 9-rule regression suite
    await page.goto('/policies');
    await expect(page.getByRole('heading', { name: 'Policy Center' })).toBeVisible();
    await page.getByRole('button', { name: /Run 9-Rule Verification Suite/i }).click();
    await expect(page.getByText(/9\/9 PASSED/i)).toBeVisible();

    // 5. Navigate to Approvals and verify HITL gate
    await page.goto('/approvals');
    await expect(page.getByRole('heading', { name: 'Approvals' })).toBeVisible();

    // 6. Navigate to Evidence Explorer and test SHA-256 tamper detection
    await page.goto('/evidence');
    await expect(page.getByRole('heading', { name: 'Evidence Explorer' })).toBeVisible();
    const tamperBtn = page.getByRole('button', { name: /Simulate Tampering/i });
    await expect(tamperBtn).toBeEnabled();
    await tamperBtn.click();
    await expect(page.getByText(/TAMPERED OR INVALID EVIDENCE BUNDLE/i)).toBeVisible();

    // 7. Navigate to Live Scanner, Search & Safe Browser (/scanner) and test SSRF protection
    await page.goto('/scanner');
    await expect(
      page.getByRole('heading', { name: /Live Scanner, Search & Safe Browser/i })
    ).toBeVisible();
    await page.getByRole('tab', { name: /Governed SSRF-Protected Browser/i }).click();
    await page.getByRole('button', { name: /Test SSRF Block/i }).click();
    await expect(page.getByText(/ssrf_private_host_blocked/i)).toBeVisible();

    // 8. Navigate to Executive Audit Reports (/reports) and verify Compliance Matrix + Ed25519 Certificate
    await page.goto('/reports');
    await expect(
      page.getByRole('heading', { name: /Executive AI Security & Governance Certificate/i })
    ).toBeVisible();
    await expect(page.getByText(/8 \/ 8 Controls Verified/i)).toBeVisible();

    // 9. Navigate to SaaS Settings, BYOK Vault & Universal Agent Gateway (/settings)
    await page.goto('/settings');
    await expect(
      page.getByRole('heading', { name: /SaaS Workspace, BYOK Vault & Universal Agent Gateway/i })
    ).toBeVisible();
    await expect(
      page.getByRole('heading', { name: /Stripe Subscription Checkout & Signed Webhook Billing/i })
    ).toBeVisible();
    await expect(
      page.getByRole('heading', { name: /Team & RBAC Access Control/i })
    ).toBeVisible();
    await expect(
      page.getByRole('heading', { name: /Official SDKs.*GitHub Webhooks/i })
    ).toBeVisible();
    await page.getByRole('button', { name: /Generate API Key/i }).click();
    await expect(page.getByText(/aiforge_live_/i).first()).toBeVisible();
  });

  test('navigates to login from sidebar', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('link', { name: /Login/i }).click();
    await expect(page).toHaveURL(/\/login/);
    await expect(page.getByRole('heading', { name: 'Entrar' })).toBeVisible();
  });
});
