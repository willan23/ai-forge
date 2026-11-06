'use client';

import { useEffect, useState } from 'react';

interface ApiKeyItem {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  createdAt: string;
  lastUsedAt: string | null;
  revoked: boolean;
}

interface TenantSettingsResponse {
  organizationId: string;
  organizationName: string;
  planTier: 'starter' | 'growth' | 'enterprise';
  monthlyRunQuota: number;
  usedRunsThisMonth: number;
  updatedAt: string;
  secretsStatus: {
    githubToken: string | null;
    openaiApiKey: string | null;
    nvidiaApiKey: string | null;
    geminiApiKey: string | null;
    webhookUrl: string | null;
    githubWebhookSecret: string | null;
  };
  apiKeys: ApiKeyItem[];
}

interface TeamMemberItem {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'operator' | 'auditor' | 'viewer';
  organizationId: string;
  status: string;
  createdAt: string;
  lastLoginAt: string | null;
}

export default function SaasSettingsPage() {
  const [config, setConfig] = useState<TenantSettingsResponse | null>(null);
  const [orgName, setOrgName] = useState('Acme Enterprise Security');
  const [planTier, setPlanTier] = useState<'starter' | 'growth' | 'enterprise'>('enterprise');

  // BYOK Secret inputs
  const [githubToken, setGithubToken] = useState('');
  const [openaiApiKey, setOpenaiApiKey] = useState('');
  const [nvidiaApiKey, setNvidiaApiKey] = useState('');
  const [geminiApiKey, setGeminiApiKey] = useState('');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [githubWebhookSecret, setGithubWebhookSecret] = useState('');

  // API key generator
  const [newKeyName, setNewKeyName] = useState('Production LangChain / CrewAI Agent');
  const [newlyCreatedRawKey, setNewlyCreatedRawKey] = useState<string | null>(null);

  // Team & RBAC Management
  const [teamMembers, setTeamMembers] = useState<TeamMemberItem[]>([]);
  const [inviteName, setInviteName] = useState('');
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<'admin' | 'operator' | 'auditor' | 'viewer'>('operator');
  const [invitePassword, setInvitePassword] = useState('SecOps-2026!');

  // Interactive External Agent Gateway Tester
  const [gwCapability, setGwCapability] = useState('github-pr-reader');
  const [gwAction, setGwAction] = useState('pull-request:read');
  const [gwEffect, setGwEffect] = useState<'read' | 'write'>('read');
  const [gwResource, setGwResource] = useState('org-approved/payments-api');
  const [gwResponse, setGwResponse] = useState<Record<string, unknown> | null>(null);

  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    fetch('/api/settings')
      .then((r) => r.json())
      .then((data: TenantSettingsResponse) => {
        if (!active || !data.organizationId) return;
        setConfig(data);
        setOrgName(data.organizationName);
        setPlanTier(data.planTier);
      })
      .catch(() => undefined);
    fetch('/api/team')
      .then((r) => r.json())
      .then((data: { members?: TeamMemberItem[] }) => {
        if (!active || !data.members) return;
        setTeamMembers(data.members);
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, []);

  const handleSaveVault = async (webhookOverride?: string) => {
    setErrorMessage(null);
    setStatusMessage('Encrypting secrets with AES-256-GCM (scrypt KDF) & validating Anti-SSRF…');
    const targetWebhook = webhookOverride !== undefined ? webhookOverride : webhookUrl;
    const res = await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'update_config',
        organizationName: orgName,
        planTier,
        secrets: {
          githubToken: githubToken || undefined,
          openaiApiKey: openaiApiKey || undefined,
          nvidiaApiKey: nvidiaApiKey || undefined,
          geminiApiKey: geminiApiKey || undefined,
          webhookUrl: targetWebhook || undefined,
          githubWebhookSecret: githubWebhookSecret || undefined,
        },
      }),
    });
    const data = await res.json();
    if (!res.ok || data.error) {
      setStatusMessage(null);
      setErrorMessage(`✗ Bloqueado pela Política de Segurança (REM-02/REM-03): ${data.error ?? 'Operation denied'}`);
      return;
    }
    if (data.config) {
      setConfig(data.config);
      setGithubToken('');
      setOpenaiApiKey('');
      setNvidiaApiKey('');
      setGeminiApiKey('');
      setWebhookUrl('');
      setGithubWebhookSecret('');
      setStatusMessage('✓ Tenant Plan & AES-256-GCM (scrypt KDF) BYOK Vault updated.');
    }
  };

  const handleCreateApiKey = async () => {
    setErrorMessage(null);
    const res = await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'create_key',
        keyName: newKeyName,
      }),
    });
    const data = await res.json();
    if (!res.ok || data.error) {
      setErrorMessage(`✗ Bloqueado (REM-02 RBAC): ${data.error ?? 'Forbidden'}`);
      return;
    }
    if (data.createdKey) {
      setNewlyCreatedRawKey(data.createdKey);
      setConfig(data.config);
      setStatusMessage('✓ New Gateway API Key generated. Copy it now—shown only once.');
    }
  };

  const handleRevokeKey = async (keyId: string) => {
    setErrorMessage(null);
    const res = await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'revoke_key',
        keyId,
      }),
    });
    const data = await res.json();
    if (!res.ok || data.error) {
      setErrorMessage(`✗ Bloqueado (REM-02 RBAC): ${data.error ?? 'Forbidden'}`);
      return;
    }
    if (data.config) {
      setConfig(data.config);
      setStatusMessage(`✓ Revoked key ${keyId}`);
    }
  };

  const handleTestGateway = async () => {
    const res = await fetch('/api/v1/gateway/authorize', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(newlyCreatedRawKey ? { Authorization: `Bearer ${newlyCreatedRawKey}` } : {}),
      },
      body: JSON.stringify({
        capability: gwCapability,
        action: gwAction,
        effect: gwEffect,
        resource: gwResource,
      }),
    });
    const data = await res.json();
    setGwResponse(data);
  };

  const handleStripeCheckout = async (targetTier: 'starter' | 'growth' | 'enterprise') => {
    setErrorMessage(null);
    setStatusMessage(`Creating Stripe Checkout Session for ${targetTier.toUpperCase()}…`);
    const res = await fetch('/api/billing/checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ planTier: targetTier }),
    });
    const data = await res.json();
    if (!res.ok || data.error) {
      setStatusMessage(null);
      setErrorMessage(`✗ Stripe Checkout Error: ${data.error ?? 'Failed'}`);
      return;
    }
    if (data.mode === 'stripe-live-api' && data.checkoutUrl) {
      window.open(data.checkoutUrl, '_blank', 'noopener,noreferrer');
      return;
    }
    if (data.simulatedWebhookEvent) {
      const whRes = await fetch('/api/webhooks/stripe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Stripe-Signature': data.simulatedWebhookEvent.signatureHeader,
        },
        body: data.simulatedWebhookEvent.rawBody,
      });
      const whData = await whRes.json();
      if (whRes.ok) {
        const refreshed = await fetch('/api/settings').then((r) => r.json());
        if (refreshed.organizationId) {
          setConfig(refreshed);
          setPlanTier(refreshed.planTier);
        }
        setStatusMessage(
          `✓ Stripe Webhook Verified (HMAC-SHA256 t=...,v1=...) · Activated ${String(
            whData.planTier
          ).toUpperCase()} (${whData.monthlyRunQuota} Governed Runs/mo).`
        );
      } else {
        setErrorMessage(`✗ Stripe Webhook Verification Failed: ${whData.error}`);
      }
    }
  };

  const handleInviteMember = async () => {
    setErrorMessage(null);
    const res = await fetch('/api/team', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'invite',
        name: inviteName,
        email: inviteEmail,
        role: inviteRole,
        temporaryPassword: invitePassword,
      }),
    });
    const data = await res.json();
    if (!res.ok || data.error) {
      setErrorMessage(`✗ Team Invite Error: ${data.error ?? 'Failed'}`);
      return;
    }
    if (data.members) {
      setTeamMembers(data.members);
      setInviteName('');
      setInviteEmail('');
      setStatusMessage(`✓ Convidado ${data.member.email} com papel RBAC "${data.member.role}" (KDF scrypt).`);
    }
  };

  const handleRevokeMember = async (targetUserId: string) => {
    setErrorMessage(null);
    const res = await fetch('/api/team', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'revoke',
        targetUserId,
      }),
    });
    const data = await res.json();
    if (!res.ok || data.error) {
      setErrorMessage(`✗ Team Protection Guard: ${data.error ?? 'Failed'}`);
      return;
    }
    if (data.members) {
      setTeamMembers(data.members);
      setStatusMessage(`✓ Acesso revogado para ${targetUserId}`);
    }
  };

  return (
    <div>
      <header className="page-header">
        <div>
          <span className="page-kicker">
            Multi-Tenant SaaS · AES-256-GCM BYOK Vault · External Agent Gateway SDK · Webhooks
          </span>
          <h1 className="page-title">SaaS Workspace, BYOK Vault &amp; Universal Agent Gateway</h1>
          <p className="page-subtitle">
            Manage subscription quotas, encrypt tenant API credentials at rest, issue Gateway API
            keys (`aiforge_live_…`) to govern external agents (LangChain, CrewAI, Python, TS), and
            configure GitHub PR Webhooks.
          </p>
        </div>
      </header>

      {statusMessage && (
        <div
          className="panel"
          style={{ borderColor: 'var(--trust-border)', background: 'var(--trust-bg)' }}
        >
          <strong>{statusMessage}</strong>
        </div>
      )}

      {errorMessage && (
        <div
          className="panel"
          style={{ borderColor: 'var(--danger-border)', background: 'rgba(239, 68, 68, 0.08)' }}
        >
          <strong style={{ color: '#f87171' }}>{errorMessage}</strong>
        </div>
      )}

      {config && (
        <div className="kpi-grid">
          <div className="kpi-card">
            <div className="kpi-label">Organization Tenant</div>
            <div className="kpi-value" style={{ fontSize: 18 }}>
              {config.organizationName}
            </div>
            <div className="kpi-meta mono">{config.organizationId}</div>
          </div>
          <div className="kpi-card">
            <div className="kpi-label">Active SaaS Plan Tier</div>
            <div className="kpi-value" style={{ fontSize: 18, textTransform: 'uppercase' }}>
              {config.planTier}
            </div>
            <div className="kpi-meta">
              {config.planTier === 'enterprise'
                ? 'Ed25519 Attestation + Unlimited Agents'
                : config.planTier === 'growth'
                  ? 'Live GitHub + OSV + PEP Gateway'
                  : 'Starter Governance Tier'}
            </div>
          </div>
          <div className="kpi-card">
            <div className="kpi-label">Monthly Governed Run Quota</div>
            <div className="kpi-value" style={{ fontSize: 18 }}>
              {config.usedRunsThisMonth} / {config.monthlyRunQuota.toLocaleString()}
            </div>
            <div className="kpi-meta">Metered per signed EvidenceBundle</div>
          </div>
          <div className="kpi-card">
            <div className="kpi-label">Active Gateway API Keys</div>
            <div className="kpi-value" style={{ fontSize: 18 }}>
              {config.apiKeys.filter((k) => !k.revoked).length} active
            </div>
            <div className="kpi-meta">SHA-256 hashed in Tenant Vault</div>
          </div>
        </div>
      )}

      <div className="grid-2">
        <section className="panel">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Tenant Plan &amp; AES-256-GCM BYOK Secret Vault</h2>
              <p className="panel-subtitle">
                Secrets are encrypted with a 96-bit IV and authentication tag before storage.
                Plaintext is never returned to the browser.
              </p>
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              <span className="badge trust">AES-256-GCM + scrypt KDF</span>
              <span className="badge info">RBAC: policy:write</span>
              <span className="badge warn">Anti-SSRF Webhook Guard</span>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <label className="field">
              <span>Organization Display Name (shown on Executive Audit Certificates)</span>
              <input
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                placeholder="Acme Enterprise Security"
              />
            </label>

            <label className="field">
              <span>SaaS Subscription Plan Tier</span>
              <select
                value={planTier}
                onChange={(e) =>
                  setPlanTier(e.target.value as 'starter' | 'growth' | 'enterprise')
                }
                style={{
                  background: 'var(--bg-elevated)',
                  border: '1px solid var(--border-strong)',
                  borderRadius: 6,
                  color: 'var(--text)',
                  padding: '10px 12px',
                }}
              >
                <option value="starter">Starter ($99/mo · 100 Governed Runs)</option>
                <option value="growth">Growth ($499/mo · 1,000 Governed Runs)</option>
                <option value="enterprise">
                  Enterprise ($2,500+/mo · 10,000 Runs + Boardroom Certificates)
                </option>
              </select>
            </label>

            <label className="field">
              <span>
                GitHub Personal Access Token / App Token{' '}
                {config?.secretsStatus.githubToken && (
                  <strong style={{ color: '#2dd4bf' }}>
                    (Stored: {config.secretsStatus.githubToken})
                  </strong>
                )}
              </span>
              <input
                type="password"
                value={githubToken}
                onChange={(e) => setGithubToken(e.target.value)}
                placeholder="ghp_••••••••••••••••••••••••••••••••••••"
              />
            </label>

            <label className="field">
              <span>
                NVIDIA NIM / OpenAI / Gemini API Key{' '}
                {config?.secretsStatus.nvidiaApiKey && (
                  <strong style={{ color: '#2dd4bf' }}>
                    (Stored: {config.secretsStatus.nvidiaApiKey})
                  </strong>
                )}
              </span>
              <input
                type="password"
                value={nvidiaApiKey}
                onChange={(e) => setNvidiaApiKey(e.target.value)}
                placeholder="nvapi-••••••••••••••••••••••••••••••••••••"
              />
            </label>

            <label className="field">
              <span>
                Slack / Discord / Microsoft Teams Governance Alert Webhook URL{' '}
                {config?.secretsStatus.webhookUrl && (
                  <strong style={{ color: '#2dd4bf' }}>
                    (Stored: {config.secretsStatus.webhookUrl})
                  </strong>
                )}
              </span>
              <input
                type="url"
                value={webhookUrl}
                onChange={(e) => setWebhookUrl(e.target.value)}
                placeholder="https://hooks.slack.com/services/T000/B000/XXXX"
              />
            </label>

            <label className="field">
              <span>
                GitHub Webhook HMAC Secret (`X-Hub-Signature-256`){' '}
                {config?.secretsStatus.githubWebhookSecret && (
                  <strong style={{ color: '#2dd4bf' }}>
                    (Stored: {config.secretsStatus.githubWebhookSecret})
                  </strong>
                )}
              </span>
              <input
                type="password"
                value={githubWebhookSecret}
                onChange={(e) => setGithubWebhookSecret(e.target.value)}
                placeholder="whsec_••••••••••••••••••••••••"
              />
            </label>

            <div className="btn-row" style={{ marginTop: 6, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <button type="button" className="btn btn-primary" onClick={() => handleSaveVault()}>
                Save &amp; Encrypt in Vault
              </button>
              <button
                type="button"
                className="btn btn-danger btn-sm"
                onClick={() => handleSaveVault('http://169.254.169.254/latest/meta-data/')}
              >
                Testar Bloqueio Anti-SSRF no Webhook (REM-03)
              </button>
            </div>
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Universal Agent Gateway API Keys (`aiforge_live_…`)</h2>
              <p className="panel-subtitle">
                Connect external agents in Python, TypeScript, LangChain, CrewAI, or n8n to AI
                Forge&apos;s 9-rule Policy Enforcement Point.
              </p>
            </div>
            <span className="badge info">SHA-256 Hashed</span>
          </div>

          <div style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
            <input
              aria-label="New API Key Name"
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              style={{
                flex: 1,
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border-strong)',
                borderRadius: 6,
                color: 'var(--text)',
                padding: '8px 12px',
              }}
            />
            <button type="button" className="btn btn-primary" onClick={handleCreateApiKey}>
              Generate API Key
            </button>
          </div>

          {newlyCreatedRawKey && (
            <div
              style={{
                padding: 12,
                marginBottom: 14,
                borderRadius: 6,
                border: '1px solid var(--trust-border)',
                background: 'var(--trust-bg)',
              }}
            >
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4 }}>
                Copy your new Gateway API Key (shown only once):
              </div>
              <code className="mono" style={{ color: '#2dd4bf', fontSize: 13 }}>
                {newlyCreatedRawKey}
              </code>
            </div>
          )}

          <table className="table">
            <thead>
              <tr>
                <th>Key Name</th>
                <th>Prefix</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {(config?.apiKeys ?? []).length === 0 ? (
                <tr>
                  <td colSpan={4} style={{ color: 'var(--text-secondary)' }}>
                    No Gateway API Keys issued yet. Click &ldquo;Generate API Key&rdquo; above.
                  </td>
                </tr>
              ) : (
                config?.apiKeys.map((k) => (
                  <tr key={k.id}>
                    <td>
                      <strong>{k.name}</strong>
                    </td>
                    <td className="mono">{k.prefix}</td>
                    <td>
                      <span className={`badge ${k.revoked ? 'danger' : 'trust'}`}>
                        {k.revoked ? 'Revoked' : 'Active'}
                      </span>
                    </td>
                    <td>
                      {!k.revoked && (
                        <button
                          type="button"
                          className="btn btn-danger btn-sm"
                          onClick={() => handleRevokeKey(k.id)}
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>

          <div style={{ marginTop: 18 }}>
            <h3 style={{ fontSize: 14, marginBottom: 8 }}>
              Interactive External Agent PEP Gateway Simulator (`POST /api/v1/gateway/authorize`)
            </h3>
            <div className="grid-2" style={{ marginBottom: 10 }}>
              <label className="field">
                <span>Capability</span>
                <input
                  value={gwCapability}
                  onChange={(e) => setGwCapability(e.target.value)}
                />
              </label>
              <label className="field">
                <span>Action</span>
                <input value={gwAction} onChange={(e) => setGwAction(e.target.value)} />
              </label>
              <label className="field">
                <span>Effect</span>
                <select
                  value={gwEffect}
                  onChange={(e) => setGwEffect(e.target.value as 'read' | 'write')}
                  style={{
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border-strong)',
                    borderRadius: 6,
                    color: 'var(--text)',
                    padding: '10px 12px',
                  }}
                >
                  <option value="read">read (Auto-Allowed if Scoped)</option>
                  <option value="write">write (Triggers HITL Approval Gate)</option>
                </select>
              </label>
              <label className="field">
                <span>Target Resource</span>
                <input value={gwResource} onChange={(e) => setGwResource(e.target.value)} />
              </label>
            </div>
            <button type="button" className="btn btn-secondary" onClick={handleTestGateway}>
              Test External Gateway Call
            </button>
            {gwResponse && (
              <pre className="code-block" style={{ marginTop: 10 }}>
                {JSON.stringify(gwResponse, null, 2)}
              </pre>
            )}
          </div>
        </section>
      </div>

      {/* Stripe Billing & Team RBAC Panels */}
      <div className="grid-2">
        <section className="panel">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Stripe Subscription Checkout &amp; Signed Webhook Billing</h2>
              <p className="panel-subtitle">
                Cryptographically verified via `Stripe-Signature` (`t=...,v1=HMAC-SHA256`) + anti-replay
                event deduplication (`POST /api/webhooks/stripe`).
              </p>
            </div>
            <span className="badge trust">Stripe HMAC-SHA256</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {(
              [
                {
                  tier: 'starter' as const,
                  title: 'Starter ($99/mo)',
                  quota: '100 Governed Runs / mo · 9-Rule PEP · SHA-256 Evidence',
                },
                {
                  tier: 'growth' as const,
                  title: 'Growth ($499/mo)',
                  quota: '1,000 Governed Runs / mo · Live GitHub + OSV Scanner · SDK Gateway',
                },
                {
                  tier: 'enterprise' as const,
                  title: 'Enterprise ($2,500/mo)',
                  quota: '10,000 Governed Runs / mo · Ed25519 Boardroom Certificates · Four-Eyes',
                },
              ]
            ).map((plan) => (
              <div
                key={plan.tier}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: 12,
                  borderRadius: 6,
                  background: 'var(--bg-elevated)',
                  border:
                    config?.planTier === plan.tier
                      ? '1px solid var(--trust-border)'
                      : '1px solid var(--border)',
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13.5 }}>
                    {plan.title}{' '}
                    {config?.planTier === plan.tier && (
                      <span className="badge trust" style={{ marginLeft: 6 }}>
                        Active Plan
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{plan.quota}</div>
                </div>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => handleStripeCheckout(plan.tier)}
                >
                  Checkout {plan.tier.toUpperCase()}
                </button>
              </div>
            ))}
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Team &amp; RBAC Access Control (`scrypt` + Multi-Tenant)</h2>
              <p className="panel-subtitle">
                Invite security engineers, operators, and external auditors with least-privilege RBAC
                roles (`admin`, `operator`, `auditor`, `viewer`).
              </p>
            </div>
            <span className="badge info">{teamMembers.length} Members</span>
          </div>

          <div className="grid-2" style={{ marginBottom: 10 }}>
            <label className="field">
              <span>Full Name</span>
              <input
                placeholder="Carlos Mendes (SecOps)"
                value={inviteName}
                onChange={(e) => setInviteName(e.target.value)}
              />
            </label>
            <label className="field">
              <span>Corporate Email</span>
              <input
                type="email"
                placeholder="carlos@enterprise.local"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
              />
            </label>
            <label className="field">
              <span>RBAC Role</span>
              <select
                value={inviteRole}
                onChange={(e) =>
                  setInviteRole(
                    e.target.value as 'admin' | 'operator' | 'auditor' | 'viewer'
                  )
                }
                style={{
                  background: 'var(--bg-elevated)',
                  border: '1px solid var(--border-strong)',
                  borderRadius: 6,
                  color: 'var(--text)',
                  padding: '10px 12px',
                }}
              >
                <option value="operator">operator (Execute Runs + Decide HITL Approvals)</option>
                <option value="auditor">auditor (Read + Export Signed Evidence Bundles)</option>
                <option value="viewer">viewer (Read-Only Dashboard Access)</option>
                <option value="admin">admin (Full Policy, Vault &amp; Release Control)</option>
              </select>
            </label>
            <label className="field">
              <span>Initial Password (scrypt KDF)</span>
              <input
                type="password"
                value={invitePassword}
                onChange={(e) => setInvitePassword(e.target.value)}
              />
            </label>
          </div>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            style={{ marginBottom: 14 }}
            onClick={handleInviteMember}
          >
            Invite Team Member
          </button>

          <table className="table">
            <thead>
              <tr>
                <th>Name &amp; Email</th>
                <th>RBAC Role</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {teamMembers.map((m) => (
                <tr key={m.id}>
                  <td>
                    <strong>{m.name}</strong>
                    <div className="mono" style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                      {m.email}
                    </div>
                  </td>
                  <td>
                    <span className="badge info">{m.role}</span>
                  </td>
                  <td>
                    <span className="badge trust">{m.status}</span>
                  </td>
                  <td>
                    <button
                      type="button"
                      className="btn btn-danger btn-sm"
                      onClick={() => handleRevokeMember(m.id)}
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>

      <section className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">
              Official SDKs (`@aiforge/sdk` TS &amp; `aiforge_sdk` Python) &amp; GitHub Webhooks
            </h2>
            <p className="panel-subtitle">
              Drop-in SDK wrappers (`guardTool` / `@governed_tool`) for LangChain, CrewAI, OpenAI
              Agents SDK, and GitHub Pull Request Webhooks
            </p>
          </div>
          <span className="badge trust">Universal PEP Gateway SDK</span>
        </div>
        <div className="grid-2">
          <div>
            <div style={{ fontSize: 12.5, fontWeight: 600, marginBottom: 6 }}>
              1. TypeScript SDK (`src/sdk/typescript/index.ts`) &amp; Python SDK (`sdk/python/aiforge_sdk.py`):
            </div>
            <pre className="code-block">{`// TypeScript (@aiforge/sdk)
import { AiForgeGatewayClient } from "@/sdk/typescript";

const aiforge = new AiForgeGatewayClient({
  baseUrl: "https://your-aiforge.com",
  apiKey: "${newlyCreatedRawKey ?? 'aiforge_live_<YOUR_KEY>'}",
});

const readPrDiff = aiforge.guardTool(
  {
    capability: "github-pr-reader",
    action: "pull-request:read",
    effect: "read",
    resolveResource: (args: { repo: string }) => args.repo,
  },
  async (args, delegatedCredential) => {
    // Runs ONLY after 9-rule PEP allows & issues HMAC-SHA256 credential
    return fetchPrDiff(args.repo, delegatedCredential.id);
  }
);`}</pre>
          </div>
          <div>
            <div style={{ fontSize: 12.5, fontWeight: 600, marginBottom: 6 }}>
              2. Python Decorator (`sdk/python/aiforge_sdk.py`) &amp; GitHub PR Webhook:
            </div>
            <pre className="code-block">{`# Python (sdk/python/aiforge_sdk.py)
from sdk.python.aiforge_sdk import AiForgeGatewayClient

client = AiForgeGatewayClient(
    base_url="https://your-aiforge.com",
    api_key="${newlyCreatedRawKey ?? 'aiforge_live_<YOUR_KEY>'}",
)

@client.governed_tool(
    capability="github-pr-reader",
    action="pull-request:read",
    effect="read",
)
def analyze_pull_request(resource: str = "org-approved/payments-api"):
    return {"status": "audited", "repo": resource}

# Seal & sign Ed25519 + SHA-256 EvidenceBundle:
bundle = client.submit_evidence(status="succeeded")`}</pre>
          </div>
        </div>
      </section>
    </div>
  );
}

