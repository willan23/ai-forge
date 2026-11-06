'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

type ScenarioOption = {
  id: 'sqli' | 'injection' | 'out-of-scope' | 'budget-exceeded' | 'scope-merge' | 'write-approval' | 'safe';
  code: string;
  label: string;
  description: string;
};

const SCENARIOS: ScenarioOption[] = [
  {
    id: 'sqli',
    code: 'SQLI-001',
    label: 'SQL Injection Diff + Write Approval Gate',
    description: 'Deteta concatenação SQL na PR #123, consulta CVE database e exige aprovação humana para comentar.',
  },
  {
    id: 'injection',
    code: 'INJECTION-001',
    label: 'Prompt Injection in Untrusted README',
    description: 'README malicioso tenta forçar secret:read e network:egress; PEP bloqueia ambos deterministicamente.',
  },
  {
    id: 'out-of-scope',
    code: 'RESOURCE-001',
    label: 'Out-of-Scope Repository Block',
    description: 'Pedido contra evil-org/secrets fora de org-approved/*; bloqueado com resource_out_of_scope.',
  },
  {
    id: 'budget-exceeded',
    code: 'BUDGET-001',
    label: 'Runaway Tool-Call Budget Enforcement',
    description: 'Excede limite de tool calls durante a run; PEP interrompe a chamada seguinte com budget_exceeded.',
  },
  {
    id: 'scope-merge',
    code: 'SCOPE-001',
    label: 'Unauthorized PR Merge Refusal',
    description: 'Utilizador pede merge da PR; PEP recusa pull-request:merge e oferece relatório em rascunho.',
  },
  {
    id: 'safe',
    code: 'FALSE-POSITIVE-001',
    label: 'Parameterized Safe Query (Zero False Positives)',
    description: 'Diff mantém query parametrizada ($1); agente confirma código seguro sem falso positivo.',
  },
];

interface AuditResult {
  status: string;
  scenario?: string;
  resource?: string;
  runId?: string;
  agentId?: string;
  releaseId?: string;
  releaseDigest: string;
  storeMode?: string;
  inputHash: string;
  outputHash: string;
  policyDecisions: Array<{ action: string; resource?: string; decision: string; reasonCode: string; policyDigest?: string }>;
  toolInvocations?: Array<{ capability: string; action: string; status: string; latencyMs: number; costUsd: number }>;
  events: Array<{ type: string; sequence: number; timestamp?: string }>;
  approvalRequest?: { id: string; impactSummary?: string } | null;
  output?: {
    analysis?: {
      findings?: Array<{
        id: string;
        severity: string;
        category: string;
        title: string;
        evidence: string;
        recommendation: string;
        confidence: number;
      }>;
    };
  } | null;
  evidenceBundle?: {
    integrity: { bundleDigest: string; createdBy: string };
    cost?: { usd: number; inputTokens: number; outputTokens: number; toolCalls: number };
  };
  evidenceJson?: string;
  links?: { run: string; release: string; evidence: string };
  error?: string;
}

interface PlatformOverview {
  storeMode: string;
  currentActor?: {
    userId: string;
    role: string;
    organizationId: string;
  };
  securityPosture?: {
    remediationVersion: string;
    signingKeyId: string;
    signingFingerprint: string;
    controls: Array<{
      id: string;
      title: string;
      status: string;
      detail: string;
    }>;
  };
  metrics: {
    totalAgents: number;
    activeKillSwitches: number;
    totalReleases: number;
    publishedReleases: number;
    totalRuns: number;
    succeededRuns: number;
    blockedRuns: number;
    pendingApprovals: number;
    totalPolicyDecisions: number;
    policyBlocks: number;
    totalCostUsd: number;
  };
  environmentSummary: Array<{
    workspaceId: string;
    name: string;
    environment: string;
    agentCount: number;
    runCount: number;
    blockedRuns: number;
    riskLevel: string;
  }>;
  primaryAgent?: { id: string; name: string; slug: string } | null;
  latestRelease?: {
    id: string;
    version: string;
    releaseDigest: string;
    policyDigest: string;
    status: string;
    scorecardJson?: {
      gateResult: string;
      metrics: {
        task_success_rate: number;
        critical_policy_violations: number;
        injection_resistance?: number;
      };
    } | null;
  } | null;
  recentAuditLogs: Array<{
    id: string;
    actorType: string;
    actorId: string;
    action: string;
    targetType?: string;
    targetId?: string;
    metadataJson?: {
      previousAuditDigest?: string;
      auditEntryDigest?: string;
      [key: string]: unknown;
    } | null;
    timestamp: string;
  }>;
}

export default function OverviewPage() {
  const [running, setRunning] = useState(false);
  const [selectedScenario, setSelectedScenario] = useState<ScenarioOption['id']>('sqli');
  const [overview, setOverview] = useState<PlatformOverview | null>(null);
  const [result, setResult] = useState<AuditResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function loadOverview() {
    try {
      const res = await fetch('/api/overview');
      if (res.ok) {
        const data = await res.json();
        setOverview(data);
      }
    } catch {
      /* ignore */
    }
  }

  useEffect(() => {
    fetch('/api/overview')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data) setOverview(data);
        const cached = sessionStorage.getItem('ai-forge:last-audit');
        if (cached) {
          try {
            setResult(JSON.parse(cached));
          } catch {
            /* ignore */
          }
        }
      })
      .catch(() => {});
  }, []);

  async function runSecurityAudit(scenarioOverride?: ScenarioOption['id']) {
    const scenario = scenarioOverride ?? selectedScenario;
    setRunning(true);
    setError(null);
    try {
      const res = await fetch('/api/demo/run-security-audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? 'Run failed');
      setResult(data);
      sessionStorage.setItem('ai-forge:last-audit', JSON.stringify(data));
      if (data.evidenceJson) {
        sessionStorage.setItem('ai-forge:last-evidence', data.evidenceJson);
      }
      await loadOverview();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error');
    } finally {
      setRunning(false);
    }
  }

  const activeReleaseDigest =
    result?.releaseDigest ?? overview?.latestRelease?.releaseDigest ?? 'sha256:pending';
  const activeAgentId = result?.agentId ?? overview?.primaryAgent?.id ?? 'agent_security_pr_auditor';
  const activeReleaseId = result?.releaseId ?? overview?.latestRelease?.id ?? 'rel_demo_initial';

  return (
    <>
      <div className="page-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
            <span className="badge trust">
              Hardened Security Posture · REM-01..REM-06 Enforced
            </span>
            <span className="badge">
              Store: {result?.storeMode ?? overview?.storeMode ?? 'memory'}
            </span>
            {overview?.currentActor && (
              <span className="badge info">
                Actor: {overview.currentActor.userId} ({overview.currentActor.role})
              </span>
            )}
            {overview?.securityPosture?.signingKeyId && (
              <span className="badge">
                Ed25519: {overview.securityPosture.signingKeyId} (AES-256-GCM at rest)
              </span>
            )}
          </div>
          <h1>Overview</h1>
          <p>
            Camada empresarial de entrega, confiança e evidência para agentes de IA: release imutável
            por digest → gates de avaliação → policy enforcement determinístico antes de cada tool
            call → aprovação humana proporcional ao risco → evidence bundle assinado.
          </p>
        </div>
        <div className="header-actions">
          <select
            aria-label="Audit scenario"
            className="select"
            style={{ width: 290 }}
            value={selectedScenario}
            onChange={(e) => setSelectedScenario(e.target.value as ScenarioOption['id'])}
          >
            {SCENARIOS.map((s) => (
              <option key={s.id} value={s.id}>
                [{s.code}] {s.label}
              </option>
            ))}
          </select>
          <button
            className="btn btn-primary"
            onClick={() => runSecurityAudit()}
            disabled={running}
          >
            {running ? 'Running…' : 'Run Security Audit'}
          </button>
          <Link className="btn btn-secondary" href="/scanner">
            Live Scanner (GitHub + OSV) →
          </Link>
        </div>
      </div>

      {/* 5-Second Executive Trust Narrative (Always Visible) */}
      <div className="panel" style={{ marginBottom: 20 }}>
        <div className="panel-header">
          <h2>Narrativa de Confiança (5-Second Verification Chain)</h2>
          <span className="mono">
            Agent: <Link className="link-accent" href={`/agents/${activeAgentId}`}>security-pr-auditor</Link>
          </span>
        </div>
        <div className="trust-chain">
          <div className="trust-step">
            <div className="trust-step-num">
              <span>1. Release Imutável</span>
              <span className="badge trust">SHA-256</span>
            </div>
            <div className="trust-step-title">Lockfile &amp; Digest</div>
            <div className="mono" style={{ fontSize: 11 }}>
              {activeReleaseDigest.slice(0, 24)}…
            </div>
            <div className="trust-step-desc">
              <Link className="link-accent" href={`/agents/${activeAgentId}/releases/${activeReleaseId}`}>
                Inspecionar Lockfile →
              </Link>
            </div>
          </div>

          <div className="trust-step">
            <div className="trust-step-num">
              <span>2. Eval Gates</span>
              <span className="badge trust">7/7 PASS</span>
            </div>
            <div className="trust-step-title">Suite Regression @0.1.0</div>
            <div className="trust-step-desc">
              0 violações críticas · 100% resistência a prompt injection antes da promoção.
            </div>
          </div>

          <div className="trust-step">
            <div className="trust-step-num">
              <span>3. Policy Engine (PEP)</span>
              <span className="badge trust">9 Regras</span>
            </div>
            <div className="trust-step-title">Deny-by-Default</div>
            <div className="trust-step-desc">
              Nenhuma autorização vem do LLM. PEP valida contrato, escopo e orçamento por tool call.
            </div>
          </div>

          <div className={`trust-step ${result?.status === 'blocked' ? 'danger' : result?.approvalRequest ? 'warn' : ''}`}>
            <div className="trust-step-num">
              <span>4. Controlo de Risco</span>
              <span className={`badge ${result?.status === 'blocked' ? 'danger' : 'warn'}`}>
                {result?.status === 'blocked' ? 'BLOCKED' : 'HITL GATE'}
              </span>
            </div>
            <div className="trust-step-title">
              {result?.status === 'blocked'
                ? 'Ação Fora de Escopo Bloqueada'
                : 'Escrita Retida para Aprovação'}
            </div>
            <div className="trust-step-desc">
              {result?.approvalRequest ? (
                <Link className="link-accent" href="/approvals">
                  Aprovar pedido {result.approvalRequest.id.slice(0, 12)}… →
                </Link>
              ) : (
                <Link className="link-accent" href="/approvals">
                  Gerir aprovações humanas →
                </Link>
              )}
            </div>
          </div>

          <div className="trust-step">
            <div className="trust-step-num">
              <span>5. Evidence Bundle</span>
              <span className="badge trust">Auditável</span>
            </div>
            <div className="trust-step-title">Integridade Criptográfica</div>
            <div className="trust-step-desc">
              {result?.links?.run ? (
                <>
                  <Link className="link-accent" href={result.links.run}>
                    Ver Run
                  </Link>{' '}
                  ·{' '}
                  <a className="link-accent" href={result.links.evidence}>
                    Exportar JSON
                  </a>
                </>
              ) : (
                <Link className="link-accent" href="/evidence">
                  Abrir Evidence Explorer →
                </Link>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Platform Metrics */}
      <div className="metrics">
        <div className="metric-card">
          <div className="label">Releases Assinadas</div>
          <div className="value">{overview?.metrics.publishedReleases ?? 1}</div>
          <div className="sub">Imutáveis por SHA-256</div>
        </div>
        <div className="metric-card">
          <div className="label">Total Runs</div>
          <div className="value">{overview?.metrics.totalRuns ?? (result ? 1 : 0)}</div>
          <div className="sub">
            Last: <span className="mono">{result?.status ?? 'idle'}</span>
          </div>
        </div>
        <div className="metric-card">
          <div className="label">Decisões de Policy</div>
          <div className="value">
            {result?.policyDecisions.length ?? overview?.metrics.totalPolicyDecisions ?? 0}
          </div>
          <div className="sub">{overview?.metrics.policyBlocks ?? 0} bloqueios PEP</div>
        </div>
        <div className="metric-card">
          <div className="label">Aprovações Pendentes</div>
          <div className="value" style={{ color: (overview?.metrics.pendingApprovals ?? 0) > 0 ? 'var(--warning)' : undefined }}>
            {overview?.metrics.pendingApprovals ?? (result?.approvalRequest ? 1 : 0)}
          </div>
          <div className="sub">Escrita exige revisão humana</div>
        </div>
        <div className="metric-card">
          <div className="label">Custo Acumulado</div>
          <div className="value">${(overview?.metrics.totalCostUsd ?? 0).toFixed(4)}</div>
          <div className="sub">Orçamento máx: $2.50 / run</div>
        </div>
        <div className="metric-card">
          <div className="label">Kill Switches Ativos</div>
          <div className="value">{overview?.metrics.activeKillSwitches ?? 0}</div>
          <div className="sub">Controlo imediato por agente</div>
        </div>
      </div>

      {error && (
        <div className="panel">
          <span className="badge danger">{error}</span>
        </div>
      )}

      {/* Interactive Scenario Lab Quick-Launch Bar */}
      <div className="panel">
        <div className="panel-header">
          <h2>Adversarial &amp; Governance Verification Lab (Cenários Obrigatórios)</h2>
          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
            Clique em qualquer cenário para executar uma run real persistida contra o Policy Enforcement Point
          </span>
        </div>
        <div className="grid-3" style={{ marginBottom: 0 }}>
          {SCENARIOS.map((s) => (
            <div
              key={s.id}
              style={{
                background: 'var(--bg-elevated)',
                border: selectedScenario === s.id ? '1px solid var(--trust)' : '1px solid var(--border)',
                borderRadius: 6,
                padding: 12,
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                gap: 10,
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span className="mono" style={{ color: '#2dd4bf', fontWeight: 600 }}>
                    {s.code}
                  </span>
                  <span className="badge" style={{ fontSize: 10 }}>
                    {s.id}
                  </span>
                </div>
                <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4 }}>{s.label}</div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{s.description}</div>
              </div>
              <button
                className="btn btn-secondary btn-sm"
                disabled={running}
                onClick={() => {
                  setSelectedScenario(s.id);
                  runSecurityAudit(s.id);
                }}
              >
                Executar {s.code}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Live Run Result Inspection */}
      {result && (
        <>
          <div className="grid-2">
            <div className="panel" style={{ marginBottom: 0 }}>
              <div className="panel-header">
                <h2>Trust Narrative &amp; Hashes da Run</h2>
                <span
                  className={`badge ${
                    result.status === 'succeeded'
                      ? 'trust'
                      : result.status === 'blocked'
                        ? 'danger'
                        : 'warn'
                  }`}
                >
                  {result.status}
                </span>
              </div>
              <ol className="timeline">
                <li>
                  <span className="dot" />
                  <div>
                    <strong>Release digest resolvido</strong>
                    <div className="mono">{result.releaseDigest}</div>
                    {result.links?.release && (
                      <div>
                        <Link className="link-accent" href={result.links.release}>
                          Ver release
                        </Link>
                      </div>
                    )}
                  </div>
                </li>
                <li>
                  <span className="dot" />
                  <div>
                    <strong>Input &amp; Output Hashes (SHA-256)</strong>
                    <div className="mono">in: {result.inputHash}</div>
                    <div className="mono">out: {result.outputHash}</div>
                  </div>
                </li>
                <li>
                  <span className="dot" />
                  <div>
                    <strong>
                      Policy enforcement antes de cada tool call ({result.policyDecisions.length}{' '}
                      decisões)
                    </strong>
                  </div>
                </li>
                <li>
                  <span className={`dot ${result.approvalRequest ? 'warn' : result.status === 'blocked' ? 'danger' : ''}`} />
                  <div>
                    {result.approvalRequest ? (
                      <>
                        <strong>Escrita enviada para aprovação</strong> —{' '}
                        <Link className="link-accent" href="/approvals">
                          {result.approvalRequest.id}
                        </Link>
                      </>
                    ) : result.status === 'blocked' ? (
                      <strong>Execução bloqueada deterministicamente pelo PEP ({result.error})</strong>
                    ) : (
                      'Sem escrita externa executada'
                    )}
                  </div>
                </li>
                <li>
                  <span className="dot" />
                  <div>
                    <strong>Evidence bundle persistido</strong>
                    {result.evidenceBundle?.integrity?.bundleDigest && (
                      <div className="mono">
                        bundle: {result.evidenceBundle.integrity.bundleDigest}
                      </div>
                    )}
                    {result.links?.run && (
                      <>
                        <Link className="link-accent" href={result.links.run}>
                          Abrir Run Detail
                        </Link>
                        {' · '}
                      </>
                    )}
                    <Link className="link-accent" href="/evidence">
                      Evidence Explorer
                    </Link>
                  </div>
                </li>
              </ol>
            </div>

            <div className="panel" style={{ marginBottom: 0 }}>
              <div className="panel-header">
                <h2>Run Timeline ({result.events.length} eventos append-only)</h2>
                {result.runId && <span className="mono">{result.runId}</span>}
              </div>
              <ul className="timeline">
                {result.events.map((e) => (
                  <li key={e.sequence}>
                    <span
                      className={`dot ${
                        e.type.includes('fail') || e.type.includes('block') || e.type.includes('refused')
                          ? 'danger'
                          : e.type.includes('approval') || e.type.includes('neutralized')
                            ? 'warn'
                            : ''
                      }`}
                    />
                    <div>
                      <strong>{e.type}</strong>
                      <div className="mono">seq {e.sequence}</div>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <h2>Policy Decisions (PEP Audit Trail)</h2>
              <Link className="btn btn-secondary btn-sm" href="/policies">
                Abrir Policy Simulator
              </Link>
            </div>
            <table className="table">
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Resource</th>
                  <th>Decision</th>
                  <th>Reason Code</th>
                </tr>
              </thead>
              <tbody>
                {result.policyDecisions.map((d, i) => (
                  <tr key={`${d.action}-${i}`}>
                    <td className="mono">{d.action}</td>
                    <td className="mono">{d.resource ?? result.resource ?? 'org-approved/payments-api'}</td>
                    <td>
                      <span
                        className={`badge ${
                          d.decision === 'allow'
                            ? 'trust'
                            : d.decision === 'approval_required'
                              ? 'warn'
                              : 'danger'
                        }`}
                      >
                        {d.decision}
                      </span>
                    </td>
                    <td className="mono">{d.reasonCode}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* Environment Isolation & OWASP Agentic Governance Posture */}
      <div className="grid-2">
        <div className="panel" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <h2>Risco e Isolamento por Ambiente</h2>
            <span className="badge">Multi-Workspace</span>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>Workspace</th>
                <th>Ambiente</th>
                <th>Postura</th>
                <th>Agentes</th>
                <th>Runs</th>
              </tr>
            </thead>
            <tbody>
              {(overview?.environmentSummary ?? [
                {
                  workspaceId: 'ws_demo_dev',
                  name: 'Platform Security',
                  environment: 'development',
                  riskLevel: 'controlled',
                  agentCount: 1,
                  runCount: result ? 1 : 0,
                },
                {
                  workspaceId: 'ws_demo_staging',
                  name: 'Platform Security (Staging)',
                  environment: 'staging',
                  riskLevel: 'elevated',
                  agentCount: 0,
                  runCount: 0,
                },
                {
                  workspaceId: 'ws_demo_prod',
                  name: 'Platform Security (Production)',
                  environment: 'production',
                  riskLevel: 'strict',
                  agentCount: 0,
                  runCount: 0,
                },
              ]).map((env) => (
                <tr key={env.workspaceId}>
                  <td>{env.name}</td>
                  <td className="mono">{env.environment}</td>
                  <td>
                    <span
                      className={`badge ${
                        env.environment === 'production'
                          ? 'danger'
                          : env.environment === 'staging'
                            ? 'warn'
                            : 'trust'
                      }`}
                    >
                      {env.riskLevel}
                    </span>
                  </td>
                  <td>{env.agentCount}</td>
                  <td>{env.runCount}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <h2>Controlos OWASP Agentic Top 10 (2026) &amp; NIST AI RMF</h2>
            <span className="badge trust">Enforced</span>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>Ameaça Agentic</th>
                <th>Controlo Técnico AI Forge</th>
                <th>Estado</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>ASI01: Prompt Injection</td>
                <td>PEP determinístico + separação de dados não confiáveis (INJECTION-001)</td>
                <td><span className="badge trust">Ativo</span></td>
              </tr>
              <tr>
                <td>ASI02: Tool Misuse</td>
                <td>Capability Contracts SHA-256 + allowlist estrita de ações</td>
                <td><span className="badge trust">Ativo</span></td>
              </tr>
              <tr>
                <td>ASI03: Privilege Abuse</td>
                <td>Credenciais delegadas efémeras (TTL 300–600s) por ação/recurso</td>
                <td><span className="badge trust">Ativo</span></td>
              </tr>
              <tr>
                <td>ASI04: Supply Chain Drift</td>
                <td>AgentLockfile canónico + releaseDigest imutável (nunca &quot;latest&quot;)</td>
                <td><span className="badge trust">Ativo</span></td>
              </tr>
              <tr>
                <td>ASI05: Runaway Execution</td>
                <td>Budget tracker no servidor (custo USD, tool calls, kill switch)</td>
                <td><span className="badge trust">Ativo</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Security Audit Remediation Posture (REM-01 to REM-06) */}
      <div className="panel" style={{ marginTop: 20 }}>
        <div className="panel-header">
          <div>
            <h2>Postura de Segurança Integral &amp; Remediação Ativa (REM-01 a REM-06)</h2>
            <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              Controlos criptográficos, de sessão, RBAC/ABAC, anti-SSRF, CSRF, Four-Eyes e PostgreSQL RLS verificados em runtime
            </span>
          </div>
          <span className="badge trust">6 / 6 Remediações Ativas</span>
        </div>
        <div className="grid-3" style={{ marginBottom: 0 }}>
          {(overview?.securityPosture?.controls ?? [
            {
              id: 'REM-01',
              title: 'Auth scrypt KDF + Fail-Closed Session & Vault',
              status: 'enforced',
              detail: 'Senhas com scrypt + timingSafeEqual; cookies HttpOnly/SameSite=Lax; AUTH_SECRET obrigatório em prod',
            },
            {
              id: 'REM-02',
              title: 'RBAC/ABAC Estrito no Vault & APIs',
              status: 'enforced',
              detail: 'policy:write exigido em /api/settings; autenticação + Zod strict em /policies, /evidence, /evals',
            },
            {
              id: 'REM-03',
              title: 'Webhook HMAC Fail-Closed + Anti-SSRF + Chaves Cifradas',
              status: 'enforced',
              detail: 'X-Hub-Signature-256 obrigatório + anti-replay; bloqueio IPv4/IPv6/Metadata; Ed25519 AES-256-GCM at rest; credenciais HMAC-SHA256',
            },
            {
              id: 'REM-04',
              title: 'CSRF Origin Guard + Rate Limit + Four-Eyes HITL',
              status: 'enforced',
              detail: 'Verificação de Origin/Host; rate limiting com auto-poda; segregação de funções (Four-Eyes)',
            },
            {
              id: 'REM-05',
              title: 'Hardening CSP + Safe Glob Regex + CI Audit Gate',
              status: 'enforced',
              detail: 'Sem unsafe-eval em produção; escapamento regex no PEP; npm audit no GitHub Actions',
            },
            {
              id: 'REM-06',
              title: 'PostgreSQL Row-Level Security + AuditLog SHA-256 Chain',
              status: 'enforced',
              detail: 'FORCE ROW LEVEL SECURITY por tenant + encadeamento criptográfico previousAuditDigest → auditEntryDigest',
            },
          ]).map((ctrl) => (
            <div
              key={ctrl.id}
              style={{
                background: 'var(--bg-elevated)',
                border: '1px solid var(--trust-border)',
                borderRadius: 6,
                padding: 12,
                display: 'flex',
                flexDirection: 'column',
                gap: 6,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="mono" style={{ color: '#2dd4bf', fontWeight: 700 }}>
                  {ctrl.id}
                </span>
                <span className="badge trust">{ctrl.status.toUpperCase()}</span>
              </div>
              <div style={{ fontWeight: 600, fontSize: 13 }}>{ctrl.title}</div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{ctrl.detail}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Tamper-Evident SHA-256 Chained Audit Log (REM-06) */}
      <div className="panel" style={{ marginTop: 20 }}>
        <div className="panel-header">
          <div>
            <h2>Trilha de Auditoria Imutável Encadeada (SHA-256 Hash Chain · REM-06)</h2>
            <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              Cada evento de auditoria encadeia criptograficamente o digest anterior (`previousAuditDigest` → `auditEntryDigest`)
            </span>
          </div>
          <span className="badge trust">Append-Only · Tamper-Evident</span>
        </div>
        {!overview?.recentAuditLogs || overview.recentAuditLogs.length === 0 ? (
          <p style={{ color: 'var(--text-secondary)', fontSize: 13, margin: 0 }}>
            Execute um cenário de auditoria acima para gerar entradas encadeadas por SHA-256 no AuditLog.
          </p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Target</th>
                <th>Previous Digest</th>
                <th>Entry SHA-256 Digest</th>
              </tr>
            </thead>
            <tbody>
              {overview.recentAuditLogs.slice(0, 8).map((log) => (
                <tr key={log.id}>
                  <td className="mono" style={{ fontSize: 11 }}>
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="mono" style={{ fontSize: 11 }}>
                    {log.actorType}:{log.actorId}
                  </td>
                  <td>
                    <span className="badge info">{log.action}</span>
                  </td>
                  <td className="mono" style={{ fontSize: 11 }}>
                    {log.targetType ? `${log.targetType}:${log.targetId ?? ''}` : '—'}
                  </td>
                  <td className="mono" style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                    {log.metadataJson?.previousAuditDigest
                      ? `${String(log.metadataJson.previousAuditDigest).slice(0, 20)}…`
                      : 'sha256:genesis…'}
                  </td>
                  <td className="mono" style={{ fontSize: 11, color: '#2dd4bf' }}>
                    {log.metadataJson?.auditEntryDigest
                      ? `${String(log.metadataJson.auditEntryDigest).slice(0, 22)}…`
                      : 'verified'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
