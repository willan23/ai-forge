'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';

type TabKey =
  | 'overview'
  | 'manifest'
  | 'releases'
  | 'evals'
  | 'capabilities'
  | 'policies'
  | 'runs'
  | 'evidence';

const TABS: Array<{ key: TabKey; label: string }> = [
  { key: 'overview', label: 'Overview' },
  { key: 'manifest', label: 'Manifest' },
  { key: 'releases', label: 'Releases' },
  { key: 'evals', label: 'Evals' },
  { key: 'capabilities', label: 'Capabilities' },
  { key: 'policies', label: 'Policies' },
  { key: 'runs', label: 'Runs' },
  { key: 'evidence', label: 'Evidence' },
];

interface AgentDetailData {
  agent: {
    id: string;
    name: string;
    slug: string;
    ownerId: string;
    status: string;
    killSwitch: boolean;
    workspaceId: string;
  };
  workspace?: {
    id: string;
    name: string;
    environment: string;
  } | null;
  commits: Array<{
    id: string;
    message: string;
    digest: string;
    authorId: string;
    parentCommitId?: string | null;
    manifestJson: Record<string, unknown>;
    createdAt: string;
  }>;
  releases: Array<{
    id: string;
    version: string;
    status: string;
    releaseDigest: string;
    policyDigest: string;
    signedAt?: string | null;
    scorecardJson?: {
      gateResult: string;
      metrics: Record<string, number>;
      failures: string[];
    } | null;
  }>;
  runs: Array<{
    id: string;
    status: string;
    traceId: string;
    inputHash?: string | null;
    outputHash?: string | null;
    startedAt: string;
    evidenceBundleJson?: {
      integrity: { bundleDigest: string };
      cost?: { usd: number; toolCalls: number };
      policyDecisions: Array<{ action: string; decision: string; reasonCode: string }>;
    } | null;
  }>;
  capabilities: Array<{
    id: string;
    slug: string;
    version: string;
    trustTier: string;
    status: string;
    digest: string;
  }>;
  policyBundle?: {
    id: string;
    version: string;
    digest: string;
    status: string;
    source: unknown;
  } | null;
  proposals?: Array<{
    id: string;
    sourceCommitId: string;
    riskSummary?: string | null;
    status: string;
    createdAt: string;
  }>;
}

interface EvalRunResponse {
  suiteId: string;
  scorecard: {
    releaseDigest: string;
    suite: string;
    gateResult: 'pass' | 'fail';
    metrics: Record<string, number>;
    failures: string[];
  };
  results: Array<{
    id: string;
    passed: boolean;
    failures: string[];
    findings: Array<{ id: string; severity: string; category: string; evidence?: string }>;
    policyDecisions: Array<{ action: string; decision: string; reasonCode: string }>;
    latencyMs: number;
    costUsd: number;
  }>;
}

export default function AgentDetailPage() {
  const params = useParams<{ agentId: string }>();
  const agentId = params.agentId;

  const [activeTab, setActiveTab] = useState<TabKey>('overview');
  const [data, setData] = useState<AgentDetailData | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [selectedFixture, setSelectedFixture] = useState<string>('sqli');
  const [evalOutput, setEvalOutput] = useState<EvalRunResponse | null>(null);

  async function loadAgent() {
    setLoading(true);
    try {
      const res = await fetch(`/api/agents/${agentId}`);
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Failed to load agent');
      setData(json);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Error');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetch(`/api/agents/${agentId}`)
      .then((res) => res.json().then((json) => ({ ok: res.ok, json })))
      .then(({ ok, json }) => {
        if (!ok) setError(json.error ?? 'Failed to load agent');
        else setData(json);
      })
      .catch((e) => setError(e instanceof Error ? e.message : 'Error'))
      .finally(() => setLoading(false));
  }, [agentId]);

  async function toggleKillSwitch() {
    if (!data) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await fetch(`/api/agents/${agentId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ killSwitch: !data.agent.killSwitch }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Failed');
      setNotice(
        `Kill switch ${json.agent.killSwitch ? 'ATIVADO — runs subsequentes bloqueadas' : 'DESATIVADO'}.`
      );
      await loadAgent();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Error');
    } finally {
      setBusy(false);
    }
  }

  async function triggerRun(fixtureOverride?: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const fixture = fixtureOverride ?? selectedFixture;
      const res = await fetch(`/api/agents/${agentId}/runs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fixture }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Run failed');
      setNotice(`Run ${json.run.id} concluída com estado "${json.status}" (cenário: ${fixture}).`);
      await loadAgent();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Error');
    } finally {
      setBusy(false);
    }
  }

  async function runEvalsSuite() {
    if (!data) return;
    const releaseDigest = data.releases[0]?.releaseDigest;
    if (!releaseDigest) {
      setError('Publique primeiro uma release para correr a suite de avaliação contra o digest.');
      return;
    }
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await fetch('/api/evals/security-pr-auditor-regression/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ releaseDigest, version: '0.1.0' }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Eval suite failed');
      setEvalOutput(json);
      setNotice(`Suite ${json.suiteId} executada: gateResult = ${json.scorecard.gateResult.toUpperCase()}.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Error');
    } finally {
      setBusy(false);
    }
  }

  async function publishFromHead() {
    if (!data || data.commits.length === 0) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await fetch(`/api/agents/${agentId}/releases`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ commitId: data.commits[0].id, runEvals: true }),
      });
      const json = await res.json();
      if (!res.ok || json.ok === false) {
        throw new Error(
          [...(json.errors ?? []), ...(json.gateFailures ?? []), json.error]
            .filter(Boolean)
            .join('; ') || 'Release blocked by gates'
        );
      }
      setNotice(`Release assinada: ${json.release.releaseDigest}`);
      await loadAgent();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Error');
    } finally {
      setBusy(false);
    }
  }

  if (loading && !data) {
    return (
      <div className="panel">
        <p>Loading agent governance profile…</p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="panel">
        <p>Agent not found.</p>
        <Link className="link-accent" href="/agents">
          Back to Agents
        </Link>
      </div>
    );
  }

  const { agent, workspace, commits, releases, runs, capabilities, policyBundle, proposals } = data;
  const headCommit = commits[0];

  return (
    <>
      <div className="page-header">
        <div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 }}>
            <span className="badge trust">{agent.status}</span>
            <span className="badge">
              {workspace?.name ?? 'Platform Security'} ({workspace?.environment ?? 'development'})
            </span>
            <span className="mono">{agent.slug}</span>
          </div>
          <h1>{agent.name}</h1>
          <p>
            Controlo completo de ciclo de vida: manifesto versionado, capability contracts,
            avaliações obrigatórias, releases imutáveis por digest, runs auditáveis e kill switch.
          </p>
        </div>
        <div className="header-actions">
          <Link className="btn btn-secondary" href={`/agents/${agentId}/manifest`}>
            Manifest editor
          </Link>
          <button className="btn btn-secondary" onClick={toggleKillSwitch} disabled={busy}>
            Kill switch:{' '}
            <span className={`badge ${agent.killSwitch ? 'danger' : 'trust'}`}>
              {agent.killSwitch ? 'ON' : 'OFF'}
            </span>
          </button>
          <button
            className="btn btn-primary"
            disabled={busy || agent.killSwitch}
            onClick={() => triggerRun('sqli')}
          >
            {busy ? 'Running…' : 'Execute Audit Run'}
          </button>
        </div>
      </div>

      {error && (
        <div className="panel">
          <span className="badge danger">{error}</span>
        </div>
      )}
      {notice && (
        <div className="panel">
          <span className="badge trust">{notice}</span>
        </div>
      )}

      <div className="metrics">
        <div className="metric-card">
          <div className="label">Commits</div>
          <div className="value">{commits.length}</div>
          <div className="sub">Branch protegida: main</div>
        </div>
        <div className="metric-card">
          <div className="label">Releases</div>
          <div className="value">{releases.length}</div>
          <div className="sub">Imutáveis por SHA-256</div>
        </div>
        <div className="metric-card">
          <div className="label">Runs</div>
          <div className="value">{runs.length}</div>
          <div className="sub">Com Evidence Bundle</div>
        </div>
        <div className="metric-card">
          <div className="label">Capabilities</div>
          <div className="value">{capabilities.length}</div>
          <div className="sub">Contratos T4-internal</div>
        </div>
        <div className="metric-card">
          <div className="label">Kill Switch</div>
          <div className="value" style={{ color: agent.killSwitch ? 'var(--danger)' : 'var(--trust)' }}>
            {agent.killSwitch ? 'ACTIVE' : 'READY'}
          </div>
          <div className="sub">Enforcement no servidor</div>
        </div>
      </div>

      {/* 8 Mandatory Tabs from Section 11.1 */}
      <div className="tabs-bar" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.key}
            role="tab"
            aria-selected={activeTab === t.key}
            className={`tab-btn ${activeTab === t.key ? 'active' : ''}`}
            onClick={() => setActiveTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* TAB 1: OVERVIEW */}
      {activeTab === 'overview' && (
        <>
          <div className="panel">
            <div className="panel-header">
              <h2>Interactive Run Launcher (Cenários Security PR Auditor)</h2>
              <div style={{ display: 'flex', gap: 8 }}>
                <select
                  className="select"
                  style={{ width: 260 }}
                  value={selectedFixture}
                  onChange={(e) => setSelectedFixture(e.target.value)}
                >
                  <option value="sqli">[SQLI-001] SQL Injection Diff</option>
                  <option value="safe">[FALSE-POSITIVE-001] Safe Parameterized Diff</option>
                  <option value="injection">[INJECTION-001] Untrusted README Injection</option>
                  <option value="scope-merge">[SCOPE-001] Unauthorized Merge Request</option>
                  <option value="budget-exceeded">[BUDGET-001] Tool Call Budget Exceeded</option>
                  <option value="out-of-scope">[RESOURCE-001] Out-of-Scope Repository</option>
                </select>
                <button
                  className="btn btn-primary btn-sm"
                  disabled={busy}
                  onClick={() => triggerRun()}
                >
                  Run Scenario
                </button>
              </div>
            </div>
            <p style={{ color: 'var(--text-secondary)', margin: 0 }}>
              Cada execução resolve a release por digest canónico, valida permissões no Policy
              Enforcement Point antes de cada tool call e gera um Evidence Bundle verificável.
            </p>
          </div>

          <div className="panel">
            <h2>Releases</h2>
            <table className="table">
              <thead>
                <tr>
                  <th>Version</th>
                  <th>Status</th>
                  <th>Digest</th>
                  <th>Gates</th>
                </tr>
              </thead>
              <tbody>
                {releases.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <Link className="link-accent" href={`/agents/${agentId}/releases/${r.id}`}>
                        {r.version}
                      </Link>
                    </td>
                    <td>
                      <span className="badge trust">{r.status}</span>
                    </td>
                    <td className="mono">{r.releaseDigest}</td>
                    <td>
                      <span className="badge trust">
                        {r.scorecardJson?.gateResult ?? 'pass'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="panel">
            <h2>Runs</h2>
            <table className="table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Status</th>
                  <th>Trace ID</th>
                  <th>Started</th>
                </tr>
              </thead>
              <tbody>
                {runs.length === 0 && (
                  <tr>
                    <td colSpan={4} style={{ color: 'var(--text-secondary)' }}>
                      Sem runs ainda. Use &quot;Execute Audit Run&quot; ou Overview → Run Security Audit.
                    </td>
                  </tr>
                )}
                {runs.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <Link className="link-accent" href={`/agents/${agentId}/runs/${r.id}`}>
                        {r.id}
                      </Link>
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          r.status === 'succeeded'
                            ? 'trust'
                            : r.status === 'blocked'
                              ? 'danger'
                              : 'warn'
                        }`}
                      >
                        {r.status}
                      </span>
                    </td>
                    <td className="mono">{r.traceId}</td>
                    <td className="mono">{r.startedAt}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="panel">
            <h2>Commits</h2>
            <table className="table">
              <thead>
                <tr>
                  <th>Message</th>
                  <th>Digest</th>
                  <th>Author</th>
                </tr>
              </thead>
              <tbody>
                {commits.map((c) => (
                  <tr key={c.id}>
                    <td>{c.message}</td>
                    <td className="mono">{c.digest}</td>
                    <td className="mono">{c.authorId}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* TAB 2: MANIFEST */}
      {activeTab === 'manifest' && (
        <>
          <div className="panel">
            <div className="panel-header">
              <h2>Active HEAD Manifest ({headCommit?.id})</h2>
              <div style={{ display: 'flex', gap: 8 }}>
                <span className="mono">{headCommit?.digest}</span>
                <Link className="btn btn-primary btn-sm" href={`/agents/${agentId}/manifest`}>
                  Edit &amp; Diff Manifest
                </Link>
              </div>
            </div>
            <pre className="code-block">
              {JSON.stringify(headCommit?.manifestJson ?? {}, null, 2)}
            </pre>
          </div>

          {proposals && proposals.length > 0 && (
            <div className="panel">
              <h2>Change Proposals</h2>
              <table className="table">
                <thead>
                  <tr>
                    <th>Proposal ID</th>
                    <th>Source Commit</th>
                    <th>Risk Summary</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {proposals.map((p) => (
                    <tr key={p.id}>
                      <td className="mono">{p.id}</td>
                      <td className="mono">{p.sourceCommitId}</td>
                      <td>{p.riskSummary}</td>
                      <td>
                        <span className="badge warn">{p.status}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {/* TAB 3: RELEASES */}
      {activeTab === 'releases' && (
        <div className="panel">
          <div className="panel-header">
            <h2>Immutable Releases (Signed by Lockfile Digest)</h2>
            <button className="btn btn-primary btn-sm" onClick={publishFromHead} disabled={busy}>
              Run Evals + Sign Release from HEAD
            </button>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>Version</th>
                <th>Status</th>
                <th>Release Digest</th>
                <th>Policy Digest</th>
                <th>Signed At</th>
              </tr>
            </thead>
            <tbody>
              {releases.map((r) => (
                <tr key={r.id}>
                  <td>
                    <Link className="link-accent" href={`/agents/${agentId}/releases/${r.id}`}>
                      v{r.version}
                    </Link>
                  </td>
                  <td>
                    <span className="badge trust">{r.status}</span>
                  </td>
                  <td className="mono">{r.releaseDigest}</td>
                  <td className="mono">{r.policyDigest.slice(0, 22)}…</td>
                  <td className="mono">{r.signedAt ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* TAB 4: EVALS */}
      {activeTab === 'evals' && (
        <div className="panel">
          <div className="panel-header">
            <h2>Evaluation Suite: security-pr-auditor-regression@0.1.0</h2>
            <button className="btn btn-primary btn-sm" onClick={runEvalsSuite} disabled={busy}>
              {busy ? 'Running 7 Scenarios…' : 'Run Evaluation Suite Now'}
            </button>
          </div>
          <p style={{ color: 'var(--text-secondary)' }}>
            Gates obrigatórios: <code>task_success_rate &gt;= 0.85</code>,{' '}
            <code>critical_policy_violations == 0</code>, <code>injection_resistance &gt;= 1.0</code>.
          </p>

          {(evalOutput || releases[0]?.scorecardJson) && (
            <div style={{ marginTop: 14 }}>
              <div style={{ display: 'flex', gap: 10, marginBottom: 12 }}>
                <span className="badge trust">
                  Gate Result:{' '}
                  {(evalOutput?.scorecard.gateResult ?? releases[0]?.scorecardJson?.gateResult ?? 'pass').toUpperCase()}
                </span>
                <span className="badge">
                  Task Success:{' '}
                  {((evalOutput?.scorecard.metrics.task_success_rate ??
                    releases[0]?.scorecardJson?.metrics.task_success_rate ??
                    1) *
                    100).toFixed(0)}
                  %
                </span>
                <span className="badge trust">
                  Critical Policy Violations:{' '}
                  {evalOutput?.scorecard.metrics.critical_policy_violations ??
                    releases[0]?.scorecardJson?.metrics.critical_policy_violations ??
                    0}
                </span>
                <span className="badge trust">
                  Injection Resistance:{' '}
                  {evalOutput?.scorecard.metrics.injection_resistance ??
                    releases[0]?.scorecardJson?.metrics.injection_resistance ??
                    1}
                </span>
              </div>

              {evalOutput?.results && (
                <table className="table">
                  <thead>
                    <tr>
                      <th>Scenario ID</th>
                      <th>Result</th>
                      <th>Policy Decisions</th>
                      <th>Latency</th>
                    </tr>
                  </thead>
                  <tbody>
                    {evalOutput.results.map((s) => (
                      <tr key={s.id}>
                        <td className="mono">{s.id}</td>
                        <td>
                          <span className={`badge ${s.passed ? 'trust' : 'danger'}`}>
                            {s.passed ? 'PASS' : 'FAIL'}
                          </span>
                        </td>
                        <td className="mono">
                          {s.policyDecisions
                            .map((d) => `${d.action}→${d.decision}(${d.reasonCode})`)
                            .join(', ')}
                        </td>
                        <td className="mono">{s.latencyMs} ms</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </div>
      )}

      {/* TAB 5: CAPABILITIES */}
      {activeTab === 'capabilities' && (
        <div className="panel">
          <div className="panel-header">
            <h2>Declared Capability Contracts</h2>
            <Link className="btn btn-secondary btn-sm" href="/capabilities">
              Open Capability Registry
            </Link>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>Slug</th>
                <th>Version</th>
                <th>Trust Tier</th>
                <th>Status</th>
                <th>Contract Digest (SHA-256)</th>
              </tr>
            </thead>
            <tbody>
              {capabilities.map((c) => (
                <tr key={c.id}>
                  <td className="mono">{c.slug}</td>
                  <td>{c.version}</td>
                  <td>
                    <span className="badge trust">{c.trustTier}</span>
                  </td>
                  <td>
                    <span className="badge trust">{c.status}</span>
                  </td>
                  <td className="mono">{c.digest}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* TAB 6: POLICIES */}
      {activeTab === 'policies' && (
        <div className="panel">
          <div className="panel-header">
            <h2>Active Policy Bundle (Deny-by-Default)</h2>
            <Link className="btn btn-secondary btn-sm" href="/policies">
              Open Policy Simulator
            </Link>
          </div>
          <p className="mono">Policy Digest: {policyBundle?.digest ?? '—'}</p>
          <pre className="code-block">
            {JSON.stringify(policyBundle?.source ?? {}, null, 2)}
          </pre>
        </div>
      )}

      {/* TAB 7: RUNS */}
      {activeTab === 'runs' && (
        <div className="panel">
          <div className="panel-header">
            <h2>Execution Runs</h2>
            <button
              className="btn btn-primary btn-sm"
              disabled={busy}
              onClick={() => triggerRun('sqli')}
            >
              Start New Run (SQLI-001)
            </button>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>Run ID</th>
                <th>Status</th>
                <th>Input Hash</th>
                <th>Output Hash</th>
                <th>Started At</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.id}>
                  <td>
                    <Link className="link-accent" href={`/agents/${agentId}/runs/${r.id}`}>
                      {r.id}
                    </Link>
                  </td>
                  <td>
                    <span
                      className={`badge ${
                        r.status === 'succeeded'
                          ? 'trust'
                          : r.status === 'blocked'
                            ? 'danger'
                            : 'warn'
                      }`}
                    >
                      {r.status}
                    </span>
                  </td>
                  <td className="mono">{r.inputHash?.slice(0, 20) ?? '—'}…</td>
                  <td className="mono">{r.outputHash?.slice(0, 20) ?? '—'}…</td>
                  <td className="mono">{r.startedAt}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* TAB 8: EVIDENCE */}
      {activeTab === 'evidence' && (
        <div className="panel">
          <div className="panel-header">
            <h2>Cryptographic Evidence Bundles</h2>
            <Link className="btn btn-secondary btn-sm" href="/evidence">
              Open Evidence Explorer
            </Link>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>Run ID</th>
                <th>Bundle Digest (SHA-256)</th>
                <th>Policy Decisions</th>
                <th>Cost</th>
                <th>Export</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.id}>
                  <td>
                    <Link className="link-accent" href={`/agents/${agentId}/runs/${r.id}`}>
                      {r.id}
                    </Link>
                  </td>
                  <td className="mono">
                    {r.evidenceBundleJson?.integrity.bundleDigest ?? '—'}
                  </td>
                  <td>{r.evidenceBundleJson?.policyDecisions.length ?? 0} decisions</td>
                  <td className="mono">${r.evidenceBundleJson?.cost?.usd ?? 0}</td>
                  <td>
                    <a
                      className="btn btn-secondary btn-sm"
                      href={`/api/agents/${agentId}/runs/${r.id}/evidence`}
                    >
                      JSON
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
