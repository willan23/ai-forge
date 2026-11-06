import Link from 'next/link';
import { getStore } from '../../../../../lib/store';
import { verifyEvidenceBundle } from '../../../../../lib/domain/evidence/verify';

export default async function RunDetailPage({
  params,
}: {
  params: Promise<{ agentId: string; runId: string }>;
}) {
  const { agentId, runId } = await params;
  const store = await getStore();
  const run = await store.getRun(runId);

  if (!run || run.agentId !== agentId) {
    return (
      <div className="panel">
        <p>Run not found.</p>
        <Link className="link-accent" href={`/agents/${agentId}`}>
          Back
        </Link>
      </div>
    );
  }

  const [events, decisions, tools, release] = await Promise.all([
    store.listRunEvents(runId),
    store.listPolicyDecisions(runId),
    store.listToolInvocations(runId),
    store.getRelease(run.agentReleaseId),
  ]);

  const totalLatencyMs = tools.reduce((sum, t) => sum + (t.latencyMs ?? 0), 0);
  const totalCostUsd =
    run.evidenceBundleJson?.cost?.usd ??
    tools.reduce((sum, t) => sum + (t.costUsd ?? 0), 0);

  const verification = run.evidenceBundleJson
    ? verifyEvidenceBundle(run.evidenceBundleJson, {
        expectedReleaseDigest: release?.releaseDigest,
        expectedPolicyDigest: release?.policyDigest,
        lockfile: release?.lockfileJson,
      })
    : null;

  const outputObj = (run.outputJson ?? null) as {
    scenario?: string;
    resource?: string;
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
    recommendations?: string[];
  } | null;

  const findings = outputObj?.analysis?.findings ?? [];

  return (
    <>
      <div className="page-header">
        <div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 }}>
            <span
              className={`badge ${
                run.status === 'succeeded'
                  ? 'trust'
                  : run.status === 'blocked'
                    ? 'danger'
                    : 'warn'
              }`}
            >
              {run.status}
            </span>
            <span className="mono">trace: {run.traceId}</span>
            {verification && (
              <span className={`badge ${verification.valid ? 'trust' : 'danger'}`}>
                {verification.valid
                  ? '✓ Evidence SHA-256 Verified'
                  : '✗ Integrity Check Failed'}
              </span>
            )}
          </div>
          <h1>Run detail</h1>
          <p>
            <Link className="link-accent" href={`/agents/${agentId}`}>
              Agent ({agentId})
            </Link>{' '}
            · Release:{' '}
            {release ? (
              <Link
                className="link-accent mono"
                href={`/agents/${agentId}/releases/${release.id}`}
              >
                {release.releaseDigest.slice(0, 26)}…
              </Link>
            ) : (
              run.agentReleaseId
            )}
          </p>
        </div>
        <div className="header-actions">
          <a className="btn btn-primary" href={`/api/agents/${agentId}/runs/${runId}/evidence`}>
            Export evidence JSON
          </a>
        </div>
      </div>

      {/* Single-Pane-of-Glass Metrics: Cost, Latency, Tools, Release, Policy, Trace */}
      <div className="metrics">
        <div className="metric-card">
          <div className="label">Total Cost</div>
          <div className="value">${totalCostUsd.toFixed(4)}</div>
          <div className="sub">
            Tokens: {run.evidenceBundleJson?.cost?.inputTokens ?? 0} in /{' '}
            {run.evidenceBundleJson?.cost?.outputTokens ?? 0} out
          </div>
        </div>
        <div className="metric-card">
          <div className="label">Tool Latency</div>
          <div className="value">{totalLatencyMs} ms</div>
          <div className="sub">{tools.length} tool invocations</div>
        </div>
        <div className="metric-card">
          <div className="label">Policy Decisions</div>
          <div className="value">{decisions.length}</div>
          <div className="sub">
            {decisions.filter((d) => d.decision === 'deny').length} blocked ·{' '}
            {decisions.filter((d) => d.decision === 'approval_required').length} HITL
          </div>
        </div>
        <div className="metric-card">
          <div className="label">Input Hash</div>
          <div className="mono" style={{ fontSize: 11 }}>
            {run.inputHash}
          </div>
        </div>
        <div className="metric-card">
          <div className="label">Output Hash</div>
          <div className="mono" style={{ fontSize: 11 }}>
            {run.outputHash}
          </div>
        </div>
      </div>

      {/* Structured Security Findings */}
      {findings.length > 0 && (
        <div className="panel">
          <div className="panel-header">
            <h2>Structured Security Findings (Calibrated Confidence, No CoT Exposed)</h2>
            <span className="badge">schema: security-finding.v1</span>
          </div>
          {findings.map((f) => (
            <div key={f.id} className={`finding-card ${f.severity}`}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <div>
                  <span
                    className={`badge ${
                      f.severity === 'high' || f.severity === 'critical'
                        ? 'danger'
                        : f.severity === 'medium'
                          ? 'warn'
                          : 'trust'
                    }`}
                    style={{ marginRight: 8 }}
                  >
                    {f.severity.toUpperCase()}
                  </span>
                  <strong>{f.title}</strong>{' '}
                  <span className="mono">({f.category})</span>
                </div>
                <span className="badge">
                  Confidence: {(f.confidence * 100).toFixed(0)}%
                </span>
              </div>
              <div style={{ fontSize: 13, marginBottom: 4 }}>
                <strong>Evidence:</strong> <span className="mono">{f.evidence}</span>
              </div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                <strong>Recommendation:</strong> {f.recommendation}
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="grid-2">
        <div className="panel" style={{ marginBottom: 0 }}>
          <h2>Policy decisions</h2>
          <table className="table">
            <thead>
              <tr>
                <th>Action</th>
                <th>Decision</th>
                <th>Reason</th>
                <th>Resource</th>
              </tr>
            </thead>
            <tbody>
              {decisions.map((d) => (
                <tr key={d.id}>
                  <td className="mono">{d.action}</td>
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
                  <td className="mono">{d.resource}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel" style={{ marginBottom: 0 }}>
          <h2>Tool invocations</h2>
          <table className="table">
            <thead>
              <tr>
                <th>Capability</th>
                <th>Action</th>
                <th>Status</th>
                <th>Latency</th>
                <th>Cost</th>
              </tr>
            </thead>
            <tbody>
              {tools.map((t) => (
                <tr key={t.id}>
                  <td className="mono">{t.capability}</td>
                  <td className="mono">{t.action}</td>
                  <td>
                    <span className="badge trust">{t.status}</span>
                  </td>
                  <td className="mono">{t.latencyMs ?? '—'} ms</td>
                  <td className="mono">${t.costUsd}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel">
        <h2>Timeline (Append-Only RunEvents)</h2>
        <ul className="timeline">
          {events.map((e) => (
            <li key={e.id}>
              <span
                className={`dot ${
                  e.type.includes('block') || e.type.includes('fail')
                    ? 'danger'
                    : e.type.includes('approval')
                      ? 'warn'
                      : ''
                }`}
              />
              <div>
                <strong>{e.type}</strong>
                <div className="mono">
                  seq {e.sequence} · {e.timestamp}
                </div>
              </div>
            </li>
          ))}
        </ul>
      </div>

      {run.outputJson != null && (
        <div className="panel">
          <h2>Structured output</h2>
          <pre className="code-block">
            {JSON.stringify(run.outputJson, null, 2)}
          </pre>
        </div>
      )}

      {run.evidenceBundleJson && (
        <div className="panel">
          <div className="panel-header">
            <h2>Evidence bundle (integrity)</h2>
            <span className="mono">{run.evidenceBundleJson.integrity.bundleDigest}</span>
          </div>
          {verification && (
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
              {verification.checks.map((c) => (
                <span key={c.check} className={`badge ${c.passed ? 'trust' : 'danger'}`}>
                  {c.passed ? '✓' : '✗'} {c.check}
                </span>
              ))}
            </div>
          )}
          <pre className="code-block" style={{ maxHeight: 360, overflow: 'auto' }}>
            {JSON.stringify(run.evidenceBundleJson, null, 2)}
          </pre>
        </div>
      )}
    </>
  );
}
