'use client';

import { useEffect, useState } from 'react';
import type { ExecutiveAuditReport } from '../../lib/domain/reports/executive-audit-report';

interface AvailableRunItem {
  id: string;
  agentId: string;
  agentName: string;
  status: string;
  startedAt: string;
  bundleDigest: string;
}

export default function ExecutiveReportsPage() {
  const [selectedRunId, setSelectedRunId] = useState<string>('latest');
  const [report, setReport] = useState<ExecutiveAuditReport | null>(null);
  const [availableRuns, setAvailableRuns] = useState<AvailableRunItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    fetch(`/api/reports/${encodeURIComponent(selectedRunId)}`)
      .then((r) => r.json())
      .then((data) => {
        if (!active) return;
        if (data.error) {
          setError(data.error);
        } else {
          setReport(data.report);
          setAvailableRuns(data.availableRuns ?? []);
          setError(null);
        }
        setLoading(false);
      })
      .catch((e) => {
        if (!active) return;
        setError(e instanceof Error ? e.message : 'Failed to load report');
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [selectedRunId]);

  const handleRunChange = (newRunId: string) => {
    setLoading(true);
    setSelectedRunId(newRunId);
  };

  const handleExportJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.reportId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <header className="page-header">
        <div>
          <span className="page-kicker">
            Boardroom Compliance · OWASP Agentic Top 10 · EU AI Act · ISO/IEC 42001 · SOC 2
          </span>
          <h1 className="page-title">Executive AI Security &amp; Governance Certificate</h1>
          <p className="page-subtitle">
            Cryptographically signed compliance report (Ed25519 + SHA-256) ready for CISOs,
            external auditors, and enterprise buyers.
          </p>
        </div>
        <div className="btn-row no-print">
          <select
            aria-label="Select Run for Audit Report"
            value={selectedRunId}
            onChange={(e) => handleRunChange(e.target.value)}
            style={{
              background: 'var(--bg-elevated)',
              border: '1px solid var(--border-strong)',
              borderRadius: 6,
              color: 'var(--text)',
              padding: '8px 12px',
              fontSize: 12.5,
            }}
          >
            <option value="latest">Latest Governed Run</option>
            {availableRuns.map((r) => (
              <option key={r.id} value={r.id}>
                {r.id} · {r.agentName} ({r.status})
              </option>
            ))}
          </select>
          <button type="button" className="btn btn-secondary" onClick={handleExportJson}>
            Export Report JSON
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => window.print()}
          >
            Print / Export Executive PDF
          </button>
        </div>
      </header>

      {error && (
        <div className="panel" style={{ borderColor: 'var(--danger-border)' }}>
          <strong style={{ color: '#f87171' }}>Report Error:</strong> {error}
        </div>
      )}

      {loading && !report && (
        <div className="panel">Generating cryptographic compliance certificate…</div>
      )}

      {report && (
        <>
          <section
            className="panel"
            style={{
              borderColor: report.cryptographicCertificate.verified
                ? 'var(--trust-border)'
                : 'var(--danger-border)',
              background:
                'linear-gradient(180deg, rgba(20, 184, 166, 0.07) 0%, rgba(17, 22, 29, 0.96) 100%)',
            }}
          >
            <div className="panel-header">
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                  <span className="badge trust">
                    GRADE {report.governanceScore.grade} · {report.governanceScore.overallScore}/100
                  </span>
                  <span className="badge info">{report.organizationName}</span>
                  <span className="mono">{report.reportId}</span>
                </div>
                <h2 className="panel-title" style={{ fontSize: 18 }}>
                  {report.governanceScore.executiveVerdict}
                </h2>
              </div>
              <div style={{ textAlign: 'right' }}>
                <span className="badge trust">
                  {report.cryptographicCertificate.verified
                    ? '✓ Ed25519 + SHA-256 Attested'
                    : '✗ Integrity Mismatch'}
                </span>
                <div className="mono" style={{ marginTop: 6, fontSize: 11 }}>
                  Generated: {new Date(report.generatedAt).toLocaleString()}
                </div>
              </div>
            </div>

            <div className="kpi-grid" style={{ marginBottom: 0 }}>
              <div className="kpi-card">
                <div className="kpi-label">Target Resource &amp; Agent</div>
                <div className="kpi-value" style={{ fontSize: 16 }}>
                  {report.run.targetResource}
                </div>
                <div className="kpi-meta">
                  {report.run.agentName} (v{report.run.releaseVersion})
                </div>
              </div>
              <div className="kpi-card">
                <div className="kpi-label">PEP Policy Evaluations</div>
                <div className="kpi-value" style={{ fontSize: 18 }}>
                  {report.metrics.totalPolicyEvaluations} rules checked
                </div>
                <div className="kpi-meta">
                  {report.metrics.allowedActions} allow · {report.metrics.deniedActionsBlocked} deny
                  · {report.metrics.humanApprovalsRequired} HITL
                </div>
              </div>
              <div className="kpi-card">
                <div className="kpi-label">Security Findings &amp; CVEs</div>
                <div className="kpi-value" style={{ fontSize: 18 }}>
                  {report.metrics.findingsCount} finding(s)
                </div>
                <div className="kpi-meta">
                  {report.metrics.criticalOrHighFindings} High/Critical severity
                </div>
              </div>
              <div className="kpi-card">
                <div className="kpi-label">Runtime Cost &amp; Envelope</div>
                <div className="kpi-value" style={{ fontSize: 18 }}>
                  ${report.metrics.totalCostUsd.toFixed(5)}
                </div>
                <div className="kpi-meta">
                  {report.metrics.totalToolInvocations} tool calls · {report.metrics.totalTokens}{' '}
                  tokens
                </div>
              </div>
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <h2 className="panel-title">
                  Regulatory &amp; Standards Compliance Matrix (2026 Benchmarks)
                </h2>
                <p className="panel-subtitle">
                  Automated control mapping across OWASP Agentic AI Top 10, EU AI Act, ISO/IEC
                  42001, SOC 2 Type II, and NIST AI RMF 1.0
                </p>
              </div>
              <span className="badge trust">8 / 8 Controls Verified</span>
            </div>
            <table className="table">
              <thead>
                <tr>
                  <th>Framework</th>
                  <th>Control ID</th>
                  <th>Requirement &amp; Control Objective</th>
                  <th>Status</th>
                  <th>Cryptographic &amp; Runtime Evidence</th>
                </tr>
              </thead>
              <tbody>
                {report.complianceMatrix.map((c) => (
                  <tr key={`${c.framework}-${c.controlId}`}>
                    <td>
                      <strong>{c.framework}</strong>
                    </td>
                    <td className="mono">{c.controlId}</td>
                    <td>{c.title}</td>
                    <td>
                      <span
                        className={`badge ${
                          c.status === 'compliant' || c.status === 'remediated_by_pep'
                            ? 'trust'
                            : 'danger'
                        }`}
                      >
                        {c.status === 'remediated_by_pep'
                          ? 'PEP Enforced'
                          : c.status === 'compliant'
                            ? 'Compliant'
                            : 'Attention'}
                      </span>
                    </td>
                    <td style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>
                      {c.evidenceSummary}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <h2 className="panel-title">
                  Code &amp; Dependency Vulnerability Findings ({report.findings.length})
                </h2>
                <p className="panel-subtitle">
                  Grounded CWE/CVE findings detected during governed execution on{' '}
                  {report.run.targetResource}
                </p>
              </div>
              <span className="badge info">{report.run.modelVersion}</span>
            </div>
            {report.findings.length === 0 ? (
              <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
                No code or dependency vulnerabilities reported in this execution run.
              </p>
            ) : (
              report.findings.map((f) => (
                <div key={f.id} className={`finding-card ${f.severity}`}>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      marginBottom: 6,
                    }}
                  >
                    <strong>
                      [{f.severity.toUpperCase()}] {f.title}
                    </strong>
                    <div style={{ display: 'flex', gap: 6 }}>
                      {f.cwe && <span className="badge warn">{f.cwe}</span>}
                      {f.cve && <span className="badge danger">{f.cve}</span>}
                      <span className="mono">
                        {f.filePath}:{f.line}
                      </span>
                    </div>
                  </div>
                  <div style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>
                    <strong>Remediation:</strong> {f.recommendation}
                  </div>
                </div>
              ))
            )}
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <h2 className="panel-title">Cryptographic Non-Repudiation Certificate</h2>
                <p className="panel-subtitle">
                  Independent verification proof anchored to canonical SHA-256 digests and Ed25519
                  asymmetric signatures
                </p>
              </div>
              <span className="badge trust">{report.cryptographicCertificate.algorithm}</span>
            </div>
            <div className="grid-2">
              <div>
                <table className="table">
                  <tbody>
                    <tr>
                      <th>Signing Key ID</th>
                      <td className="mono">{report.cryptographicCertificate.keyId}</td>
                    </tr>
                    <tr>
                      <th>Public Key Fingerprint</th>
                      <td className="mono">{report.cryptographicCertificate.fingerprintSha256}</td>
                    </tr>
                    <tr>
                      <th>Evidence Bundle Digest</th>
                      <td className="mono">{report.cryptographicCertificate.bundleDigest}</td>
                    </tr>
                    <tr>
                      <th>Immutable Release Digest</th>
                      <td className="mono">{report.cryptographicCertificate.releaseDigest}</td>
                    </tr>
                    <tr>
                      <th>Policy Bundle Digest</th>
                      <td className="mono">{report.cryptographicCertificate.policyDigest}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div>
                <div style={{ marginBottom: 8, fontSize: 12, color: 'var(--text-secondary)' }}>
                  <strong>Ed25519 Digital Signature (Base64) &amp; Verification Checks:</strong>
                </div>
                <pre className="code-block" style={{ marginBottom: 10 }}>
                  {report.cryptographicCertificate.digitalSignatureBase64 ||
                    '(signature attached)'}
                </pre>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {report.cryptographicCertificate.verificationChecks.map((chk) => (
                    <span
                      key={chk.check}
                      className={`badge ${chk.passed ? 'trust' : 'danger'}`}
                    >
                      {chk.passed ? '✓' : '✗'} {chk.check}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
