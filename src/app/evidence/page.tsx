'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface VerificationReport {
  valid: boolean;
  tampered: boolean;
  bundleDigest: string;
  recomputedDigest: string;
  verifiedAt: string;
  checks: Array<{
    check: string;
    passed: boolean;
    expected?: string;
    actual?: string;
    detail: string;
  }>;
}

interface EvidenceItem {
  runId: string;
  traceId: string;
  agentId: string;
  agentName: string;
  actor: string;
  releaseId: string;
  releaseVersion: string;
  releaseDigest: string;
  status: string;
  startedAt: string;
  endedAt: string;
  bundleDigest: string;
  bundle: Record<string, unknown>;
  verification: VerificationReport;
}

export default function EvidencePage() {
  const [items, setItems] = useState<EvidenceItem[]>([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [cachedFallback, setCachedFallback] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [decisionFilter, setDecisionFilter] = useState('all');
  const [liveReport, setLiveReport] = useState<VerificationReport | null>(null);
  const [editorJson, setEditorJson] = useState<string>('');

  async function loadEvidence() {
    try {
      const params = new URLSearchParams();
      if (query) params.set('query', query);
      if (decisionFilter !== 'all') params.set('decision', decisionFilter);
      const res = await fetch(`/api/evidence?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        const loaded: EvidenceItem[] = data.items ?? [];
        setItems(loaded);
        if (loaded.length > 0) {
          setSelectedIndex(0);
          setEditorJson(JSON.stringify(loaded[0].bundle, null, 2));
          setLiveReport(loaded[0].verification);
        }
      }
    } catch {
      /* ignore */
    }
  }

  useEffect(() => {
    fetch('/api/evidence')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        const cached = sessionStorage.getItem('ai-forge:last-evidence');
        if (cached) {
          setCachedFallback(cached);
          setEditorJson(cached);
        }
        if (data) {
          const loaded: EvidenceItem[] = data.items ?? [];
          setItems(loaded);
          if (loaded.length > 0) {
            setSelectedIndex(0);
            setEditorJson(JSON.stringify(loaded[0].bundle, null, 2));
            setLiveReport(loaded[0].verification);
          }
        }
      })
      .catch(() => {});
  }, []);

  async function verifyCurrentJson(customJson?: string) {
    try {
      const parsed = JSON.parse(customJson ?? editorJson);
      const res = await fetch('/api/evidence/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bundle: parsed }),
      });
      const report = await res.json();
      setLiveReport(report);
    } catch {
      setLiveReport({
        valid: false,
        tampered: true,
        bundleDigest: 'invalid-json',
        recomputedDigest: 'invalid-json',
        verifiedAt: new Date().toISOString(),
        checks: [
          {
            check: 'json_parse',
            passed: false,
            detail: 'Invalid JSON syntax in evidence bundle payload.',
          },
        ],
      });
    }
  }

  function simulateTampering() {
    if (!editorJson) return;
    try {
      const parsed = JSON.parse(editorJson);
      if (parsed.cost) {
        parsed.cost.usd = 999.99;
      } else {
        parsed.status = 'cancelled';
      }
      const tamperedStr = JSON.stringify(parsed, null, 2);
      setEditorJson(tamperedStr);
      verifyCurrentJson(tamperedStr);
    } catch {
      /* ignore */
    }
  }

  const activeItem = items[selectedIndex] ?? null;
  const displayBundleText =
    editorJson ||
    (cachedFallback &&
    (!query || cachedFallback.toLowerCase().includes(query.toLowerCase()))
      ? cachedFallback
      : '');

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Evidence Explorer</h1>
          <p>
            Pesquisa e verificação criptográfica de Evidence Bundles por trace ID, release digest,
            run ID, actor e decisão de política. Inclui verificador de integridade SHA-256 live.
          </p>
        </div>
        <div className="header-actions">
          <button
            className="btn btn-primary btn-sm"
            disabled={!displayBundleText}
            onClick={() => verifyCurrentJson()}
          >
            Verify SHA-256 Integrity
          </button>
          <button
            className="btn btn-danger btn-sm"
            disabled={!displayBundleText}
            onClick={simulateTampering}
          >
            Simulate Tampering (Modify Payload)
          </button>
        </div>
      </div>

      <div className="panel">
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <input
            className="input"
            style={{ flex: 1, minWidth: 260 }}
            placeholder="Filtrar por texto (trace ID, release digest, run ID, actor, action…)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <select
            className="select"
            style={{ width: 210 }}
            value={decisionFilter}
            onChange={(e) => setDecisionFilter(e.target.value)}
          >
            <option value="all">Todas as Decisões PEP</option>
            <option value="allow">Decision: allow</option>
            <option value="approval_required">Decision: approval_required</option>
            <option value="deny">Decision: deny</option>
          </select>
          <button className="btn btn-secondary" onClick={loadEvidence}>
            Search Store
          </button>
        </div>
      </div>

      {liveReport && (
        <div className="panel">
          <div className="panel-header">
            <h2>Cryptographic Integrity Verification Report</h2>
            <span className={`badge ${liveReport.valid ? 'trust' : 'danger'}`}>
              {liveReport.valid
                ? '✓ VALID · ZERO TAMPERING DETECTED'
                : '✗ TAMPERED OR INVALID EVIDENCE BUNDLE'}
            </span>
          </div>
          <div className="mono" style={{ marginBottom: 10 }}>
            <div>Declared bundleDigest: {liveReport.bundleDigest}</div>
            <div>Recomputed SHA-256: &nbsp;&nbsp;&nbsp;{liveReport.recomputedDigest}</div>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {liveReport.checks.map((c) => (
                <tr key={c.check}>
                  <td className="mono">{c.check}</td>
                  <td>
                    <span className={`badge ${c.passed ? 'trust' : 'danger'}`}>
                      {c.passed ? 'PASS' : 'FAIL'}
                    </span>
                  </td>
                  <td>{c.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {items.length > 0 && (
        <div className="panel">
          <h2>Persisted Evidence Bundles ({items.length})</h2>
          <table className="table">
            <thead>
              <tr>
                <th>Run ID / Trace</th>
                <th>Agent &amp; Actor</th>
                <th>Release Digest</th>
                <th>Bundle Digest</th>
                <th>Status</th>
                <th>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item, idx) => (
                <tr key={item.runId}>
                  <td>
                    <Link
                      className="link-accent mono"
                      href={`/agents/${item.agentId}/runs/${item.runId}`}
                    >
                      {item.runId}
                    </Link>
                  </td>
                  <td>
                    <div>{item.agentName}</div>
                    <div className="mono">{item.actor}</div>
                  </td>
                  <td className="mono">{item.releaseDigest.slice(0, 22)}…</td>
                  <td className="mono">{item.bundleDigest.slice(0, 22)}…</td>
                  <td>
                    <span
                      className={`badge ${
                        item.status === 'succeeded'
                          ? 'trust'
                          : item.status === 'blocked'
                            ? 'danger'
                            : 'warn'
                      }`}
                    >
                      {item.status}
                    </span>
                  </td>
                  <td>
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={() => {
                        setSelectedIndex(idx);
                        const jsonStr = JSON.stringify(item.bundle, null, 2);
                        setEditorJson(jsonStr);
                        setLiveReport(item.verification);
                      }}
                    >
                      Inspect &amp; Verify
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="panel">
        <div className="panel-header">
          <h2>
            Evidence Bundle JSON{' '}
            {activeItem ? `(${activeItem.runId})` : cachedFallback ? '(Cached Run)' : ''}
          </h2>
          {activeItem && (
            <a
              className="btn btn-secondary btn-sm"
              href={`/api/agents/${activeItem.agentId}/runs/${activeItem.runId}/evidence`}
            >
              Download Canonical JSON
            </a>
          )}
        </div>
        {displayBundleText ? (
          <textarea
            className="textarea"
            rows={20}
            value={displayBundleText}
            onChange={(e) => setEditorJson(e.target.value)}
          />
        ) : (
          <p style={{ color: 'var(--text-secondary)', margin: 0 }}>
            Sem evidence bundle em cache ou filtro sem resultados. Corra um Security Audit no{' '}
            <Link className="link-accent" href="/">
              Overview
            </Link>{' '}
            ou exporte a partir da página de Run.
          </p>
        )}
      </div>
    </>
  );
}
