'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface HealthStatus {
  status: string;
  store: { mode: string; durableDiskPersistence: boolean };
  crypto: {
    algorithm: string;
    keyId: string;
    fingerprintSha256: string;
    publicKeyPem: string;
  };
  llm: { configured: boolean; provider: string; model: string };
  integrations: Record<string, string>;
}

interface LiveAuditResponse {
  run: { id: string; status: string };
  release: { id: string; releaseDigest: string; version: string };
  approval?: { id: string };
  github: {
    status: string;
    latencyMs: number;
    error?: string;
    data?: {
      repository: string;
      prNumber: number;
      title: string;
      htmlUrl?: string;
      author?: string;
      headSha?: string;
      diff?: string;
      files?: Array<{ path: string; status: string; additions: number; deletions: number }>;
    };
  };
  osv: {
    status: string;
    latencyMs: number;
    data?: {
      package: string;
      version: string;
      totalFound: number;
      matches: Array<{
        id: string;
        cve: string;
        severity: string;
        summary: string;
        referenceUrl?: string;
      }>;
    };
  };
  webIntelligence: {
    status: string;
    latencyMs: number;
    data?: {
      query: string;
      totalResults: number;
      items: Array<{
        id: string;
        source: string;
        title: string;
        summary: string;
        url: string;
        severity?: string;
        cveId?: string;
      }>;
    };
  };
  llmAnalysis: {
    modelVersion: string;
    usage: { inputTokens: number; outputTokens: number; costUsd: number };
    findings: Array<{
      id: string;
      severity: string;
      category: string;
      title: string;
      evidence: string;
      recommendation: string;
      confidence: number;
    }>;
  };
  policyDecisions: Array<{
    action: string;
    resource: string;
    decision: string;
    reasonCode: string;
  }>;
  evidenceBundle: {
    integrity: {
      bundleDigest: string;
      signature?: string;
      keyId?: string;
      algorithm?: string;
    };
  };
}

interface SearchItem {
  id: string;
  source: string;
  title: string;
  summary: string;
  url: string;
  severity?: string;
  cveId?: string;
  publishedAt?: string;
}

export default function LiveScannerPage() {
  const [activeTab, setActiveTab] = useState<'repo' | 'search' | 'browse'>('repo');
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [showPublicKey, setShowPublicKey] = useState(false);

  // Tab 1: Live Repo Audit
  const [repo, setRepo] = useState('lodash/lodash');
  const [prNumber, setPrNumber] = useState('');
  const [pkgToScan, setPkgToScan] = useState('lodash');
  const [versionToScan, setVersionToScan] = useState('4.17.15');
  const [auditing, setAuditing] = useState(false);
  const [auditResult, setAuditResult] = useState<LiveAuditResponse | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);

  // Tab 2: Live Intelligence Search
  const [searchQuery, setSearchQuery] = useState('lodash');
  const [searching, setSearching] = useState(false);
  const [searchItems, setSearchItems] = useState<SearchItem[]>([]);
  const [searchLatency, setSearchLatency] = useState<number | null>(null);

  // Tab 3: SSRF-Protected Governed Browser
  const [browseUrl, setBrowseUrl] = useState('https://osv.dev');
  const [browsing, setBrowsing] = useState(false);
  const [browseResult, setBrowseResult] = useState<{
    status: string;
    error?: string;
    latencyMs?: number;
    data?: {
      url: string;
      httpStatus?: number;
      title?: string;
      excerpt?: string;
      reason?: string;
    };
  } | null>(null);

  useEffect(() => {
    fetch('/api/health')
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (data) setHealth(data);
      })
      .catch(() => {});
  }, []);

  async function runLiveRepoAudit() {
    setAuditing(true);
    setAuditError(null);
    try {
      const res = await fetch('/api/live/audit-repo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repo,
          prNumber: prNumber ? Number(prNumber) : undefined,
          packageToScan: pkgToScan,
          versionToScan: versionToScan || undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? 'Live audit failed');
      setAuditResult(data);
      if (data.evidenceBundle) {
        sessionStorage.setItem('ai-forge:last-evidence', JSON.stringify(data.evidenceBundle, null, 2));
      }
    } catch (e) {
      setAuditError(e instanceof Error ? e.message : 'Live audit failed');
    } finally {
      setAuditing(false);
    }
  }

  async function runLiveSearch(customQuery?: string) {
    const q = customQuery ?? searchQuery;
    if (customQuery) setSearchQuery(customQuery);
    setSearching(true);
    try {
      const res = await fetch('/api/live/intelligence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'search', query: q }),
      });
      const data = await res.json();
      setSearchItems(data.data?.items ?? []);
      setSearchLatency(data.latencyMs ?? null);
    } catch {
      /* ignore */
    } finally {
      setSearching(false);
    }
  }

  async function runSafeBrowse(targetOverride?: string) {
    const target = targetOverride ?? browseUrl;
    if (targetOverride) setBrowseUrl(targetOverride);
    setBrowsing(true);
    try {
      const res = await fetch('/api/live/intelligence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'browse', url: target }),
      });
      const data = await res.json();
      setBrowseResult(data);
    } catch (e) {
      setBrowseResult({ status: 'failed', error: String(e) });
    } finally {
      setBrowsing(false);
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <span className="badge trust">REAL-INTEGRATION MODE · LIVE HTTPS &amp; ED25519</span>
            {health && (
              <span className="badge">
                LLM: {health.llm.provider} ({health.llm.model})
              </span>
            )}
            {health && <span className="badge">Signer: {health.crypto.keyId}</span>}
          </div>
          <h1>Live Scanner, Search &amp; Safe Browser</h1>
          <p>
            Auditoria real de repositórios GitHub via REST API, pesquisa de vulnerabilidades em
            tempo real no OSV.dev / GitHub Advisories / NPM Registry, navegação HTTPS protegida
            contra SSRF e assinatura criptográfica assimétrica Ed25519.
          </p>
        </div>
        {health && (
          <div className="header-actions">
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setShowPublicKey((v) => !v)}
            >
              {showPublicKey ? 'Hide Ed25519 Public Key' : 'Inspect Ed25519 Public Key'}
            </button>
          </div>
        )}
      </div>

      {showPublicKey && health && (
        <div className="panel">
          <div className="panel-header">
            <h2>Organizational Ed25519 Signing Key ({health.crypto.keyId})</h2>
            <span className="mono">{health.crypto.fingerprintSha256}</span>
          </div>
          <pre className="code">{health.crypto.publicKeyPem}</pre>
        </div>
      )}

      <div className="tabs-bar" role="tablist">
        <button
          role="tab"
          aria-selected={activeTab === 'repo'}
          className={`tab-btn ${activeTab === 'repo' ? 'active' : ''}`}
          onClick={() => setActiveTab('repo')}
        >
          1. Live GitHub Repository &amp; OSV.dev Auditor
        </button>
        <button
          role="tab"
          aria-selected={activeTab === 'search'}
          className={`tab-btn ${activeTab === 'search' ? 'active' : ''}`}
          onClick={() => setActiveTab('search')}
        >
          2. Live Security &amp; Package Search
        </button>
        <button
          role="tab"
          aria-selected={activeTab === 'browse'}
          className={`tab-btn ${activeTab === 'browse' ? 'active' : ''}`}
          onClick={() => setActiveTab('browse')}
        >
          3. Governed SSRF-Protected Browser
        </button>
      </div>

      {/* TAB 1: LIVE REPO AUDITOR */}
      {activeTab === 'repo' && (
        <>
          <div className="panel">
            <div className="panel-header">
              <h2>Auditar Repositório Público GitHub + OSV.dev CVE Database em Tempo Real</h2>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => {
                    setRepo('lodash/lodash');
                    setPkgToScan('lodash');
                    setVersionToScan('4.17.15');
                  }}
                >
                  Preset: lodash/lodash (4.17.15)
                </button>
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => {
                    setRepo('expressjs/express');
                    setPkgToScan('express');
                    setVersionToScan('4.17.1');
                  }}
                >
                  Preset: expressjs/express (4.17.1)
                </button>
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => {
                    setRepo('axios/axios');
                    setPkgToScan('axios');
                    setVersionToScan('0.21.1');
                  }}
                >
                  Preset: axios/axios (0.21.1)
                </button>
              </div>
            </div>

            <div className="grid-2" style={{ marginBottom: 12 }}>
              <div>
                <label style={{ display: 'block', fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>
                  GitHub Repository (owner/repo)
                </label>
                <input
                  className="input"
                  value={repo}
                  onChange={(e) => setRepo(e.target.value)}
                  placeholder="ex: expressjs/express"
                />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
                <div>
                  <label style={{ display: 'block', fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>
                    PR # (opcional)
                  </label>
                  <input
                    className="input"
                    value={prNumber}
                    onChange={(e) => setPrNumber(e.target.value)}
                    placeholder="Auto (latest)"
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>
                    Pacote npm (OSV.dev)
                  </label>
                  <input
                    className="input"
                    value={pkgToScan}
                    onChange={(e) => setPkgToScan(e.target.value)}
                    placeholder="lodash"
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>
                    Versão
                  </label>
                  <input
                    className="input"
                    value={versionToScan}
                    onChange={(e) => setVersionToScan(e.target.value)}
                    placeholder="4.17.15"
                  />
                </div>
              </div>
            </div>

            <button
              className="btn btn-primary"
              disabled={auditing}
              onClick={runLiveRepoAudit}
            >
              {auditing
                ? 'A consultar GitHub API + OSV.dev + LLM + PEP…'
                : 'Run Live Governed Repository Audit'}
            </button>
          </div>

          {auditError && (
            <div className="panel">
              <span className="badge danger">{auditError}</span>
            </div>
          )}

          {auditResult && (
            <>
              <div className="panel">
                <div className="panel-header">
                  <h2>
                    Resultado da Auditoria Live — {auditResult.github.data?.repository ?? repo}
                  </h2>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <span className="badge trust">
                      Signed: {auditResult.evidenceBundle.integrity.keyId}
                    </span>
                    <Link
                      className="btn btn-primary btn-sm"
                      href={`/agents/agent_security_pr_auditor/runs/${auditResult.run.id}`}
                    >
                      Abrir Run Detail ({auditResult.run.id.slice(0, 14)}…) →
                    </Link>
                  </div>
                </div>

                <div className="metrics" style={{ marginBottom: 12 }}>
                  <div className="metric-card">
                    <div className="label">GitHub API Latency</div>
                    <div className="value">{auditResult.github.latencyMs} ms</div>
                    <div className="sub">
                      {auditResult.github.data?.prNumber
                        ? `PR #${auditResult.github.data.prNumber}`
                        : 'Latest Commit Diff'}
                    </div>
                  </div>
                  <div className="metric-card">
                    <div className="label">OSV.dev CVEs Found</div>
                    <div className="value" style={{ color: 'var(--warn)' }}>
                      {auditResult.osv.data?.totalFound ?? 0}
                    </div>
                    <div className="sub">
                      {auditResult.osv.data?.package}@{auditResult.osv.data?.version} (
                      {auditResult.osv.latencyMs} ms)
                    </div>
                  </div>
                  <div className="metric-card">
                    <div className="label">Model Analyzer</div>
                    <div className="value" style={{ fontSize: 15 }}>
                      {auditResult.llmAnalysis.modelVersion}
                    </div>
                    <div className="sub">
                      {auditResult.llmAnalysis.usage.inputTokens} in /{' '}
                      {auditResult.llmAnalysis.usage.outputTokens} out tokens
                    </div>
                  </div>
                  <div className="metric-card">
                    <div className="label">Ed25519 Signature</div>
                    <div className="value" style={{ fontSize: 14, color: 'var(--trust)' }}>
                      VERIFIED
                    </div>
                    <div className="sub mono">
                      {auditResult.evidenceBundle.integrity.bundleDigest.slice(0, 22)}…
                    </div>
                  </div>
                </div>

                <h3>
                  Achados de Segurança &amp; CVEs Reais ({auditResult.llmAnalysis.findings.length})
                </h3>
                <div className="finding-grid" style={{ marginBottom: 16 }}>
                  {auditResult.llmAnalysis.findings.map((f, idx) => (
                    <div
                      key={`${f.id}-${idx}`}
                      className={`finding-card ${f.severity === 'high' || f.severity === 'critical' ? 'high' : ''}`}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                        <strong>{f.title}</strong>
                        <span
                          className={`badge ${
                            f.severity === 'high' || f.severity === 'critical'
                              ? 'danger'
                              : f.severity === 'medium'
                                ? 'warn'
                                : 'trust'
                          }`}
                        >
                          {f.severity} · {f.category}
                        </span>
                      </div>
                      <div className="mono" style={{ marginBottom: 6 }}>
                        Evidência: {f.evidence}
                      </div>
                      <div style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>
                        Recomendação: {f.recommendation}
                      </div>
                    </div>
                  ))}
                </div>

                {auditResult.github.data?.diff && (
                  <>
                    <h3>
                      Diff Real Obtido de api.github.com ({auditResult.github.data.title})
                    </h3>
                    <pre className="code" style={{ maxHeight: 240 }}>
                      {auditResult.github.data.diff}
                    </pre>
                  </>
                )}
              </div>
            </>
          )}
        </>
      )}

      {/* TAB 2: LIVE SECURITY & PACKAGE INTELLIGENCE SEARCH */}
      {activeTab === 'search' && (
        <div className="panel">
          <div className="panel-header">
            <h2>
              Pesquisa Live Multi-Fonte (GitHub Advisories + OSV.dev + NPM Registry + HN Algolia)
            </h2>
            <div style={{ display: 'flex', gap: 6 }}>
              {['lodash', 'express', 'jsonwebtoken', 'sql injection', 'prompt injection'].map(
                (q) => (
                  <button
                    key={q}
                    className="btn btn-secondary btn-sm"
                    onClick={() => runLiveSearch(q)}
                  >
                    {q}
                  </button>
                )
              )}
            </div>
          </div>

          <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
            <input
              className="input"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Pesquisar CVE, pacote npm, GHSA ou tópico de segurança…"
            />
            <button
              className="btn btn-primary"
              disabled={searching}
              onClick={() => runLiveSearch()}
            >
              {searching ? 'Searching Live APIs…' : 'Search Live Intelligence'}
            </button>
          </div>

          {searchLatency !== null && (
            <div style={{ marginBottom: 12, fontSize: 12, color: 'var(--text-secondary)' }}>
              Encontrados {searchItems.length} resultados reais em {searchLatency} ms.
            </div>
          )}

          {searchItems.length > 0 && (
            <table className="table">
              <thead>
                <tr>
                  <th>Fonte</th>
                  <th>Título / Advisory</th>
                  <th>Severidade / ID</th>
                  <th>Link Externo</th>
                </tr>
              </thead>
              <tbody>
                {searchItems.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <span className="badge">{item.source}</span>
                    </td>
                    <td>
                      <strong>{item.title}</strong>
                      <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
                        {item.summary}
                      </div>
                    </td>
                    <td>
                      {item.severity && (
                        <span
                          className={`badge ${
                            item.severity === 'critical' || item.severity === 'high'
                              ? 'danger'
                              : 'warn'
                          }`}
                        >
                          {item.severity}
                        </span>
                      )}{' '}
                      {item.cveId && <span className="mono">{item.cveId}</span>}
                    </td>
                    <td>
                      <a
                        className="link-accent mono"
                        href={item.url}
                        target="_blank"
                        rel="noreferrer"
                      >
                        Abrir fonte ↗
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* TAB 3: GOVERNED SSRF-PROTECTED WEB BROWSER */}
      {activeTab === 'browse' && (
        <div className="panel">
          <div className="panel-header">
            <h2>Navegador HTTPS Governado com Proteção Anti-SSRF &amp; Envelope Não-Confiável</h2>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => runSafeBrowse('https://osv.dev')}
              >
                Browse: https://osv.dev
              </button>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => runSafeBrowse('https://api.github.com/meta')}
              >
                Browse: https://api.github.com/meta
              </button>
              <button
                className="btn btn-danger btn-sm"
                onClick={() => runSafeBrowse('https://169.254.169.254/latest/meta-data/')}
              >
                Test SSRF Block (169.254.169.254)
              </button>
              <button
                className="btn btn-danger btn-sm"
                onClick={() => runSafeBrowse('http://localhost:5432')}
              >
                Test Localhost Block (http://localhost:5432)
              </button>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
            <input
              className="input"
              value={browseUrl}
              onChange={(e) => setBrowseUrl(e.target.value)}
              placeholder="https://..."
            />
            <button
              className="btn btn-primary"
              disabled={browsing}
              onClick={() => runSafeBrowse()}
            >
              {browsing ? 'Fetching…' : 'Browse URL Safely'}
            </button>
          </div>

          {browseResult && (
            <div className="panel" style={{ marginBottom: 0 }}>
              <div className="panel-header">
                <h3>
                  Status:{' '}
                  <span
                    className={`badge ${browseResult.status === 'succeeded' ? 'trust' : 'danger'}`}
                  >
                    {browseResult.status}
                  </span>
                </h3>
                {browseResult.latencyMs !== undefined && (
                  <span className="mono">{browseResult.latencyMs} ms</span>
                )}
              </div>
              {browseResult.error && (
                <div className="badge danger" style={{ marginBottom: 8 }}>
                  Bloqueado pelo Adaptador Seguro: {browseResult.error}
                </div>
              )}
              {browseResult.data?.excerpt && (
                <>
                  <div style={{ marginBottom: 8 }}>
                    <strong>Título:</strong> {browseResult.data.title} ·{' '}
                    <span className="badge warn">UNTRUSTED DATA ENVELOPE</span>
                  </div>
                  <pre className="code">{browseResult.data.excerpt}</pre>
                </>
              )}
            </div>
          )}
        </div>
      )}
    </>
  );
}

