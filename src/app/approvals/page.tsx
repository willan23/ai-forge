'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface DraftExecutionReceipt {
  draftId: string;
  adapter: string;
  executedAt: string;
  resource: string;
  body: string;
  latencyMs: number;
}

interface Approval {
  id: string;
  resourceType: string;
  resourceId: string;
  requestedBy: string;
  approverId?: string | null;
  decision: string | null;
  reason: string | null;
  impactSummary?: string;
  permissions?: string[];
  draftExecutionReceipt?: DraftExecutionReceipt | null;
  expiresAt?: string | null;
  createdAt: string;
}

export default function ApprovalsPage() {
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [reason, setReason] = useState('Approved after human review of draft comment impact.');
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  async function load() {
    const res = await fetch('/api/approvals');
    const data = await res.json();
    if (!res.ok) setError(data.error ?? 'Failed');
    else setApprovals(data.approvals ?? []);
  }

  useEffect(() => {
    fetch('/api/approvals')
      .then((res) => res.json().then((data) => ({ ok: res.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) setError(data.error ?? 'Failed');
        else setApprovals(data.approvals ?? []);
      })
      .catch((e) => setError(String(e)));
  }, []);

  async function decide(id: string, decision: 'approved' | 'denied') {
    setBusyId(id);
    setError(null);
    setMessage(null);
    try {
      const res = await fetch(`/api/approvals/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision, reason }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? 'Failed');
      const draftNote = data.approval?.draftExecutionReceipt
        ? ` · Draft Comment executado (${data.approval.draftExecutionReceipt.draftId})`
        : '';
      setMessage(`Approval ${id} → ${decision}${draftNote}`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed');
    } finally {
      setBusyId(null);
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
            <span className="badge trust">REM-04: Four-Eyes Separation of Duties</span>
            <span className="badge info">REM-03: HMAC-SHA256 Signed Delegated Credentials</span>
          </div>
          <h1>Approvals</h1>
          <p>
            Human-in-the-Loop (HITL) Gate: escritas externas nunca ocorrem sem aprovação explícita.
            Após aprovação justificada, o runtime emite credencial efémera assinada por HMAC-SHA256
            e executa o adaptador de rascunho com trilha de auditoria encadeada por SHA-256.
          </p>
        </div>
        <span className="badge warn">
          Pending: {approvals.filter((a) => !a.decision).length}
        </span>
      </div>

      <div className="panel">
        <label style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
          Mandatory Justification for Approve / Deny Decision
        </label>
        <input
          className="input"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          style={{ marginTop: 8 }}
        />
      </div>

      {error && (
        <div className="panel">
          <span className="badge danger">{error}</span>
        </div>
      )}
      {message && (
        <div className="panel">
          <span className="badge trust">{message}</span>
        </div>
      )}

      <div className="panel">
        {approvals.length === 0 ? (
          <p style={{ color: 'var(--text-secondary)', margin: 0 }}>
            Sem pedidos pendentes. Execute &quot;Run Security Audit&quot; no{' '}
            <Link className="link-accent" href="/">
              Overview
            </Link>{' '}
            para gerar um pedido de aprovação de comentário em pull request.
          </p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Approval ID</th>
                <th>Resource &amp; Blast-Radius Impact</th>
                <th>Permissions &amp; Expiry</th>
                <th>Decision</th>
                <th>Actions / Post-Approval Receipt</th>
              </tr>
            </thead>
            <tbody>
              {approvals.map((a) => (
                <tr key={a.id}>
                  <td className="mono">{a.id}</td>
                  <td>
                    <div>
                      <span className="badge">{a.resourceType}</span>{' '}
                      <Link
                        className="link-accent mono"
                        href={`/agents/agent_security_pr_auditor/runs/${a.resourceId}`}
                      >
                        {a.resourceId}
                      </Link>
                    </div>
                    {a.impactSummary && (
                      <div style={{ color: 'var(--text-secondary)', fontSize: 12, marginTop: 4 }}>
                        {a.impactSummary}
                      </div>
                    )}
                  </td>
                  <td>
                    <div className="mono">
                      {(a.permissions ?? ['pull-request:draft-comment']).join(', ')}
                    </div>
                    {a.expiresAt && (
                      <div className="mono" style={{ fontSize: 11 }}>
                        exp: {a.expiresAt.slice(0, 19)}Z
                      </div>
                    )}
                  </td>
                  <td>
                    <span
                      className={`badge ${
                        a.decision === 'approved'
                          ? 'trust'
                          : a.decision === 'denied'
                            ? 'danger'
                            : 'warn'
                      }`}
                    >
                      {a.decision ?? 'pending'}
                    </span>
                  </td>
                  <td>
                    {!a.decision && (
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button
                          className="btn btn-primary btn-sm"
                          disabled={busyId === a.id}
                          onClick={() => decide(a.id, 'approved')}
                        >
                          Approve
                        </button>
                        <button
                          className="btn btn-secondary btn-sm"
                          disabled={busyId === a.id}
                          onClick={() => decide(a.id, 'denied')}
                        >
                          Deny
                        </button>
                      </div>
                    )}
                    {a.reason && (
                      <div className="mono" style={{ marginTop: 4 }}>
                        Reason: {a.reason}
                      </div>
                    )}
                    {a.draftExecutionReceipt && (
                      <div
                        style={{
                          marginTop: 6,
                          padding: 8,
                          background: 'var(--trust-bg)',
                          border: '1px solid var(--trust-border)',
                          borderRadius: 4,
                          fontSize: 11.5,
                        }}
                      >
                        <strong style={{ color: '#2dd4bf' }}>
                          ✓ Executed via Delegated Credential:
                        </strong>{' '}
                        <span className="mono">{a.draftExecutionReceipt.draftId}</span> (
                        {a.draftExecutionReceipt.latencyMs}ms)
                      </div>
                    )}
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
