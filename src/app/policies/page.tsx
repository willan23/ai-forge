'use client';

import { useState } from 'react';

const MANDATORY_RULES = [
  {
    order: 1,
    reasonCode: 'capability_not_declared',
    decision: 'deny',
    condition: 'Capability não consta no manifesto/lockfile da release',
    preset: {
      capabilityDeclared: false,
      actionDeclared: true,
      resourceAllowed: true,
      dataClassification: 'internal',
      effect: 'read',
      egressViolation: false,
      costUsd: 0.1,
      toolCalls: 1,
    },
  },
  {
    order: 2,
    reasonCode: 'action_not_declared',
    decision: 'deny',
    condition: 'Ação não consta do CapabilityContract',
    preset: {
      capabilityDeclared: true,
      actionDeclared: false,
      resourceAllowed: true,
      dataClassification: 'internal',
      effect: 'read',
      egressViolation: false,
      costUsd: 0.1,
      toolCalls: 1,
    },
  },
  {
    order: 3,
    reasonCode: 'resource_out_of_scope',
    decision: 'deny',
    condition: 'Recurso fora dos padrões permitidos (ex: evil-org/secrets)',
    preset: {
      capabilityDeclared: true,
      actionDeclared: true,
      resourceAllowed: false,
      resource: 'evil-org/secrets',
      dataClassification: 'internal',
      effect: 'read',
      egressViolation: false,
      costUsd: 0.1,
      toolCalls: 1,
    },
  },
  {
    order: 4,
    reasonCode: 'data_classification_exceeded',
    decision: 'deny',
    condition: 'Classificação do pedido (restricted) excede máximo do agente (internal)',
    preset: {
      capabilityDeclared: true,
      actionDeclared: true,
      resourceAllowed: true,
      dataClassification: 'restricted',
      effect: 'read',
      egressViolation: false,
      costUsd: 0.1,
      toolCalls: 1,
    },
  },
  {
    order: 5,
    reasonCode: 'budget_exceeded',
    decision: 'deny',
    condition: 'Orçamento USD, timeout ou maxToolCalls excedidos',
    preset: {
      capabilityDeclared: true,
      actionDeclared: true,
      resourceAllowed: true,
      dataClassification: 'internal',
      effect: 'read',
      egressViolation: false,
      costUsd: 2.6,
      toolCalls: 30,
    },
  },
  {
    order: 6,
    reasonCode: 'destructive_action_blocked',
    decision: 'deny',
    condition: 'Ação com efeito delete é bloqueada deterministicamente',
    preset: {
      capabilityDeclared: true,
      actionDeclared: true,
      resourceAllowed: true,
      dataClassification: 'internal',
      effect: 'delete',
      egressViolation: false,
      costUsd: 0.1,
      toolCalls: 1,
    },
  },
  {
    order: 7,
    reasonCode: 'write_requires_approval',
    decision: 'approval_required',
    condition: 'Ação com efeito write exige aprovação explícita no MVP',
    preset: {
      capabilityDeclared: true,
      actionDeclared: true,
      resourceAllowed: true,
      dataClassification: 'internal',
      effect: 'write',
      egressViolation: false,
      costUsd: 0.1,
      toolCalls: 1,
    },
  },
  {
    order: 8,
    reasonCode: 'egress_not_allowed',
    decision: 'deny',
    condition: 'Rede de saída para domínio externo não autorizado',
    preset: {
      capabilityDeclared: true,
      actionDeclared: true,
      resourceAllowed: true,
      dataClassification: 'internal',
      effect: 'read',
      egressViolation: true,
      costUsd: 0.1,
      toolCalls: 1,
    },
  },
  {
    order: 9,
    reasonCode: 'read_within_contract',
    decision: 'allow',
    condition: 'Leitura autorizada dentro do contrato, escopo e orçamento',
    preset: {
      capabilityDeclared: true,
      actionDeclared: true,
      resourceAllowed: true,
      dataClassification: 'internal',
      effect: 'read',
      egressViolation: false,
      costUsd: 0.1,
      toolCalls: 1,
    },
  },
];

interface SuiteResultItem {
  id: string;
  name: string;
  expectedDecision: string;
  expectedReason: string;
  actualDecision: string;
  actualReason: string;
  passed: boolean;
}

export default function PoliciesPage() {
  const [input, setInput] = useState(
    JSON.stringify(MANDATORY_RULES[8].preset, null, 2)
  );
  const [result, setResult] = useState<{
    decision: string;
    reasonCode: string;
    policyDigest?: string;
    evaluatedInput?: unknown;
  } | null>(null);
  const [suiteResults, setSuiteResults] = useState<SuiteResultItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function simulate(customPreset?: Record<string, unknown>) {
    setError(null);
    try {
      const simPayload = customPreset ?? JSON.parse(input);
      if (customPreset) {
        setInput(JSON.stringify(customPreset, null, 2));
      }
      const res = await fetch('/api/policies/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ simulation: simPayload }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? 'Evaluation failed');
      setResult(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Error');
    }
  }

  async function runAllRulesTest() {
    setError(null);
    try {
      const res = await fetch('/api/policies/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ runSuite: true }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? 'Suite failed');
      setSuiteResults(data.results ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Error');
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Policy Center</h1>
          <p>
            Policy Enforcement Point (PEP) determinístico e deny-by-default. Nenhuma autorização vem
            do LLM: cada tool call é avaliada contra 9 regras ordenadas com reasonCode explícito e
            policyDigest SHA-256.
          </p>
        </div>
        <button className="btn btn-primary" onClick={runAllRulesTest}>
          Run 9-Rule Verification Suite
        </button>
      </div>

      {suiteResults && (
        <div className="panel">
          <div className="panel-header">
            <h2>Policy Engine Regression Suite (9/9 Deterministic Rules)</h2>
            <span className="badge trust">
              {suiteResults.filter((r) => r.passed).length}/{suiteResults.length} PASSED
            </span>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>Rule ID</th>
                <th>Description</th>
                <th>Expected</th>
                <th>Actual</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {suiteResults.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.id}</td>
                  <td>{r.name}</td>
                  <td className="mono">
                    {r.expectedDecision}: {r.expectedReason}
                  </td>
                  <td className="mono">
                    {r.actualDecision}: {r.actualReason}
                  </td>
                  <td>
                    <span className={`badge ${r.passed ? 'trust' : 'danger'}`}>
                      {r.passed ? 'PASS' : 'FAIL'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="grid-2">
        <div className="panel" style={{ marginBottom: 0 }}>
          <h2>Default Policy Bundle (v0.1.0 — 9 Rules Ordered)</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
            Clique em &quot;Test Rule&quot; em qualquer linha para carregar e avaliar o cenário no
            simulador ao lado.
          </p>
          <table className="table">
            <thead>
              <tr>
                <th>#</th>
                <th>Reason Code</th>
                <th>Decision</th>
                <th>Test</th>
              </tr>
            </thead>
            <tbody>
              {MANDATORY_RULES.map((r) => (
                <tr key={r.reasonCode}>
                  <td className="mono">{r.order}</td>
                  <td>
                    <div className="mono" style={{ color: 'var(--text)' }}>
                      {r.reasonCode}
                    </div>
                    <div style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                      {r.condition}
                    </div>
                  </td>
                  <td>
                    <span
                      className={`badge ${
                        r.decision === 'allow'
                          ? 'trust'
                          : r.decision === 'approval_required'
                            ? 'warn'
                            : 'danger'
                      }`}
                    >
                      {r.decision}
                    </span>
                  </td>
                  <td>
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={() => simulate(r.preset)}
                    >
                      Test Rule
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <h2>Simulator</h2>
            {result && (
              <span
                className={`badge ${
                  result.decision === 'allow'
                    ? 'trust'
                    : result.decision === 'approval_required'
                      ? 'warn'
                      : 'danger'
                }`}
              >
                {result.decision} · {result.reasonCode}
              </span>
            )}
          </div>
          <textarea
            className="textarea"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            rows={14}
          />
          <div style={{ marginTop: 12, display: 'flex', gap: 8, alignItems: 'center' }}>
            <button className="btn btn-primary" onClick={() => simulate()}>
              Evaluate
            </button>
            {error && <span className="badge danger">{error}</span>}
          </div>

          {result && (
            <div style={{ marginTop: 16 }}>
              <div className="mono" style={{ marginBottom: 8 }}>
                policyDigest: {result.policyDigest}
              </div>
              {result.evaluatedInput != null && (
                <pre className="code-block" style={{ maxHeight: 240, overflow: 'auto' }}>
                  {JSON.stringify(result.evaluatedInput, null, 2)}
                </pre>
              )}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
