import { getDemoContracts } from '../../fixtures/demo-agents';

export default function CapabilitiesPage() {
  const { github, vuln, draft, digests } = getDemoContracts();
  const rows = [
    { contract: github, digest: digests.githubPrReader, status: 'active' },
    { contract: vuln, digest: digests.vulnLookup, status: 'active' },
    { contract: draft, digest: digests.draftComment, status: 'active' },
  ];

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Capabilities</h1>
          <p>
            Capability Contracts declarativos (agentforge.dev/v1alpha1): um contrato define ações,
            padrões de recursos, classificação máxima de dados, TTL de credenciais delegadas e
            limites por run. Um contrato sozinho não concede acesso sem PolicyBundle e Release.
          </p>
        </div>
        <span className="badge trust">{rows.length} Active Contracts</span>
      </div>

      <div className="panel">
        <h2>Registered Capability Contracts</h2>
        <table className="table">
          <thead>
            <tr>
              <th>Name &amp; Version</th>
              <th>Trust Tier</th>
              <th>Declared Actions &amp; Effect</th>
              <th>Resource Scope</th>
              <th>Data &amp; Auth TTL</th>
              <th>Limits</th>
              <th>Risk</th>
              <th>Status</th>
              <th>SHA-256 Digest</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ contract, digest, status }) => (
              <tr key={contract.metadata.name}>
                <td>
                  <strong>{contract.metadata.name}</strong>
                  <div className="mono">v{contract.metadata.version}</div>
                </td>
                <td>
                  <span className="badge trust">{contract.metadata.trustTier}</span>
                </td>
                <td>
                  {contract.spec.actions.map((a) => (
                    <div key={a.name} className="mono" style={{ marginBottom: 4 }}>
                      {a.name}{' '}
                      <span
                        className={`badge ${
                          a.effect === 'write'
                            ? 'warn'
                            : a.effect === 'delete'
                              ? 'danger'
                              : 'trust'
                        }`}
                      >
                        {a.effect} (approval: {a.approval})
                      </span>
                    </div>
                  ))}
                </td>
                <td className="mono">
                  {contract.spec.resources
                    .map((r) => `${r.type}: ${r.patterns.join(', ')}`)
                    .join('; ')}
                </td>
                <td className="mono">
                  <div>max: {contract.spec.data.maxInputClassification}</div>
                  <div>
                    {contract.spec.authentication.method} · TTL{' '}
                    {contract.spec.authentication.maxTtlSeconds}s
                  </div>
                </td>
                <td className="mono">
                  <div>timeout: {contract.spec.limits.timeoutSeconds}s</div>
                  <div>maxCalls: {contract.spec.limits.maxRequestsPerRun}</div>
                </td>
                <td>
                  <span
                    className={`badge ${
                      contract.spec.risk.level === 'high' || contract.spec.risk.level === 'critical'
                        ? 'danger'
                        : contract.spec.risk.level === 'medium'
                          ? 'warn'
                          : 'trust'
                    }`}
                  >
                    {contract.spec.risk.level}
                  </span>
                </td>
                <td>
                  <span className="badge trust">{status}</span>
                </td>
                <td className="mono">{digest}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="grid-3">
        {rows.map(({ contract, digest }) => (
          <div key={contract.metadata.name} className="panel" style={{ marginBottom: 0 }}>
            <div className="panel-header">
              <h2>{contract.metadata.name}</h2>
              <span className="mono" style={{ fontSize: 11 }}>
                {digest.slice(0, 18)}…
              </span>
            </div>
            <pre className="code-block" style={{ maxHeight: 300, overflow: 'auto' }}>
              {JSON.stringify(contract, null, 2)}
            </pre>
          </div>
        ))}
      </div>
    </>
  );
}
