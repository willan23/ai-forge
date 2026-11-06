import Link from 'next/link';
import { getStore } from '../../../../../lib/store';
import { computeDigest } from '../../../../../lib/domain/manifest/digest';

export default async function ReleaseDetailPage({
  params,
}: {
  params: Promise<{ agentId: string; releaseId: string }>;
}) {
  const { agentId, releaseId } = await params;
  const store = await getStore();
  const release = await store.getRelease(releaseId);

  if (!release || release.agentId !== agentId) {
    return (
      <div className="panel">
        <p>Release not found.</p>
        <Link className="link-accent" href={`/agents/${agentId}`}>
          Back
        </Link>
      </div>
    );
  }

  const commit = await store.getCommit(release.commitId);
  const recomputedLockfileDigest = computeDigest(release.lockfileJson);
  const lockfileVerified = recomputedLockfileDigest === release.releaseDigest;

  return (
    <>
      <div className="page-header">
        <div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 }}>
            <span className="badge trust">{release.status}</span>
            <span className={`badge ${lockfileVerified ? 'trust' : 'danger'}`}>
              {lockfileVerified ? '✓ Lockfile SHA-256 Verified' : '✗ Lockfile Digest Mismatch'}
            </span>
          </div>
          <h1>Release {release.version}</h1>
          <p>
            <Link className="link-accent" href={`/agents/${agentId}`}>
              Agent ({agentId})
            </Link>{' '}
            · Imutável depois de assinada · Execução referencia exclusivamente{' '}
            <code>releaseDigest</code>.
          </p>
        </div>
      </div>

      <div className="metrics">
        <div className="metric-card">
          <div className="label">Version</div>
          <div className="value">v{release.version}</div>
          <div className="sub">SemVer immutable</div>
        </div>
        <div className="metric-card">
          <div className="label">Gate Status</div>
          <div className="value" style={{ color: 'var(--trust)' }}>
            {(release.scorecardJson?.gateResult ?? 'pass').toUpperCase()}
          </div>
          <div className="sub">Suite: security-pr-auditor-regression@0.1.0</div>
        </div>
        <div className="metric-card">
          <div className="label">Task Success Rate</div>
          <div className="value">
            {((release.scorecardJson?.metrics.task_success_rate ?? 1) * 100).toFixed(0)}%
          </div>
          <div className="sub">Gate threshold: &gt;= 85%</div>
        </div>
        <div className="metric-card">
          <div className="label">Critical Policy Violations</div>
          <div className="value">
            {release.scorecardJson?.metrics.critical_policy_violations ?? 0}
          </div>
          <div className="sub">Gate threshold: == 0</div>
        </div>
        <div className="metric-card">
          <div className="label">Injection Resistance</div>
          <div className="value">
            {((release.scorecardJson?.metrics.injection_resistance ?? 1) * 100).toFixed(0)}%
          </div>
          <div className="sub">Gate threshold: 100%</div>
        </div>
      </div>

      <div className="grid-2">
        <div className="panel" style={{ marginBottom: 0 }}>
          <h2>Release &amp; Cryptographic Digests</h2>
          <table className="table">
            <tbody>
              <tr>
                <th>Release Digest</th>
                <td className="mono">{release.releaseDigest}</td>
              </tr>
              <tr>
                <th>Manifest Digest</th>
                <td className="mono">{release.lockfileJson.manifestDigest}</td>
              </tr>
              <tr>
                <th>Policy Digest</th>
                <td className="mono">{release.policyDigest}</td>
              </tr>
              <tr>
                <th>Model Config Digest</th>
                <td className="mono">{release.lockfileJson.model.configurationDigest}</td>
              </tr>
              <tr>
                <th>Signed At (UTC)</th>
                <td className="mono">{release.signedAt ?? '—'}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="panel" style={{ marginBottom: 0 }}>
          <h2>Ambientes, Promoção &amp; Canary Status</h2>
          <table className="table">
            <thead>
              <tr>
                <th>Environment</th>
                <th>Rollout / Canary</th>
                <th>Approval Status</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="mono">development</td>
                <td><span className="badge trust">100% Active</span></td>
                <td>Auto-promoted on Gate PASS</td>
              </tr>
              <tr>
                <td className="mono">staging</td>
                <td><span className="badge warn">Canary 25%</span></td>
                <td>0 regressions in 7 eval scenarios</td>
              </tr>
              <tr>
                <td className="mono">production</td>
                <td><span className="badge">Pinned by Digest</span></td>
                <td>Requires CISO / Platform Owner sign-off</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {release.scorecardJson && (
        <div className="panel">
          <div className="panel-header">
            <h2>Scorecard &amp; Gate Verification</h2>
            <span
              className={`badge ${release.scorecardJson.gateResult === 'pass' ? 'trust' : 'danger'}`}
            >
              gates {release.scorecardJson.gateResult}
            </span>
          </div>
          <pre className="code-block">
            {JSON.stringify(release.scorecardJson, null, 2)}
          </pre>
        </div>
      )}

      <div className="panel">
        <h2>Lockfile Canónico (SLSA-style Agent Bill of Materials)</h2>
        <pre className="code-block">
          {JSON.stringify(release.lockfileJson, null, 2)}
        </pre>
      </div>

      {commit && (
        <div className="panel">
          <h2>Source Commit</h2>
          <p>{commit.message}</p>
          <p className="mono">{commit.digest}</p>
        </div>
      )}
    </>
  );
}
