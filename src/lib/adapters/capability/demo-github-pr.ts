import type { CapabilityAdapter, CapabilityInvokeRequest, CapabilityInvokeResult } from './interface';
import { DemoCredentialBroker } from '../../domain/runtime/credential-broker';

const SQLI_DIFF = `--- a/src/db/users.ts
+++ b/src/db/users.ts
@@ -10,7 +10,7 @@
-  const rows = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
+  const rows = await db.query('SELECT * FROM users WHERE id = ' + req.params.id);
   return rows;
`;

const SAFE_DIFF = `--- a/src/db/users.ts
+++ b/src/db/users.ts
@@ -10,7 +10,8 @@
-  const rows = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
+  // keep parameterized
+  const rows = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
   return rows;
`;

/**
 * Demo GitHub PR reader — returns fixture diffs.
 * Mode: demo-simulation (not a real GitHub API call).
 */
export class DemoGitHubPrReaderAdapter implements CapabilityAdapter {
  readonly name = 'github-pr-reader';
  private readonly broker = new DemoCredentialBroker();

  async invoke(request: CapabilityInvokeRequest): Promise<CapabilityInvokeResult> {
    const started = Date.now();
    const validation = this.broker.validate(request.credential, request.action, request.resource);

    if (!validation.valid) {
      return {
        status: 'failed',
        data: null,
        provenance: {
          adapter: this.name,
          mode: 'demo-simulation',
          timestamp: new Date().toISOString(),
        },
        latencyMs: Date.now() - started,
        error: validation.reason,
      };
    }

    if (!['pull-request:read', 'repository:file-read'].includes(request.action)) {
      return {
        status: 'failed',
        data: null,
        provenance: {
          adapter: this.name,
          mode: 'demo-simulation',
          timestamp: new Date().toISOString(),
        },
        latencyMs: Date.now() - started,
        error: 'action_not_supported',
      };
    }

    const payload = (request.payload ?? {}) as { fixture?: string; prNumber?: number };
    const fixture = payload.fixture ?? 'sqli';
    const diff = fixture === 'safe' ? SAFE_DIFF : SQLI_DIFF;

    return {
      status: 'succeeded',
      data: {
        repository: request.resource,
        prNumber: payload.prNumber ?? 123,
        title: fixture === 'safe' ? 'Harden query binding' : 'Quick user lookup fix',
        diff,
        files: [{ path: 'src/db/users.ts', status: 'modified' }],
        mode: 'demo-simulation',
      },
      provenance: {
        adapter: this.name,
        mode: 'demo-simulation',
        timestamp: new Date().toISOString(),
      },
      latencyMs: Date.now() - started + 5,
    };
  }
}
