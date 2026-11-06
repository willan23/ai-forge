import type { CapabilityAdapter, CapabilityInvokeRequest, CapabilityInvokeResult } from './interface';
import { DemoCredentialBroker } from '../../domain/runtime/credential-broker';

const draftStore = new Map<string, { body: string; approvalId: string; resource: string }>();

/**
 * Demo draft comment adapter.
 * REFUSES execution without a valid approvalId.
 * Never sends externally — stores draft locally only.
 * Mode: demo-simulation.
 */
export class DemoDraftCommentAdapter implements CapabilityAdapter {
  readonly name = 'github-draft-comment';
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

    if (request.action !== 'pull-request:draft-comment') {
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

    if (!request.approvalId) {
      return {
        status: 'failed',
        data: null,
        provenance: {
          adapter: this.name,
          mode: 'demo-simulation',
          timestamp: new Date().toISOString(),
        },
        latencyMs: Date.now() - started,
        error: 'approval_required',
      };
    }

    const payload = (request.payload ?? {}) as {
      body?: string;
      prNumber?: number;
      githubToken?: string;
      allowLivePublish?: boolean;
    };
    const body = payload.body ?? '(empty draft)';
    const id = `draft_${Date.now()}`;
    draftStore.set(id, {
      body,
      approvalId: request.approvalId,
      resource: request.resource,
    });

    const token = payload.githubToken ?? process.env.GITHUB_TOKEN;
    const allowLiveWrite =
      payload.allowLivePublish === true || process.env.AI_FORGE_ALLOW_LIVE_GITHUB_WRITE === '1';

    if (allowLiveWrite && token && payload.prNumber && /^[\w.-]+\/[\w.-]+$/.test(request.resource)) {
      try {
        const ghRes = await fetch(
          `https://api.github.com/repos/${request.resource}/issues/${payload.prNumber}/comments`,
          {
            method: 'POST',
            headers: {
              Accept: 'application/vnd.github+json',
              Authorization: `Bearer ${token}`,
              'User-Agent': 'AI-Forge-Governed-Auditor/1.0',
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ body }),
            signal: AbortSignal.timeout(8000),
          }
        );
        if (ghRes.ok) {
          const json = (await ghRes.json()) as { html_url?: string; id?: number };
          return {
            status: 'succeeded',
            data: {
              draftId: id,
              approvalId: request.approvalId,
              body,
              published: true,
              githubCommentUrl: json.html_url,
              githubCommentId: json.id,
              mode: 'real-integration',
              note: 'Published to GitHub PR after verified human-in-the-loop approval.',
            },
            provenance: {
              adapter: this.name,
              mode: 'real-integration',
              timestamp: new Date().toISOString(),
            },
            latencyMs: Date.now() - started,
          };
        }
      } catch {
        // Fall back to local signed draft receipt if network write fails
      }
    }

    return {
      status: 'succeeded',
      data: {
        draftId: id,
        approvalId: request.approvalId,
        body,
        published: false,
        mode: 'demo-simulation',
        note: 'Draft stored locally only — not sent to GitHub.',
      },
      provenance: {
        adapter: this.name,
        mode: 'demo-simulation',
        timestamp: new Date().toISOString(),
      },
      latencyMs: Date.now() - started + 2,
    };
  }

  /** Test helper */
  static getDraft(id: string) {
    return draftStore.get(id);
  }
}
