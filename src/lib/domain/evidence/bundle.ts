import { computeDigest } from '../manifest/digest';
import { signDigestEd25519 } from '../crypto/signing';
import type { EvidenceBundle } from './schema';

interface PolicyDecisionRecord {
  timestamp: string;
  action: string;
  decision: 'allow' | 'deny' | 'approval_required';
  reasonCode: string;
  policyDigest: string;
}

interface ToolCallRecord {
  capability: string;
  action: string;
  status: 'succeeded' | 'failed' | 'blocked';
  startedAt: string;
  endedAt: string;
  requestHash?: string;
  responseHash?: string;
  traceId?: string;
}

interface ArtifactRecord {
  type: 'trace' | 'output' | 'citation' | 'approval' | 'log' | 'evaluation' | 'attachment';
  uri: string;
  digest: string;
  classification?: 'public' | 'internal' | 'confidential' | 'restricted';
}

/**
 * Evidence Bundle Builder
 *
 * Constructs an immutable evidence bundle from run execution data.
 * No sensitive content by default — uses hashes and URIs for protected artifacts.
 */
export class EvidenceBundleBuilder {
  private policyDecisions: PolicyDecisionRecord[] = [];
  private toolCalls: ToolCallRecord[] = [];
  private artifacts: ArtifactRecord[] = [];
  private totalCostUsd = 0;
  private totalInputTokens = 0;
  private totalOutputTokens = 0;
  private totalToolCallCount = 0;

  constructor(
    private readonly runId: string,
    private readonly releaseDigest: string,
    private readonly startedAt: string,
  ) {}

  addPolicyDecision(decision: PolicyDecisionRecord): this {
    this.policyDecisions.push(decision);
    return this;
  }

  addToolCall(call: ToolCallRecord): this {
    this.toolCalls.push(call);
    this.totalToolCallCount++;
    return this;
  }

  addArtifact(artifact: ArtifactRecord): this {
    this.artifacts.push(artifact);
    return this;
  }

  addCost(costUsd: number, inputTokens: number, outputTokens: number): this {
    this.totalCostUsd += costUsd;
    this.totalInputTokens += inputTokens;
    this.totalOutputTokens += outputTokens;
    return this;
  }

  build(params: {
    status: 'succeeded' | 'failed' | 'cancelled' | 'blocked' | 'timed_out';
    endedAt: string;
    inputHash?: string;
    outputHash?: string;
  }): EvidenceBundle {
    // Build the bundle without integrity first
    const bundleWithoutIntegrity = {
      runId: this.runId,
      releaseDigest: this.releaseDigest,
      status: params.status,
      startedAt: this.startedAt,
      endedAt: params.endedAt,
      inputHash: params.inputHash,
      outputHash: params.outputHash,
      policyDecisions: this.policyDecisions,
      toolCalls: this.toolCalls.length > 0 ? this.toolCalls : undefined,
      artifacts: this.artifacts,
      cost: {
        usd: Math.round(this.totalCostUsd * 1000) / 1000,
        inputTokens: this.totalInputTokens,
        outputTokens: this.totalOutputTokens,
        toolCalls: this.totalToolCallCount,
      },
    };

    // Compute bundle digest over the content and sign with Ed25519
    const bundleDigest = computeDigest(bundleWithoutIntegrity);
    const sig = signDigestEd25519(bundleDigest);

    return {
      ...bundleWithoutIntegrity,
      integrity: {
        bundleDigest,
        signature: sig.signature,
        keyId: sig.keyId,
        algorithm: sig.algorithm,
        publicKeyFingerprint: sig.publicKeyFingerprint,
        signedAt: sig.signedAt,
        createdBy: 'ai-forge-runtime',
      },
    };
  }
}
