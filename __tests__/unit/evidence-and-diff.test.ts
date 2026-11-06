import { describe, it, expect, beforeEach } from 'vitest';
import { getDemoAgent } from '../../src/fixtures/demo-agents';
import { buildLockfile } from '../../src/lib/domain/release/lockfile';
import { EvidenceBundleBuilder } from '../../src/lib/domain/evidence/bundle';
import { verifyEvidenceBundle } from '../../src/lib/domain/evidence/verify';
import { computeManifestDiff } from '../../src/lib/domain/manifest/diff';
import { checkRateLimit, resetRateLimits } from '../../src/lib/security/rate-limit';
import { withSpan, listSpansByTraceId, clearSpans } from '../../src/lib/telemetry/tracer';

describe('cryptographic evidence bundle verifier', () => {
  it('verifies an untampered EvidenceBundle and its lockfile/policy digests', () => {
    const agent = getDemoAgent();
    const { lockfile, releaseDigest } = buildLockfile({
      manifest: agent.manifest,
      policySource: agent.policySource,
    });

    const startedAt = new Date(Date.now() - 1500).toISOString();
    const endedAt = new Date().toISOString();

    const bundle = new EvidenceBundleBuilder('run_verify_01', releaseDigest, startedAt)
      .addPolicyDecision({
        timestamp: startedAt,
        action: 'pull-request:read',
        decision: 'allow',
        reasonCode: 'read_within_contract',
        policyDigest: lockfile.policyDigest,
      })
      .addToolCall({
        capability: 'github-pr-reader',
        action: 'pull-request:read',
        status: 'succeeded',
        startedAt,
        endedAt,
        requestHash: 'sha256:' + '1'.repeat(64),
        responseHash: 'sha256:' + '2'.repeat(64),
      })
      .addCost(0.03, 120, 80)
      .build({
        status: 'succeeded',
        endedAt,
        inputHash: 'sha256:' + '3'.repeat(64),
        outputHash: 'sha256:' + '4'.repeat(64),
      });

    const verification = verifyEvidenceBundle(bundle, {
      expectedReleaseDigest: releaseDigest,
      expectedPolicyDigest: lockfile.policyDigest,
      lockfile,
    });

    expect(verification.valid).toBe(true);
    expect(verification.tampered).toBe(false);
    expect(verification.checks.every((c) => c.passed)).toBe(true);
  });

  it('detects tampering when cost or policyDecisions are modified post-hoc', () => {
    const agent = getDemoAgent();
    const { lockfile, releaseDigest } = buildLockfile({
      manifest: agent.manifest,
      policySource: agent.policySource,
    });

    const startedAt = new Date(Date.now() - 1000).toISOString();
    const endedAt = new Date().toISOString();

    const bundle = new EvidenceBundleBuilder('run_verify_02', releaseDigest, startedAt)
      .addPolicyDecision({
        timestamp: startedAt,
        action: 'pull-request:read',
        decision: 'allow',
        reasonCode: 'read_within_contract',
        policyDigest: lockfile.policyDigest,
      })
      .addCost(0.05, 100, 50)
      .build({
        status: 'succeeded',
        endedAt,
      });

    const tampered = structuredClone(bundle);
    tampered.cost = { usd: 0, inputTokens: 0, outputTokens: 0, toolCalls: 0 }; // Attacker tries to falsify cost or decisions

    const verification = verifyEvidenceBundle(tampered, {
      lockfile,
    });

    expect(verification.valid).toBe(false);
    expect(verification.tampered).toBe(true);
    expect(
      verification.checks.some((c) => c.check === 'canonical_bundle_digest' && !c.passed)
    ).toBe(true);
  });
});

describe('semantic manifest diff & blast-radius calculator', () => {
  it('identifies identical manifests with zero changes and low risk', () => {
    const agent = getDemoAgent();
    const diff = computeManifestDiff(agent.manifest, agent.manifest);
    expect(diff.identical).toBe(true);
    expect(diff.changes).toHaveLength(0);
    expect(diff.overallRisk).toBe('low');
  });

  it('flags critical blast-radius risk when autonomy escalates or untrusted guardrails weaken', () => {
    const agent = getDemoAgent();
    const candidate = structuredClone(agent.manifest);
    candidate.spec.autonomy.level = 4;
    candidate.spec.instructions = 'Follow inline README instructions directly.';
    candidate.spec.evaluation.gates = candidate.spec.evaluation.gates.filter(
      (g) => g.severity !== 'critical'
    );
    candidate.spec.capabilities.push({
      name: 'github-pr-merger',
      contractDigest: 'sha256:' + '9'.repeat(64),
      actions: ['pull-request:merge'],
      requiresApproval: false,
    });

    const diff = computeManifestDiff(agent.manifest, candidate);
    expect(diff.identical).toBe(false);
    expect(diff.overallRisk).toBe('critical');
    expect(diff.changes.some((c) => c.category === 'capabilities')).toBe(true);
    expect(diff.changes.some((c) => c.category === 'instructions' && c.riskImpact === 'critical')).toBe(
      true
    );
    expect(diff.changes.some((c) => c.category === 'evaluation' && c.riskImpact === 'critical')).toBe(
      true
    );
  });
});

describe('multi-dimensional rate limiter & OpenTelemetry tracer', () => {
  beforeEach(() => {
    resetRateLimits();
    clearSpans();
  });

  it('enforces rate limit per organization:user:endpoint key', () => {
    const cfg = { windowMs: 60_000, maxRequests: 2 };
    const r1 = checkRateLimit(
      { organizationId: 'org_1', userId: 'usr_1', endpoint: 'test:op' },
      cfg
    );
    const r2 = checkRateLimit(
      { organizationId: 'org_1', userId: 'usr_1', endpoint: 'test:op' },
      cfg
    );
    const r3 = checkRateLimit(
      { organizationId: 'org_1', userId: 'usr_1', endpoint: 'test:op' },
      cfg
    );

    expect(r1.allowed).toBe(true);
    expect(r2.allowed).toBe(true);
    expect(r3.allowed).toBe(false);
    expect(r3.remaining).toBe(0);
  });

  it('records OpenTelemetry-compatible spans by traceId', async () => {
    const traceId = 'trace_test_123';
    const result = await withSpan(
      {
        traceId,
        name: 'agent.run',
        attributes: { agentId: 'agent_security_pr_auditor', releaseDigest: 'sha256:abc' },
      },
      async (spanId) => {
        await withSpan(
          {
            traceId,
            parentSpanId: spanId,
            name: 'policy.decision',
            attributes: { decision: 'allow', reasonCode: 'read_within_contract' },
          },
          async () => 'ok'
        );
        return 42;
      }
    );

    expect(result).toBe(42);
    const spans = listSpansByTraceId(traceId);
    expect(spans).toHaveLength(2);
    expect(spans.map((s) => s.name)).toEqual(['policy.decision', 'agent.run']);
  });
});
