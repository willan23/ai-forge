import { describe, it, expect } from 'vitest';
import { canTransition, transition, isTerminalState } from '../../src/lib/domain/runtime/state-machine';
import { checkBudget, createBudgetTracker } from '../../src/lib/domain/runtime/budget';
import { buildLockfile } from '../../src/lib/domain/release/lockfile';
import { createRelease } from '../../src/lib/domain/release/create';
import { getDemoAgent } from '../../src/fixtures/demo-agents';
import { runEvalSuite } from '../../src/lib/domain/eval/runner';
import { DEMO_EVAL_SCENARIOS, DEMO_EVAL_GATES } from '../../src/fixtures/demo-evals';
import { orchestrateSecurityPrAudit } from '../../src/lib/domain/runtime/orchestrator';
import { DemoDraftCommentAdapter } from '../../src/lib/adapters/capability/demo-draft-comment';
import { DemoCredentialBroker } from '../../src/lib/domain/runtime/credential-broker';

describe('state machine', () => {
  it('allows queued → resolving_release → running → succeeded', () => {
    expect(canTransition('queued', 'resolving_release')).toBe(true);
    const t = transition('running', 'succeeded');
    expect(t.to).toBe('succeeded');
    expect(isTerminalState('succeeded')).toBe(true);
    expect(() => transition('succeeded', 'running')).toThrow();
  });
});

describe('budget', () => {
  it('blocks when tool calls exhausted', () => {
    const tracker = createBudgetTracker({ maxRunSeconds: 60, maxToolCalls: 1, maxCostUsd: 1 });
    tracker.recordToolCall(0.1);
    const check = tracker.check();
    expect(check.allowed).toBe(false);
    expect(check.reason).toBe('tool_call_limit_exceeded');
  });

  it('allows within limits', () => {
    const check = checkBudget(
      { maxRunSeconds: 60, maxToolCalls: 5, maxCostUsd: 1 },
      { startedAt: new Date(), toolCalls: 1, costUsd: 0.1 }
    );
    expect(check.allowed).toBe(true);
  });
});

describe('lockfile + release + evals + orchestrator', () => {
  it('runs the Security PR Auditor vertical end-to-end in memory', async () => {
    const agent = getDemoAgent();
    const { releaseDigest } = buildLockfile({
      manifest: agent.manifest,
      policySource: agent.policySource,
    });

    const evalResult = runEvalSuite({
      suite: 'security-pr-auditor-regression',
      version: '0.1.0',
      releaseDigest,
      scenarios: DEMO_EVAL_SCENARIOS,
      gates: DEMO_EVAL_GATES,
    });

    expect(evalResult.results).toHaveLength(7);
    expect(evalResult.results.every((r) => r.passed)).toBe(true);
    expect(evalResult.scorecard.gateResult).toBe('pass');

    const release = createRelease({
      manifest: agent.manifest,
      policySource: agent.policySource,
      version: '0.1.0',
      availableCapabilities: [
        { name: 'github-pr-reader', digest: agent.contracts.digests.githubPrReader, status: 'active' },
        {
          name: 'dependency-vulnerability-db',
          digest: agent.contracts.digests.vulnLookup,
          status: 'active',
        },
        {
          name: 'github-draft-comment',
          digest: agent.contracts.digests.draftComment,
          status: 'active',
        },
      ],
      scorecard: evalResult.scorecard,
    });

    expect(release.ok).toBe(true);
    if (!release.ok) return;

    const run = await orchestrateSecurityPrAudit({
      runId: 'run_test_1',
      organizationId: 'org_demo_wgf',
      workspaceId: agent.workspaceId,
      agentId: agent.id,
      releaseDigest: release.releaseDigest,
      releaseVersion: '0.1.0',
      releaseStatus: release.status,
      lockfile: release.lockfile,
      manifest: agent.manifest,
      policySource: agent.policySource,
      killSwitch: false,
      environment: 'development',
      resource: 'org-approved/payments-api',
      fixture: 'sqli',
    });

    expect(run.status).toBe('succeeded');
    expect(run.policyDecisions.some((d) => d.action === 'pull-request:read')).toBe(true);
    expect(run.policyDecisions.some((d) => d.reasonCode === 'write_requires_approval')).toBe(true);
    expect(run.evidenceBundle.integrity.bundleDigest).toMatch(/^sha256:/);
    expect(run.approvalRequest).toBeDefined();
  });

  it('blocks release when injection resistance fails', () => {
    const agent = getDemoAgent();
    const release = createRelease({
      manifest: agent.manifest,
      policySource: agent.policySource,
      version: '0.1.0',
      availableCapabilities: [
        { name: 'github-pr-reader', digest: agent.contracts.digests.githubPrReader, status: 'active' },
        {
          name: 'dependency-vulnerability-db',
          digest: agent.contracts.digests.vulnLookup,
          status: 'active',
        },
        {
          name: 'github-draft-comment',
          digest: agent.contracts.digests.draftComment,
          status: 'active',
        },
      ],
      scorecard: {
        releaseDigest: 'sha256:' + 'a'.repeat(64),
        suite: 'x@0.1.0',
        metrics: {
          task_success_rate: 1,
          tool_contract_correctness: 1,
          critical_policy_violations: 0,
          injection_resistance: 0,
          false_positive_rate: 0,
          average_cost_usd: 0.1,
          p95_latency_ms: 100,
        },
        gateResult: 'fail',
        failures: ['injection'],
      },
    });
    expect(release.ok).toBe(false);
  });
});

describe('draft comment adapter', () => {
  it('refuses without approvalId', async () => {
    const broker = new DemoCredentialBroker();
    const cred = broker.issue({
      runId: 'r1',
      releaseDigest: 'sha256:' + 'b'.repeat(64),
      capability: 'github-draft-comment',
      action: 'pull-request:draft-comment',
      resource: 'org-approved/x',
      purpose: 'test',
    });
    const adapter = new DemoDraftCommentAdapter();
    const result = await adapter.invoke({
      credential: cred,
      action: 'pull-request:draft-comment',
      resource: 'org-approved/x',
      payload: { body: 'hi' },
      traceId: 't1',
    });
    expect(result.status).toBe('failed');
    expect(result.error).toBe('approval_required');
  });
});
