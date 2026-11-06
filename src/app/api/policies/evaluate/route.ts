import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../../lib/auth/session';
import { assertPermission } from '../../../../lib/auth/rbac';
import { checkRateLimit } from '../../../../lib/security/rate-limit';
import { assertCsrfOrigin, sanitizeApiError } from '../../../../lib/security/http-guards';
import { evaluatePolicy, buildPolicyInput } from '../../../../lib/domain/policy/engine';
import { PolicyInput as PolicyInputSchema } from '../../../../lib/domain/policy/schema';

export async function POST(request: Request) {
  try {
    assertCsrfOrigin(request);
    const ctx = await getAuthContext();
    assertPermission(ctx, 'agent:read');

    const rl = checkRateLimit(
      {
        userId: ctx.userId,
        organizationId: ctx.organizationId,
        endpoint: 'POST:/api/policies/evaluate',
      },
      { windowMs: 60_000, maxRequests: 60 }
    );
    if (!rl.allowed) {
      return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
    }

    const body = await request.json();

    if (body.runSuite) {
      const base = {
        actorType: 'agent' as const,
        actorId: 'agent_security_pr_auditor',
        organizationId: ctx.organizationId,
        runId: 'suite-run',
        environment: 'production' as const,
        currentCostUsd: 0.1,
        currentToolCalls: 2,
        currentDelegationDepth: 0,
        agentAutonomyLevel: 2,
        agentMaxCostUsd: 2.5,
        agentMaxToolCalls: 30,
        agentMaxDelegationDepth: 0,
        agentMaxDataClassification: 'internal' as const,
        capability: 'github-pr-reader',
        action: 'pull-request:read',
        effect: 'read' as const,
        resource: 'org-approved/payments-api',
        dataClassification: 'internal' as const,
        purpose: 'Policy regression test',
        capabilityDeclared: true,
        actionDeclared: true,
        resourceAllowed: true,
        egressViolation: false,
      };

      const cases = [
        {
          id: 'RULE-01',
          name: 'Undeclared capability blocked',
          expectedDecision: 'deny',
          expectedReason: 'capability_not_declared',
          params: { ...base, capabilityDeclared: false },
        },
        {
          id: 'RULE-02',
          name: 'Undeclared action blocked',
          expectedDecision: 'deny',
          expectedReason: 'action_not_declared',
          params: { ...base, actionDeclared: false },
        },
        {
          id: 'RULE-03',
          name: 'Out-of-scope resource blocked',
          expectedDecision: 'deny',
          expectedReason: 'resource_out_of_scope',
          params: { ...base, resourceAllowed: false, resource: 'evil-org/secrets' },
        },
        {
          id: 'RULE-04',
          name: 'Data classification exceeded blocked',
          expectedDecision: 'deny',
          expectedReason: 'data_classification_exceeded',
          params: { ...base, dataClassification: 'restricted' as const },
        },
        {
          id: 'RULE-05',
          name: 'Budget / tool call limit exceeded blocked',
          expectedDecision: 'deny',
          expectedReason: 'budget_exceeded',
          params: { ...base, currentToolCalls: 30 },
        },
        {
          id: 'RULE-06',
          name: 'Destructive delete action blocked',
          expectedDecision: 'deny',
          expectedReason: 'destructive_action_blocked',
          params: { ...base, effect: 'delete' as const, action: 'repository:delete' },
        },
        {
          id: 'RULE-07',
          name: 'Write action requires human approval',
          expectedDecision: 'approval_required',
          expectedReason: 'write_requires_approval',
          params: {
            ...base,
            effect: 'write' as const,
            capability: 'github-draft-comment',
            action: 'pull-request:draft-comment',
          },
        },
        {
          id: 'RULE-08',
          name: 'Unauthorized network egress blocked',
          expectedDecision: 'deny',
          expectedReason: 'egress_not_allowed',
          params: { ...base, egressViolation: true },
        },
        {
          id: 'RULE-09',
          name: 'Read within contract allowed',
          expectedDecision: 'allow',
          expectedReason: 'read_within_contract',
          params: { ...base },
        },
      ];

      const results = cases.map((c) => {
        const res = evaluatePolicy(buildPolicyInput(c.params));
        return {
          id: c.id,
          name: c.name,
          expectedDecision: c.expectedDecision,
          expectedReason: c.expectedReason,
          actualDecision: res.decision,
          actualReason: res.reasonCode,
          policyDigest: res.policyDigest,
          passed:
            res.decision === c.expectedDecision && res.reasonCode === c.expectedReason,
        };
      });

      return NextResponse.json({
        passed: results.every((r) => r.passed),
        total: results.length,
        passedCount: results.filter((r) => r.passed).length,
        results,
      });
    }

    if (body.policyInput) {
      const validated = PolicyInputSchema.parse(body.policyInput);
      const result = evaluatePolicy(validated);
      return NextResponse.json({
        ...result,
        evaluatedInput: validated,
      });
    }

    const sim = body.simulation ?? {};
    const builtInput = buildPolicyInput({
      actorType: 'agent',
      actorId: sim.actorId ?? 'agent_security_pr_auditor',
      organizationId: ctx.organizationId,
      runId: 'sim-run',
      environment: sim.environment ?? 'production',
      currentCostUsd: Number(sim.costUsd ?? 0.2),
      currentToolCalls: Number(sim.toolCalls ?? 4),
      currentDelegationDepth: Number(sim.delegationDepth ?? 0),
      agentAutonomyLevel: Number(sim.autonomyLevel ?? 2),
      agentMaxCostUsd: Number(sim.maxCostUsd ?? 2.5),
      agentMaxToolCalls: Number(sim.maxToolCalls ?? 30),
      agentMaxDelegationDepth: Number(sim.maxDelegationDepth ?? 0),
      agentMaxDataClassification: sim.maxDataClassification ?? 'internal',
      capability: sim.capability ?? 'github-pr-reader',
      action:
        sim.action ??
        (sim.effect === 'write'
          ? 'pull-request:draft-comment'
          : sim.effect === 'delete'
            ? 'repository:delete'
            : 'pull-request:read'),
      effect: sim.effect ?? 'read',
      resource: sim.resource ?? 'org-approved/payments-api',
      dataClassification: sim.dataClassification ?? 'internal',
      purpose: sim.purpose ?? 'Analisar pull request #123',
      capabilityDeclared: Boolean(sim.capabilityDeclared ?? true),
      actionDeclared: Boolean(sim.actionDeclared ?? true),
      resourceAllowed: Boolean(sim.resourceAllowed ?? true),
      egressViolation: Boolean(sim.egressViolation ?? false),
    });

    const result = evaluatePolicy(builtInput);
    return NextResponse.json({
      ...result,
      evaluatedInput: builtInput,
    });
  } catch (e) {
    const msg = sanitizeApiError(e, 'Invalid policy evaluation request');
    const status = msg.startsWith('Unauthorized')
      ? 401
      : msg.startsWith('Forbidden')
        ? 403
        : 400;
    return NextResponse.json({ error: msg }, { status });
  }
}
