import { describe, it, expect } from 'vitest';
import { evaluatePolicy, buildPolicyInput } from '../../src/lib/domain/policy/engine';

function input(overrides: Partial<Parameters<typeof buildPolicyInput>[0]> = {}) {
  return buildPolicyInput({
    actorType: 'agent',
    actorId: 'a1',
    organizationId: 'o1',
    runId: 'r1',
    environment: 'development',
    currentCostUsd: 0,
    currentToolCalls: 0,
    currentDelegationDepth: 0,
    agentAutonomyLevel: 2,
    agentMaxCostUsd: 2.5,
    agentMaxToolCalls: 30,
    agentMaxDelegationDepth: 0,
    agentMaxDataClassification: 'internal',
    capability: 'github-pr-reader',
    action: 'pull-request:read',
    effect: 'read',
    resource: 'org-approved/x',
    dataClassification: 'internal',
    purpose: 'test',
    capabilityDeclared: true,
    actionDeclared: true,
    resourceAllowed: true,
    egressViolation: false,
    ...overrides,
  });
}

describe('policy engine', () => {
  it('denies undeclared capability', () => {
    const r = evaluatePolicy(input({ capabilityDeclared: false }));
    expect(r.decision).toBe('deny');
    expect(r.reasonCode).toBe('capability_not_declared');
  });

  it('denies out-of-scope resource', () => {
    const r = evaluatePolicy(input({ resourceAllowed: false }));
    expect(r.decision).toBe('deny');
    expect(r.reasonCode).toBe('resource_out_of_scope');
  });

  it('denies delete', () => {
    const r = evaluatePolicy(input({ effect: 'delete' }));
    expect(r.decision).toBe('deny');
    expect(r.reasonCode).toBe('destructive_action_blocked');
  });

  it('requires approval for write', () => {
    const r = evaluatePolicy(input({ effect: 'write' }));
    expect(r.decision).toBe('approval_required');
    expect(r.reasonCode).toBe('write_requires_approval');
  });

  it('allows read within contract', () => {
    const r = evaluatePolicy(input());
    expect(r.decision).toBe('allow');
    expect(r.reasonCode).toBe('read_within_contract');
  });

  it('denies budget exceeded', () => {
    const r = evaluatePolicy(input({ currentToolCalls: 30 }));
    expect(r.decision).toBe('deny');
    expect(r.reasonCode).toBe('budget_exceeded');
  });
});
