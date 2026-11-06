import type { PolicyInput, PolicyResult } from './schema';
import { rules } from './rules';
import { computeDigest } from '../manifest/digest';

/**
 * Deterministic Policy Engine.
 * 
 * Evaluates a policy input against the 9 mandatory rules in order.
 * First matching rule wins. If no rule matches, defaults to deny.
 * 
 * CRITICAL: No authorization comes from the LLM. The model may suggest
 * tools or decisions. This engine determines authorization.
 */
export function evaluatePolicy(input: PolicyInput, policySource?: unknown): PolicyResult {
  // Compute policy digest for traceability
  const policyDigest = policySource
    ? computeDigest(policySource)
    : computeDigest({ version: '0.1.0', rules: rules.map((r) => r.id) });

  // Evaluate rules in order — first match wins
  for (const rule of rules) {
    const result = rule.evaluate(input);
    if (result !== null) {
      return {
        ...result,
        policyDigest,
      };
    }
  }

  // Default deny — deny-by-default principle
  return {
    decision: 'deny',
    reasonCode: 'default_deny',
    policyDigest,
  };
}

/**
 * Check if a resource matches any allowed pattern.
 * Patterns support simple glob matching with `*`.
 */
export function matchesResourcePattern(resource: string, patterns: string[]): boolean {
  return patterns.some((pattern) => {
    // Safely escape regex special characters except `*` and `?`
    const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    const regexStr = '^' + escaped.replace(/\*/g, '.*').replace(/\?/g, '.') + '$';
    return new RegExp(regexStr).test(resource);
  });
}

/**
 * Build a PolicyInput from run context and a tool call request.
 * This is the bridge between the runtime and the policy engine.
 */
export function buildPolicyInput(params: {
  actorType: 'agent' | 'user' | 'system';
  actorId: string;
  organizationId: string;
  runId: string;
  environment: 'development' | 'staging' | 'production';
  currentCostUsd: number;
  currentToolCalls: number;
  currentDelegationDepth: number;
  agentAutonomyLevel: number;
  agentMaxCostUsd: number;
  agentMaxToolCalls: number;
  agentMaxDelegationDepth: number;
  agentMaxDataClassification: 'public' | 'internal' | 'confidential' | 'restricted';
  capability: string;
  action: string;
  effect: 'read' | 'write' | 'delete' | 'execute' | 'delegate';
  resource: string;
  dataClassification: 'public' | 'internal' | 'confidential' | 'restricted';
  purpose: string;
  capabilityDeclared: boolean;
  actionDeclared: boolean;
  resourceAllowed: boolean;
  egressViolation: boolean;
}): PolicyInput {
  return {
    actor: {
      type: params.actorType,
      id: params.actorId,
      organizationId: params.organizationId,
    },
    run: {
      id: params.runId,
      environment: params.environment,
      costUsd: params.currentCostUsd,
      toolCalls: params.currentToolCalls,
      delegationDepth: params.currentDelegationDepth,
    },
    agent: {
      autonomyLevel: params.agentAutonomyLevel,
      maxCostUsd: params.agentMaxCostUsd,
      maxToolCalls: params.agentMaxToolCalls,
      maxDelegationDepth: params.agentMaxDelegationDepth,
      maxDataClassification: params.agentMaxDataClassification,
    },
    request: {
      capability: params.capability,
      action: params.action,
      effect: params.effect,
      resource: params.resource,
      dataClassification: params.dataClassification,
      purpose: params.purpose,
      capabilityDeclared: params.capabilityDeclared,
      actionDeclared: params.actionDeclared,
      resourceAllowed: params.resourceAllowed,
      egressViolation: params.egressViolation,
    },
  };
}
