import type { PolicyInput, PolicyResult } from './schema';

// ─── Data Classification Hierarchy ───────────────────────────────────────────

const CLASSIFICATION_LEVELS: Record<string, number> = {
  public: 1,
  internal: 2,
  confidential: 3,
  restricted: 4,
};

// ─── The 9 Mandatory Policy Rules ────────────────────────────────────────────
// Evaluated in order. First matching rule wins.
// Default: deny (deny-by-default principle).

type PolicyRule = {
  id: string;
  evaluate: (input: PolicyInput) => PolicyResult | null;
};

const rules: PolicyRule[] = [
  // Rule 1: Capability not declared in the release manifest
  {
    id: 'capability_not_declared',
    evaluate: (input) => {
      if (!input.request.capabilityDeclared) {
        return {
          decision: 'deny',
          reasonCode: 'capability_not_declared',
          policyDigest: '',
        };
      }
      return null;
    },
  },

  // Rule 2: Action not declared in the capability contract
  {
    id: 'action_not_declared',
    evaluate: (input) => {
      if (!input.request.actionDeclared) {
        return {
          decision: 'deny',
          reasonCode: 'action_not_declared',
          policyDigest: '',
        };
      }
      return null;
    },
  },

  // Rule 3: Resource out of permitted patterns
  {
    id: 'resource_out_of_scope',
    evaluate: (input) => {
      if (!input.request.resourceAllowed) {
        return {
          decision: 'deny',
          reasonCode: 'resource_out_of_scope',
          policyDigest: '',
        };
      }
      return null;
    },
  },

  // Rule 4: Data classification exceeds agent's maximum
  {
    id: 'data_classification_exceeded',
    evaluate: (input) => {
      const requestLevel = CLASSIFICATION_LEVELS[input.request.dataClassification] ?? 0;
      const maxLevel = CLASSIFICATION_LEVELS[input.agent.maxDataClassification] ?? 0;
      if (requestLevel > maxLevel) {
        return {
          decision: 'deny',
          reasonCode: 'data_classification_exceeded',
          policyDigest: '',
        };
      }
      return null;
    },
  },

  // Rule 5: Budget, timeout, or tool calls exceeded
  {
    id: 'budget_exceeded',
    evaluate: (input) => {
      if (input.run.costUsd >= input.agent.maxCostUsd) {
        return { decision: 'deny', reasonCode: 'budget_exceeded', policyDigest: '' };
      }
      if (input.run.toolCalls >= input.agent.maxToolCalls) {
        return { decision: 'deny', reasonCode: 'budget_exceeded', policyDigest: '' };
      }
      if (input.run.delegationDepth > input.agent.maxDelegationDepth) {
        return { decision: 'deny', reasonCode: 'budget_exceeded', policyDigest: '' };
      }
      return null;
    },
  },

  // Rule 6: Destructive actions (delete) are always blocked
  {
    id: 'destructive_action_blocked',
    evaluate: (input) => {
      if (input.request.effect === 'delete') {
        return {
          decision: 'deny',
          reasonCode: 'destructive_action_blocked',
          policyDigest: '',
        };
      }
      return null;
    },
  },

  // Rule 7: Write actions require explicit approval in the MVP
  {
    id: 'write_requires_approval',
    evaluate: (input) => {
      if (input.request.effect === 'write') {
        return {
          decision: 'approval_required',
          reasonCode: 'write_requires_approval',
          policyDigest: '',
        };
      }
      return null;
    },
  },

  // Rule 8: Egress to unauthorized domains is blocked
  {
    id: 'egress_not_allowed',
    evaluate: (input) => {
      if (input.request.egressViolation) {
        return {
          decision: 'deny',
          reasonCode: 'egress_not_allowed',
          policyDigest: '',
        };
      }
      return null;
    },
  },

  // Rule 9: Read within contract — the only allow rule
  {
    id: 'read_within_contract',
    evaluate: (input) => {
      if (input.request.effect === 'read') {
        return {
          decision: 'allow',
          reasonCode: 'read_within_contract',
          policyDigest: '',
        };
      }
      return null;
    },
  },
];

export { rules };
