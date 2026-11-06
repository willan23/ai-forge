import { z } from 'zod';

// ─── Policy Input Schema ─────────────────────────────────────────────────────

export const PolicyInput = z.object({
  actor: z.object({
    type: z.enum(['agent', 'user', 'system']),
    id: z.string(),
    organizationId: z.string(),
  }),
  run: z.object({
    id: z.string(),
    environment: z.enum(['development', 'staging', 'production']),
    costUsd: z.number().min(0),
    toolCalls: z.number().int().min(0),
    delegationDepth: z.number().int().min(0),
  }),
  agent: z.object({
    autonomyLevel: z.number().int().min(0).max(5),
    maxCostUsd: z.number().positive(),
    maxToolCalls: z.number().int().min(0),
    maxDelegationDepth: z.number().int().min(0).max(3),
    maxDataClassification: z.enum(['public', 'internal', 'confidential', 'restricted']),
  }),
  request: z.object({
    capability: z.string(),
    action: z.string(),
    effect: z.enum(['read', 'write', 'delete', 'execute', 'delegate']),
    resource: z.string(),
    dataClassification: z.enum(['public', 'internal', 'confidential', 'restricted']),
    purpose: z.string(),
    capabilityDeclared: z.boolean(),
    actionDeclared: z.boolean(),
    resourceAllowed: z.boolean(),
    egressViolation: z.boolean(),
  }),
});

export type PolicyInput = z.infer<typeof PolicyInput>;

// ─── Policy Result Schema ────────────────────────────────────────────────────

export const PolicyResult = z.object({
  decision: z.enum(['allow', 'deny', 'approval_required']),
  reasonCode: z.string(),
  policyDigest: z.string(),
  expiresAt: z.string().datetime().optional(),
  approvalUrl: z.string().optional(),
});

export type PolicyResult = z.infer<typeof PolicyResult>;
