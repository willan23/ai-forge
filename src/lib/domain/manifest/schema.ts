import { z } from 'zod';

// ─── Shared Types ────────────────────────────────────────────────────────────

export const DataClassification = z.enum(['public', 'internal', 'confidential', 'restricted']);
export type DataClassification = z.infer<typeof DataClassification>;

export const ToolEffect = z.enum(['read', 'write', 'delete', 'execute', 'delegate']);
export type ToolEffect = z.infer<typeof ToolEffect>;

export const PolicyDecisionType = z.enum(['allow', 'deny', 'approval_required']);
export type PolicyDecisionType = z.infer<typeof PolicyDecisionType>;

// ─── Capability Reference ────────────────────────────────────────────────────

export const CapabilityRef = z.object({
  name: z.string().regex(/^[a-z][a-z0-9-]{2,62}$/),
  contractDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  actions: z.array(z.string().regex(/^[a-z][a-z0-9:.-]{1,100}$/)).min(1),
  purpose: z.string().max(500).optional(),
  requiresApproval: z.boolean().default(false),
}).strict();

// ─── Model Configuration ─────────────────────────────────────────────────────

export const ModelConfig = z.object({
  provider: z.string().min(2).max(100),
  model: z.string().min(2).max(200),
  mode: z.enum(['fixed', 'approved-router']),
  allowedModels: z.array(z.string()).optional(),
  temperature: z.number().min(0).max(2).optional(),
  maxOutputTokens: z.number().int().min(64).max(131072).optional(),
  structuredOutputSchema: z.string().max(512).optional(),
}).strict().refine(
  (data) => {
    if (data.mode === 'approved-router') {
      return data.allowedModels && data.allowedModels.length >= 1;
    }
    return true;
  },
  { message: 'approved-router mode requires at least one allowedModels entry' }
);

// ─── Autonomy ────────────────────────────────────────────────────────────────

export const Autonomy = z.object({
  level: z.number().int().min(0).max(5),
  approvalPolicy: z.enum(['always', 'risk-based', 'never']),
  maxDelegationDepth: z.number().int().min(0).max(3).default(0),
  rollbackRequired: z.boolean().default(true),
}).strict().refine(
  (data) => {
    // Levels 3–5 can NEVER use approvalPolicy: never
    if (data.level >= 3 && data.approvalPolicy === 'never') {
      return false;
    }
    return true;
  },
  { message: 'Autonomy levels 3–5 cannot use approvalPolicy "never"' }
);

// ─── Data Policy ─────────────────────────────────────────────────────────────

export const DataPolicy = z.object({
  maxClassification: DataClassification,
  retention: z.enum(['none', 'metadata-only', '30d', '90d', 'custom']),
  egress: z.enum(['deny', 'approved-domains', 'approved-providers']),
  redactionProfile: z.string().max(128).optional(),
}).strict();

// ─── Budgets ─────────────────────────────────────────────────────────────────

export const Budgets = z.object({
  maxRunSeconds: z.number().int().min(1).max(86400),
  maxToolCalls: z.number().int().min(0).max(1000),
  maxCostUsd: z.number().positive().max(10000),
  maxInputTokens: z.number().int().min(128).max(1000000).optional(),
}).strict();

// ─── Evaluation Gate ─────────────────────────────────────────────────────────

export const EvalGate = z.object({
  metric: z.string().regex(/^[a-z][a-z0-9_.-]{2,100}$/),
  operator: z.enum(['gte', 'lte', 'eq']),
  threshold: z.number(),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
}).strict();
export type EvalGate = z.infer<typeof EvalGate>;

// ─── Evaluation ──────────────────────────────────────────────────────────────

export const Evaluation = z.object({
  suiteRefs: z.array(z.string().regex(/^[a-z][a-z0-9-]{2,80}@.+$/)).min(1),
  gates: z.array(EvalGate).min(1),
}).strict();

// ─── Optional sub-specs ──────────────────────────────────────────────────────

export const Routing = z.object({
  fallbackAllowed: z.boolean().default(false),
  fallbackModels: z.array(z.string()).optional(),
}).strict();

export const Delegation = z.object({
  allowedAgents: z.array(z.string()).optional(),
  requireEvidence: z.boolean().default(true),
}).strict();

export const Knowledge = z.object({
  packRefs: z.array(z.string()).optional(),
  citationRequired: z.boolean().default(true),
  maxChunks: z.number().int().min(0).max(50).optional(),
}).strict();

// ─── Agent Manifest Metadata ─────────────────────────────────────────────────

export const AgentMetadata = z.object({
  name: z.string().regex(/^[a-z][a-z0-9-]{2,62}$/),
  version: z.string().regex(/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/),
  owner: z.string().min(3).max(128),
  description: z.string().max(500).optional(),
  labels: z.record(z.string(), z.string().max(128)),
  annotations: z.record(z.string(), z.string().max(2048)).optional(),
}).strict();

// ─── Agent Manifest Spec ─────────────────────────────────────────────────────

export const AgentSpec = z.object({
  purpose: z.string().min(10).max(1000),
  instructions: z.string().min(20).max(30000),
  model: ModelConfig,
  autonomy: Autonomy,
  capabilities: z.array(CapabilityRef).min(1),
  data: DataPolicy,
  budgets: Budgets,
  evaluation: Evaluation,
  routing: Routing.optional(),
  delegation: Delegation.optional(),
  knowledge: Knowledge.optional(),
}).strict();

// ─── Full Agent Manifest ─────────────────────────────────────────────────────

export const AgentManifest = z.object({
  apiVersion: z.literal('agentforge.dev/v1alpha1'),
  kind: z.literal('Agent'),
  metadata: AgentMetadata,
  spec: AgentSpec,
}).strict();

export type AgentManifest = z.infer<typeof AgentManifest>;

// ─── Secret Field Detection ──────────────────────────────────────────────────

/** Exact / structured secret field names — avoid false positives like maxOutputTokens. */
const SECRET_FIELD_NAMES = new Set([
  'secret',
  'secrets',
  'apikey',
  'api_key',
  'api-key',
  'token',
  'accesstoken',
  'access_token',
  'refreshtoken',
  'refresh_token',
  'password',
  'passwd',
  'credential',
  'credentials',
  'private_key',
  'privatekey',
  'clientsecret',
  'client_secret',
]);

/**
 * Deep-scan a manifest object for forbidden secret fields.
 * Returns an array of field paths that look like secrets.
 */
export function detectSecretFields(obj: unknown, path = ''): string[] {
  const violations: string[] = [];
  if (obj === null || obj === undefined) return violations;

  if (typeof obj === 'object' && !Array.isArray(obj)) {
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      const currentPath = path ? `${path}.${key}` : key;
      const normalized = key.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
      if (SECRET_FIELD_NAMES.has(normalized) || SECRET_FIELD_NAMES.has(key.toLowerCase())) {
        violations.push(currentPath);
      }
      violations.push(...detectSecretFields(value, currentPath));
    }
  } else if (Array.isArray(obj)) {
    obj.forEach((item, index) => {
      violations.push(...detectSecretFields(item, `${path}[${index}]`));
    });
  }
  return violations;
}
