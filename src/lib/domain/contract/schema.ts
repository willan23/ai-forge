import { z } from 'zod';

// ─── Capability Contract Schema ──────────────────────────────────────────────

export const ContractAction = z.object({
  name: z.string().regex(/^[a-z][a-z0-9:.-]{1,100}$/),
  description: z.string().max(1000).optional(),
  effect: z.enum(['read', 'write', 'delete', 'execute', 'delegate']),
  approval: z.enum(['never', 'risk-based', 'always']),
  idempotency: z.enum(['required', 'supported', 'none']),
  reversible: z.boolean().default(false),
}).strict();

export const ContractResource = z.object({
  type: z.string().max(100),
  patterns: z.array(z.string().max(500)).min(1),
  owner: z.string().max(200).optional(),
}).strict();

export const ContractData = z.object({
  maxInputClassification: z.enum(['public', 'internal', 'confidential', 'restricted']),
  maxOutputClassification: z.enum(['public', 'internal', 'confidential', 'restricted']),
  retention: z.enum(['none', 'metadata-only', '30d', '90d', 'custom']),
  egressDomains: z.array(z.string()).optional(),
}).strict();

export const ContractAuth = z.object({
  method: z.enum(['none', 'oidc', 'oauth2', 'mTLS', 'workload-identity', 'api-key-vault']),
  delegation: z.enum(['none', 'short-lived', 'on-behalf-of']),
  maxTtlSeconds: z.number().int().min(60).max(3600).optional(),
  scopes: z.array(z.string()).optional(),
}).strict();

export const ContractLimits = z.object({
  timeoutSeconds: z.number().int().min(1).max(3600),
  maxRequestsPerRun: z.number().int().min(1).max(10000),
  maxCostUsd: z.number().min(0).optional(),
}).strict();

export const ContractRisk = z.object({
  level: z.enum(['low', 'medium', 'high', 'critical']),
  justification: z.string().min(10).max(2000),
  requiresSandbox: z.boolean().default(true),
  requiresHumanOwner: z.boolean().default(false),
}).strict();

export const ContractObservability = z.object({
  tracePropagation: z.boolean().default(true),
  evidenceRequired: z.boolean().default(true),
  redactionProfile: z.string().max(128).optional(),
}).strict();

export const ContractSpec = z.object({
  transport: z.enum(['local', 'http', 'mcp', 'a2a', 'queue']),
  endpoint: z.string().url().optional(),
  actions: z.array(ContractAction).min(1),
  resources: z.array(ContractResource),
  data: ContractData,
  authentication: ContractAuth,
  limits: ContractLimits,
  risk: ContractRisk,
  observability: ContractObservability.optional(),
}).strict();

export const ContractMetadata = z.object({
  name: z.string().regex(/^[a-z][a-z0-9-]{2,62}$/),
  version: z.string().regex(/^[0-9]+\.[0-9]+\.[0-9]+.*$/),
  publisher: z.string().min(3),
  trustTier: z.enum(['T0-local', 'T1-community', 'T2-verified', 'T3-certified', 'T4-internal']),
  source: z.string().url().optional(),
  signature: z.string().max(4096).optional(),
}).strict();

export const CapabilityContract = z.object({
  apiVersion: z.literal('agentforge.dev/v1alpha1'),
  kind: z.enum(['Capability', 'Connector', 'RemoteAgent']),
  metadata: ContractMetadata,
  spec: ContractSpec,
}).strict();

export type CapabilityContract = z.infer<typeof CapabilityContract>;
