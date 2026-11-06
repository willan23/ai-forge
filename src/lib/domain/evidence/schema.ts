import { z } from 'zod';

// ─── Evidence Bundle Schema ──────────────────────────────────────────────────

export const EvidencePolicyDecision = z.object({
  timestamp: z.string().datetime(),
  action: z.string(),
  decision: z.enum(['allow', 'deny', 'approval_required']),
  reasonCode: z.string(),
  policyDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
});

export const EvidenceToolCall = z.object({
  capability: z.string(),
  action: z.string(),
  status: z.enum(['succeeded', 'failed', 'blocked']),
  startedAt: z.string().datetime(),
  endedAt: z.string().datetime(),
  requestHash: z.string().optional(),
  responseHash: z.string().optional(),
  traceId: z.string().optional(),
});

export const EvidenceArtifactEntry = z.object({
  type: z.enum(['trace', 'output', 'citation', 'approval', 'log', 'evaluation', 'attachment']),
  uri: z.string(),
  digest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  classification: z.enum(['public', 'internal', 'confidential', 'restricted']).optional(),
});

export const EvidenceCost = z.object({
  usd: z.number().min(0),
  inputTokens: z.number().int().min(0),
  outputTokens: z.number().int().min(0),
  toolCalls: z.number().int().min(0),
});

export const EvidenceIntegrity = z.object({
  bundleDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  signature: z.string().optional(),
  keyId: z.string().optional(),
  algorithm: z.string().optional(),
  publicKeyFingerprint: z.string().optional(),
  signedAt: z.string().optional(),
  createdBy: z.string(),
});

export const EvidenceBundle = z.object({
  runId: z.string(),
  releaseDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  status: z.enum(['succeeded', 'failed', 'cancelled', 'blocked', 'timed_out']),
  startedAt: z.string().datetime(),
  endedAt: z.string().datetime(),
  inputHash: z.string().regex(/^sha256:[a-f0-9]{64}$/).optional(),
  outputHash: z.string().regex(/^sha256:[a-f0-9]{64}$/).optional(),
  policyDecisions: z.array(EvidencePolicyDecision),
  toolCalls: z.array(EvidenceToolCall).optional(),
  artifacts: z.array(EvidenceArtifactEntry),
  cost: EvidenceCost.optional(),
  integrity: EvidenceIntegrity,
});

export type EvidenceBundle = z.infer<typeof EvidenceBundle>;
