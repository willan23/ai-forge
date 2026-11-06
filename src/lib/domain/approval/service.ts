import { z } from 'zod';

export const ApprovalDecisionSchema = z.object({
  approvalId: z.string().min(1),
  decision: z.enum(['approved', 'denied']),
  reason: z.string().min(5).max(2000),
  approverId: z.string().min(1),
});

export type ApprovalDecision = z.infer<typeof ApprovalDecisionSchema>;

export interface ApprovalRequestRecord {
  id: string;
  organizationId: string;
  resourceType: 'release' | 'run' | 'change_proposal' | 'tool_invocation';
  resourceId: string;
  requestedBy: string;
  impactSummary: string;
  permissions: string[];
  expiresAt?: string;
  decision?: 'approved' | 'denied';
  reason?: string;
  approverId?: string;
  createdAt: string;
}

/**
 * Create an in-memory approval request (demo / unit-test friendly).
 */
export function createApprovalRequest(params: {
  organizationId: string;
  resourceType: ApprovalRequestRecord['resourceType'];
  resourceId: string;
  requestedBy: string;
  impactSummary: string;
  permissions: string[];
  expiresInMinutes?: number;
}): ApprovalRequestRecord {
  const now = new Date();
  const expiresAt =
    params.expiresInMinutes !== undefined
      ? new Date(now.getTime() + params.expiresInMinutes * 60_000).toISOString()
      : undefined;

  return {
    id: `apr_${now.getTime()}`,
    organizationId: params.organizationId,
    resourceType: params.resourceType,
    resourceId: params.resourceId,
    requestedBy: params.requestedBy,
    impactSummary: params.impactSummary,
    permissions: params.permissions,
    expiresAt,
    createdAt: now.toISOString(),
  };
}

/**
 * Apply an approval decision with required justification.
 */
export function decideApproval(
  request: ApprovalRequestRecord,
  decision: ApprovalDecision,
  options?: { enforceFourEyes?: boolean }
): ApprovalRequestRecord {
  if (request.decision) {
    throw new Error(`Approval ${request.id} already decided as ${request.decision}.`);
  }
  if (request.expiresAt && new Date(request.expiresAt) < new Date()) {
    throw new Error(`Approval ${request.id} has expired.`);
  }

  const parsed = ApprovalDecisionSchema.parse(decision);

  const requireFourEyes =
    options?.enforceFourEyes === true || process.env.AI_FORGE_ENFORCE_FOUR_EYES === '1';
  if (requireFourEyes && request.requestedBy === parsed.approverId) {
    throw new Error(
      `four_eyes_violation: requester (${request.requestedBy}) cannot self-approve ${request.id}.`
    );
  }

  return {
    ...request,
    decision: parsed.decision,
    reason: parsed.reason,
    approverId: parsed.approverId,
  };
}
