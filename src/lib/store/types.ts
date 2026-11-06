/**
 * Persistence abstraction for AI Forge.
 *
 * - `prisma`: PostgreSQL via Prisma (production / docker-compose)
 * - `memory`: process-local store for demo/tests when DATABASE_URL is absent
 *
 * Both backends share the same service API so routes never branch on storage.
 */

import type { AgentManifest } from '../domain/manifest/schema';
import type { AgentLockfile } from '../domain/release/lockfile';
import type { EvidenceBundle } from '../domain/evidence/schema';
import type { Scorecard } from '../domain/eval/gates';

export type StoreMode = 'prisma' | 'memory';

export interface StoredOrganization {
  id: string;
  name: string;
  slug: string;
  plan: string;
}

export interface StoredWorkspace {
  id: string;
  organizationId: string;
  name: string;
  environment: string;
}

export interface StoredAgent {
  id: string;
  workspaceId: string;
  slug: string;
  name: string;
  ownerId: string;
  status: string;
  killSwitch: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface StoredBranch {
  id: string;
  agentId: string;
  name: string;
  headCommitId: string | null;
  protected: boolean;
}

export interface StoredCommit {
  id: string;
  branchId: string;
  parentCommitId: string | null;
  manifestJson: AgentManifest;
  message: string;
  authorId: string;
  digest: string;
  createdAt: string;
}

export interface StoredRelease {
  id: string;
  agentId: string;
  commitId: string;
  version: string;
  releaseDigest: string;
  status: string;
  lockfileJson: AgentLockfile;
  policyDigest: string;
  evaluationReportId: string | null;
  scorecardJson?: Scorecard | null;
  signedAt: string | null;
  createdAt: string;
}

export interface StoredCapability {
  id: string;
  workspaceId: string;
  slug: string;
  version: string;
  contractJson: unknown;
  digest: string;
  trustTier: string;
  status: string;
}

export interface StoredPolicyBundle {
  id: string;
  workspaceId: string;
  version: string;
  source: unknown;
  digest: string;
  status: string;
}

export interface StoredChangeProposal {
  id: string;
  agentId: string;
  sourceCommitId: string;
  targetBranchId: string;
  diffJson: unknown;
  riskSummary: string | null;
  status: 'open' | 'approved' | 'rejected' | 'merged';
  createdAt: string;
  updatedAt: string;
}

export interface DraftExecutionReceipt {
  draftId: string;
  adapter: string;
  executedAt: string;
  resource: string;
  body: string;
  latencyMs: number;
}

export interface StoredApproval {
  id: string;
  organizationId: string;
  resourceType: string;
  resourceId: string;
  requestedBy: string;
  approverId: string | null;
  decision: string | null;
  reason: string | null;
  impactSummary?: string;
  permissions?: string[];
  draftExecutionReceipt?: DraftExecutionReceipt | null;
  expiresAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface StoredRun {
  id: string;
  workspaceId: string;
  agentId: string;
  agentReleaseId: string;
  status: string;
  inputHash: string | null;
  outputHash: string | null;
  budgetJson: unknown;
  traceId: string;
  retryOfRunId: string | null;
  outputJson?: unknown;
  evidenceBundleJson?: EvidenceBundle | null;
  startedAt: string;
  endedAt: string | null;
  createdAt: string;
}

export interface StoredRunEvent {
  id: string;
  runId: string;
  sequence: number;
  type: string;
  payloadRedactedJson: unknown;
  timestamp: string;
}

export interface StoredPolicyDecision {
  id: string;
  runId: string;
  action: string;
  resource: string | null;
  decision: string;
  reasonCode: string;
  policyDigest: string;
  timestamp: string;
}

export interface StoredToolInvocation {
  id: string;
  runId: string;
  action: string;
  capability: string;
  status: string;
  latencyMs: number | null;
  costUsd: number;
  timestamp: string;
}

export interface StoredEvidenceArtifact {
  id: string;
  runId: string;
  type: string;
  uri: string;
  digest: string;
  classification: string;
}

export interface StoredAuditLog {
  id: string;
  organizationId: string;
  actorType: string;
  actorId: string;
  action: string;
  targetType?: string | null;
  targetId?: string | null;
  metadataJson?: unknown;
  timestamp: string;
}

export interface ForgeStore {
  readonly mode: StoreMode;

  ensureSeed(): Promise<void>;

  listWorkspaces(organizationId?: string): Promise<StoredWorkspace[]>;
  listAgents(workspaceId?: string): Promise<StoredAgent[]>;
  getAgent(agentId: string): Promise<StoredAgent | null>;
  createAgent(input: {
    workspaceId: string;
    slug: string;
    name: string;
    ownerId: string;
  }): Promise<StoredAgent>;
  updateAgent(
    agentId: string,
    patch: Partial<Pick<StoredAgent, 'name' | 'status' | 'killSwitch'>>
  ): Promise<StoredAgent>;

  getBranch(agentId: string, name: string): Promise<StoredBranch | null>;
  ensureBranch(agentId: string, name: string): Promise<StoredBranch>;

  listCommits(agentId: string): Promise<StoredCommit[]>;
  createCommit(input: {
    agentId: string;
    branchName?: string;
    manifest: AgentManifest;
    message: string;
    authorId: string;
    parentCommitId?: string | null;
  }): Promise<StoredCommit>;
  getCommit(commitId: string): Promise<StoredCommit | null>;

  listChangeProposals(agentId: string): Promise<StoredChangeProposal[]>;
  createChangeProposal(input: {
    agentId: string;
    sourceCommitId: string;
    targetBranchId: string;
    diffJson: unknown;
    riskSummary?: string | null;
  }): Promise<StoredChangeProposal>;
  updateChangeProposal(
    proposalId: string,
    patch: Partial<Pick<StoredChangeProposal, 'status' | 'riskSummary'>>
  ): Promise<StoredChangeProposal>;

  listCapabilities(workspaceId: string): Promise<StoredCapability[]>;
  getPolicyBundle(workspaceId: string): Promise<StoredPolicyBundle | null>;

  listReleases(agentId: string): Promise<StoredRelease[]>;
  getRelease(releaseId: string): Promise<StoredRelease | null>;
  getReleaseByDigest(digest: string): Promise<StoredRelease | null>;
  createRelease(input: Omit<StoredRelease, 'id' | 'createdAt'> & { id?: string }): Promise<StoredRelease>;

  listRuns(agentId: string): Promise<StoredRun[]>;
  listAllRuns(workspaceId?: string): Promise<StoredRun[]>;
  getRun(runId: string): Promise<StoredRun | null>;
  createRun(input: Omit<StoredRun, 'createdAt'> & { id?: string }): Promise<StoredRun>;
  updateRun(runId: string, patch: Partial<StoredRun>): Promise<StoredRun>;
  addRunEvent(event: Omit<StoredRunEvent, 'id'>): Promise<StoredRunEvent>;
  listRunEvents(runId: string): Promise<StoredRunEvent[]>;
  addPolicyDecision(d: Omit<StoredPolicyDecision, 'id'>): Promise<StoredPolicyDecision>;
  listPolicyDecisions(runId: string): Promise<StoredPolicyDecision[]>;
  addToolInvocation(t: Omit<StoredToolInvocation, 'id'>): Promise<StoredToolInvocation>;
  listToolInvocations(runId: string): Promise<StoredToolInvocation[]>;
  addEvidenceArtifact(a: Omit<StoredEvidenceArtifact, 'id'>): Promise<StoredEvidenceArtifact>;

  listApprovals(organizationId: string): Promise<StoredApproval[]>;
  getApproval(id: string): Promise<StoredApproval | null>;
  createApproval(input: Omit<StoredApproval, 'updatedAt'> & { id?: string }): Promise<StoredApproval>;
  updateApproval(id: string, patch: Partial<StoredApproval>): Promise<StoredApproval>;

  getWorkspace(workspaceId: string): Promise<StoredWorkspace | null>;
  getOrganization(organizationId: string): Promise<StoredOrganization | null>;
  provisionOrganization(input: {
    id: string;
    name: string;
    slug: string;
    plan?: string;
    ownerId: string;
  }): Promise<{ organization: StoredOrganization; workspace: StoredWorkspace; agent: StoredAgent }>;
  writeAudit(event: {
    organizationId: string;
    actorType: string;
    actorId: string;
    action: string;
    targetType?: string;
    targetId?: string;
    metadataJson?: unknown;
  }): Promise<void>;
  listAuditLogs(organizationId: string, limit?: number): Promise<StoredAuditLog[]>;
}

export function resolveStoreMode(): StoreMode {
  const forced = process.env.AI_FORGE_STORE?.toLowerCase();
  if (forced === 'memory' || forced === 'prisma') return forced;
  return process.env.DATABASE_URL ? 'prisma' : 'memory';
}
