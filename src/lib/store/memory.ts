import * as fs from 'node:fs';
import * as path from 'node:path';
import { computeDigest } from '../domain/manifest/digest';
import { getDemoAgent, DEMO_ORG, DEMO_WORKSPACE } from '../../fixtures/demo-agents';
import { DEMO_EVAL_SCENARIOS, DEMO_EVAL_GATES } from '../../fixtures/demo-evals';
import { runEvalSuite } from '../domain/eval/runner';
import { buildLockfile } from '../domain/release/lockfile';
import type {
  ForgeStore,
  StoredAgent,
  StoredApproval,
  StoredAuditLog,
  StoredBranch,
  StoredCapability,
  StoredChangeProposal,
  StoredCommit,
  StoredEvidenceArtifact,
  StoredOrganization,
  StoredPolicyBundle,
  StoredPolicyDecision,
  StoredRelease,
  StoredRun,
  StoredRunEvent,
  StoredToolInvocation,
  StoredWorkspace,
} from './types';

function id(prefix: string) {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}_${Date.now().toString(36)}`;
}

type MemoryDb = {
  orgs: Map<string, StoredOrganization>;
  workspaces: Map<string, StoredWorkspace>;
  agents: Map<string, StoredAgent>;
  branches: Map<string, StoredBranch>;
  commits: Map<string, StoredCommit>;
  proposals: Map<string, StoredChangeProposal>;
  capabilities: Map<string, StoredCapability>;
  policies: Map<string, StoredPolicyBundle>;
  releases: Map<string, StoredRelease>;
  runs: Map<string, StoredRun>;
  events: StoredRunEvent[];
  decisions: StoredPolicyDecision[];
  tools: StoredToolInvocation[];
  artifacts: StoredEvidenceArtifact[];
  approvals: Map<string, StoredApproval>;
  audits: StoredAuditLog[];
  seeded: boolean;
};

const globalStore = globalThis as unknown as { __aiForgeMemory?: MemoryDb };

function db(): MemoryDb {
  if (!globalStore.__aiForgeMemory) {
    globalStore.__aiForgeMemory = {
      orgs: new Map(),
      workspaces: new Map(),
      agents: new Map(),
      branches: new Map(),
      commits: new Map(),
      proposals: new Map(),
      capabilities: new Map(),
      policies: new Map(),
      releases: new Map(),
      runs: new Map(),
      events: [],
      decisions: [],
      tools: [],
      artifacts: [],
      approvals: new Map(),
      audits: [],
      seeded: false,
    };
  }
  return globalStore.__aiForgeMemory;
}

/** Reset memory DB — for tests only. */
export function resetMemoryStore() {
  globalStore.__aiForgeMemory = undefined;
}

function isFilePersistenceEnabled(): boolean {
  if (process.env.AI_FORGE_STORE === 'memory') return false;
  if (process.env.VITEST) return false;
  return true;
}

function getStoreFilePath(): string {
  const baseDir = process.env.AI_FORGE_DATA_DIR ?? path.join(process.cwd(), '.data');
  return path.join(baseDir, 'ai-forge-store.json');
}

function persistToDisk(): void {
  if (!isFilePersistenceEnabled()) return;
  try {
    const d = db();
    const file = getStoreFilePath();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const serialized = {
      orgs: [...d.orgs.entries()],
      workspaces: [...d.workspaces.entries()],
      agents: [...d.agents.entries()],
      branches: [...d.branches.entries()],
      commits: [...d.commits.entries()],
      proposals: [...d.proposals.entries()],
      capabilities: [...d.capabilities.entries()],
      policies: [...d.policies.entries()],
      releases: [...d.releases.entries()],
      runs: [...d.runs.entries()],
      events: d.events,
      decisions: d.decisions,
      tools: d.tools,
      artifacts: d.artifacts,
      approvals: [...d.approvals.entries()],
      audits: d.audits,
      seeded: d.seeded,
    };
    const tmpFile = `${file}.tmp`;
    fs.writeFileSync(tmpFile, JSON.stringify(serialized, null, 2), 'utf8');
    fs.renameSync(tmpFile, file);
  } catch {
    // Ignore disk write errors in read-only environments
  }
}

function hydrateFromDisk(): boolean {
  if (!isFilePersistenceEnabled()) return false;
  try {
    const file = getStoreFilePath();
    if (!fs.existsSync(file)) return false;
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!raw || !raw.seeded) return false;
    const d = db();
    d.orgs = new Map(raw.orgs ?? []);
    d.workspaces = new Map(raw.workspaces ?? []);
    d.agents = new Map(raw.agents ?? []);
    d.branches = new Map(raw.branches ?? []);
    d.commits = new Map(raw.commits ?? []);
    d.proposals = new Map(raw.proposals ?? []);
    d.capabilities = new Map(raw.capabilities ?? []);
    d.policies = new Map(raw.policies ?? []);
    d.releases = new Map(raw.releases ?? []);
    d.runs = new Map(raw.runs ?? []);
    d.events = raw.events ?? [];
    d.decisions = raw.decisions ?? [];
    d.tools = raw.tools ?? [];
    d.artifacts = raw.artifacts ?? [];
    d.approvals = new Map(raw.approvals ?? []);
    d.audits = raw.audits ?? [];
    d.seeded = true;
    return true;
  } catch {
    return false;
  }
}

export class MemoryStore implements ForgeStore {
  readonly mode = 'memory' as const;

  async ensureSeed(): Promise<void> {
    const d = db();
    if (d.seeded) return;
    if (hydrateFromDisk()) return;

    const demo = getDemoAgent();
    const { lockfile, releaseDigest, manifestDigest, policyDigest } = buildLockfile({
      manifest: demo.manifest,
      policySource: demo.policySource,
      createdAt: '2026-01-01T00:00:00.000Z',
    });

    const evalResult = runEvalSuite({
      suite: 'security-pr-auditor-regression',
      version: '0.1.0',
      releaseDigest,
      scenarios: DEMO_EVAL_SCENARIOS,
      gates: DEMO_EVAL_GATES,
      manifest: demo.manifest,
    });

    d.orgs.set(DEMO_ORG.id, { ...DEMO_ORG });
    d.workspaces.set(DEMO_WORKSPACE.id, { ...DEMO_WORKSPACE });
    d.workspaces.set('ws_demo_staging', {
      id: 'ws_demo_staging',
      organizationId: DEMO_ORG.id,
      name: 'Platform Security (Staging)',
      environment: 'staging',
    });
    d.workspaces.set('ws_demo_prod', {
      id: 'ws_demo_prod',
      organizationId: DEMO_ORG.id,
      name: 'Platform Security (Production)',
      environment: 'production',
    });

    for (const wsId of [DEMO_WORKSPACE.id, 'ws_demo_staging', 'ws_demo_prod']) {
      for (const [slug, contract, digest] of [
        ['github-pr-reader', demo.contracts.github, demo.contracts.digests.githubPrReader],
        ['dependency-vulnerability-db', demo.contracts.vuln, demo.contracts.digests.vulnLookup],
        ['github-draft-comment', demo.contracts.draft, demo.contracts.digests.draftComment],
      ] as const) {
        const capId = wsId === DEMO_WORKSPACE.id ? `cap_${slug}` : `cap_${slug}_${wsId}`;
        d.capabilities.set(capId, {
          id: capId,
          workspaceId: wsId,
          slug,
          version: '0.1.0',
          contractJson: contract,
          digest,
          trustTier: contract.metadata.trustTier,
          status: 'active',
        });
      }

      const polId = wsId === DEMO_WORKSPACE.id ? 'pol_demo' : `pol_${wsId}`;
      d.policies.set(polId, {
        id: polId,
        workspaceId: wsId,
        version: '0.1.0',
        source: demo.policySource,
        digest: policyDigest,
        status: 'active',
      });
    }

    const now = new Date().toISOString();
    d.agents.set(demo.id, {
      id: demo.id,
      workspaceId: demo.workspaceId,
      slug: demo.slug,
      name: demo.name,
      ownerId: demo.ownerId,
      status: 'active',
      killSwitch: false,
      createdAt: now,
      updatedAt: now,
    });

    const branchId = 'branch_main_demo';
    const commitId = 'commit_demo_initial';
    d.branches.set(branchId, {
      id: branchId,
      agentId: demo.id,
      name: 'main',
      headCommitId: commitId,
      protected: true,
    });
    d.commits.set(commitId, {
      id: commitId,
      branchId,
      parentCommitId: null,
      manifestJson: demo.manifest,
      message: 'Initial Security PR Auditor manifest',
      authorId: demo.ownerId,
      digest: manifestDigest,
      createdAt: now,
    });

    d.releases.set('rel_demo_initial', {
      id: 'rel_demo_initial',
      agentId: demo.id,
      commitId,
      version: demo.manifest.metadata.version,
      releaseDigest,
      status: 'published',
      lockfileJson: lockfile,
      policyDigest,
      evaluationReportId: 'eval_demo_initial',
      scorecardJson: evalResult.scorecard,
      signedAt: now,
      createdAt: now,
    });

    d.audits.push({
      id: 'audit_seed_1',
      organizationId: DEMO_ORG.id,
      actorType: 'system',
      actorId: 'ai-forge-bootstrap',
      action: 'release.published',
      targetType: 'release',
      targetId: 'rel_demo_initial',
      metadataJson: { releaseDigest, version: '0.1.0', gateResult: 'pass' },
      timestamp: now,
    });

    d.seeded = true;
    persistToDisk();
  }

  async listWorkspaces(organizationId?: string) {
    await this.ensureSeed();
    const all = [...db().workspaces.values()];
    return organizationId ? all.filter((w) => w.organizationId === organizationId) : all;
  }

  async listAgents(workspaceId?: string) {
    await this.ensureSeed();
    const all = [...db().agents.values()];
    return workspaceId ? all.filter((a) => a.workspaceId === workspaceId) : all;
  }

  async getAgent(agentId: string) {
    await this.ensureSeed();
    return db().agents.get(agentId) ?? null;
  }

  async createAgent(input: {
    workspaceId: string;
    slug: string;
    name: string;
    ownerId: string;
  }) {
    await this.ensureSeed();
    const now = new Date().toISOString();
    const agent: StoredAgent = {
      id: id('agent'),
      workspaceId: input.workspaceId,
      slug: input.slug,
      name: input.name,
      ownerId: input.ownerId,
      status: 'active',
      killSwitch: false,
      createdAt: now,
      updatedAt: now,
    };
    db().agents.set(agent.id, agent);
    await this.ensureBranch(agent.id, 'main');
    persistToDisk();
    return agent;
  }

  async updateAgent(
    agentId: string,
    patch: Partial<Pick<StoredAgent, 'name' | 'status' | 'killSwitch'>>
  ) {
    const agent = await this.getAgent(agentId);
    if (!agent) throw new Error(`Agent not found: ${agentId}`);
    const updated = { ...agent, ...patch, updatedAt: new Date().toISOString() };
    db().agents.set(agentId, updated);
    persistToDisk();
    return updated;
  }

  async getBranch(agentId: string, name: string) {
    await this.ensureSeed();
    return (
      [...db().branches.values()].find((b) => b.agentId === agentId && b.name === name) ?? null
    );
  }

  async ensureBranch(agentId: string, name: string) {
    const existing = await this.getBranch(agentId, name);
    if (existing) return existing;
    const branch: StoredBranch = {
      id: id('branch'),
      agentId,
      name,
      headCommitId: null,
      protected: name === 'main',
    };
    db().branches.set(branch.id, branch);
    return branch;
  }

  async listCommits(agentId: string) {
    await this.ensureSeed();
    const branchIds = new Set(
      [...db().branches.values()].filter((b) => b.agentId === agentId).map((b) => b.id)
    );
    return [...db().commits.values()]
      .filter((c) => branchIds.has(c.branchId))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async createCommit(input: {
    agentId: string;
    branchName?: string;
    manifest: import('../domain/manifest/schema').AgentManifest;
    message: string;
    authorId: string;
    parentCommitId?: string | null;
  }) {
    const branch = await this.ensureBranch(input.agentId, input.branchName ?? 'main');
    const digest = computeDigest(input.manifest);
    const commit: StoredCommit = {
      id: id('commit'),
      branchId: branch.id,
      parentCommitId: input.parentCommitId ?? branch.headCommitId,
      manifestJson: input.manifest,
      message: input.message,
      authorId: input.authorId,
      digest,
      createdAt: new Date().toISOString(),
    };
    db().commits.set(commit.id, commit);
    db().branches.set(branch.id, { ...branch, headCommitId: commit.id });
    persistToDisk();
    return commit;
  }

  async getCommit(commitId: string) {
    await this.ensureSeed();
    return db().commits.get(commitId) ?? null;
  }

  async listChangeProposals(agentId: string) {
    await this.ensureSeed();
    return [...db().proposals.values()]
      .filter((p) => p.agentId === agentId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async createChangeProposal(input: {
    agentId: string;
    sourceCommitId: string;
    targetBranchId: string;
    diffJson: unknown;
    riskSummary?: string | null;
  }) {
    await this.ensureSeed();
    const now = new Date().toISOString();
    const proposal: StoredChangeProposal = {
      id: id('cp'),
      agentId: input.agentId,
      sourceCommitId: input.sourceCommitId,
      targetBranchId: input.targetBranchId,
      diffJson: input.diffJson,
      riskSummary: input.riskSummary ?? null,
      status: 'open',
      createdAt: now,
      updatedAt: now,
    };
    db().proposals.set(proposal.id, proposal);
    persistToDisk();
    return proposal;
  }

  async updateChangeProposal(
    proposalId: string,
    patch: Partial<Pick<StoredChangeProposal, 'status' | 'riskSummary'>>
  ) {
    await this.ensureSeed();
    const existing = db().proposals.get(proposalId);
    if (!existing) throw new Error(`ChangeProposal not found: ${proposalId}`);
    const updated: StoredChangeProposal = {
      ...existing,
      ...patch,
      updatedAt: new Date().toISOString(),
    };
    db().proposals.set(proposalId, updated);
    persistToDisk();
    return updated;
  }

  async listCapabilities(workspaceId: string) {
    await this.ensureSeed();
    return [...db().capabilities.values()].filter((c) => c.workspaceId === workspaceId);
  }

  async getPolicyBundle(workspaceId: string) {
    await this.ensureSeed();
    return [...db().policies.values()].find((p) => p.workspaceId === workspaceId) ?? null;
  }

  async listReleases(agentId: string) {
    await this.ensureSeed();
    return [...db().releases.values()]
      .filter((r) => r.agentId === agentId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async getRelease(releaseId: string) {
    await this.ensureSeed();
    return db().releases.get(releaseId) ?? null;
  }

  async getReleaseByDigest(digest: string) {
    await this.ensureSeed();
    return [...db().releases.values()].find((r) => r.releaseDigest === digest) ?? null;
  }

  async createRelease(input: Omit<StoredRelease, 'id' | 'createdAt'> & { id?: string }) {
    const release: StoredRelease = {
      ...input,
      id: input.id ?? id('rel'),
      createdAt: new Date().toISOString(),
    };
    db().releases.set(release.id, release);
    persistToDisk();
    return release;
  }

  async listRuns(agentId: string) {
    await this.ensureSeed();
    return [...db().runs.values()]
      .filter((r) => r.agentId === agentId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async listAllRuns(workspaceId?: string) {
    await this.ensureSeed();
    const all = [...db().runs.values()];
    const filtered = workspaceId ? all.filter((r) => r.workspaceId === workspaceId) : all;
    return filtered.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async getRun(runId: string) {
    await this.ensureSeed();
    return db().runs.get(runId) ?? null;
  }

  async createRun(input: Omit<StoredRun, 'createdAt'> & { id?: string }) {
    const run: StoredRun = {
      ...input,
      id: input.id ?? id('run'),
      createdAt: new Date().toISOString(),
    };
    db().runs.set(run.id, run);
    persistToDisk();
    return run;
  }

  async updateRun(runId: string, patch: Partial<StoredRun>) {
    const run = await this.getRun(runId);
    if (!run) throw new Error(`Run not found: ${runId}`);
    const updated = { ...run, ...patch };
    db().runs.set(runId, updated);
    persistToDisk();
    return updated;
  }

  async addRunEvent(event: Omit<StoredRunEvent, 'id'>) {
    const row: StoredRunEvent = { ...event, id: id('evt') };
    db().events.push(row);
    persistToDisk();
    return row;
  }

  async listRunEvents(runId: string) {
    return db()
      .events.filter((e) => e.runId === runId)
      .sort((a, b) => a.sequence - b.sequence);
  }

  async addPolicyDecision(d: Omit<StoredPolicyDecision, 'id'>) {
    const row: StoredPolicyDecision = { ...d, id: id('pd') };
    db().decisions.push(row);
    persistToDisk();
    return row;
  }

  async listPolicyDecisions(runId: string) {
    return db().decisions.filter((d) => d.runId === runId);
  }

  async addToolInvocation(t: Omit<StoredToolInvocation, 'id'>) {
    const row: StoredToolInvocation = { ...t, id: id('ti') };
    db().tools.push(row);
    persistToDisk();
    return row;
  }

  async listToolInvocation(runId: string) {
    return db().tools.filter((t) => t.runId === runId);
  }

  async listToolInvocations(runId: string) {
    return db().tools.filter((t) => t.runId === runId);
  }

  async addEvidenceArtifact(a: Omit<StoredEvidenceArtifact, 'id'>) {
    const row: StoredEvidenceArtifact = { ...a, id: id('ea') };
    db().artifacts.push(row);
    persistToDisk();
    return row;
  }

  async listApprovals(organizationId: string) {
    await this.ensureSeed();
    return [...db().approvals.values()]
      .filter((a) => a.organizationId === organizationId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async getApproval(approvalId: string) {
    await this.ensureSeed();
    return db().approvals.get(approvalId) ?? null;
  }

  async createApproval(input: Omit<StoredApproval, 'updatedAt'> & { id?: string }) {
    const now = new Date().toISOString();
    const row: StoredApproval = {
      ...input,
      id: input.id ?? id('apr'),
      updatedAt: now,
      createdAt: input.createdAt ?? now,
    };
    db().approvals.set(row.id, row);
    persistToDisk();
    return row;
  }

  async updateApproval(approvalId: string, patch: Partial<StoredApproval>) {
    const existing = await this.getApproval(approvalId);
    if (!existing) throw new Error(`Approval not found: ${approvalId}`);
    const updated = { ...existing, ...patch, updatedAt: new Date().toISOString() };
    db().approvals.set(approvalId, updated);
    persistToDisk();
    return updated;
  }

  async getWorkspace(workspaceId: string) {
    await this.ensureSeed();
    return db().workspaces.get(workspaceId) ?? null;
  }

  async getOrganization(organizationId: string) {
    await this.ensureSeed();
    return db().orgs.get(organizationId) ?? null;
  }

  async provisionOrganization(input: {
    id: string;
    name: string;
    slug: string;
    plan?: string;
    ownerId: string;
  }) {
    await this.ensureSeed();
    const d = db();
    const org: StoredOrganization = {
      id: input.id,
      name: input.name,
      slug: input.slug,
      plan: input.plan ?? 'starter',
    };
    d.orgs.set(org.id, org);

    const demo = getDemoAgent();
    const { lockfile, releaseDigest, manifestDigest, policyDigest } = buildLockfile({
      manifest: demo.manifest,
      policySource: demo.policySource,
      createdAt: new Date().toISOString(),
    });

    const devWs: StoredWorkspace = {
      id: `ws_${input.slug}_dev`,
      organizationId: org.id,
      name: `${input.name} (Development)`,
      environment: 'development',
    };
    const stagingWs: StoredWorkspace = {
      id: `ws_${input.slug}_staging`,
      organizationId: org.id,
      name: `${input.name} (Staging)`,
      environment: 'staging',
    };
    const prodWs: StoredWorkspace = {
      id: `ws_${input.slug}_prod`,
      organizationId: org.id,
      name: `${input.name} (Production)`,
      environment: 'production',
    };
    for (const ws of [devWs, stagingWs, prodWs]) {
      d.workspaces.set(ws.id, ws);
      for (const [slug, contract, digest] of [
        ['github-pr-reader', demo.contracts.github, demo.contracts.digests.githubPrReader],
        ['dependency-vulnerability-db', demo.contracts.vuln, demo.contracts.digests.vulnLookup],
        ['github-draft-comment', demo.contracts.draft, demo.contracts.digests.draftComment],
      ] as const) {
        const capId = `cap_${slug}_${ws.id}`;
        d.capabilities.set(capId, {
          id: capId,
          workspaceId: ws.id,
          slug,
          version: '0.1.0',
          contractJson: contract,
          digest,
          trustTier: contract.metadata.trustTier,
          status: 'active',
        });
      }
      d.policies.set(`pol_${ws.id}`, {
        id: `pol_${ws.id}`,
        workspaceId: ws.id,
        version: '0.1.0',
        source: demo.policySource,
        digest: policyDigest,
        status: 'active',
      });
    }

    const now = new Date().toISOString();
    const agentId = `agent_security_pr_auditor_${input.slug}`;
    const agent: StoredAgent = {
      id: agentId,
      workspaceId: devWs.id,
      slug: 'security-pr-auditor',
      name: 'Security PR Auditor',
      ownerId: input.ownerId,
      status: 'active',
      killSwitch: false,
      createdAt: now,
      updatedAt: now,
    };
    d.agents.set(agent.id, agent);

    const branchId = `branch_main_${input.slug}`;
    const commitId = `commit_init_${input.slug}`;
    d.branches.set(branchId, {
      id: branchId,
      agentId: agent.id,
      name: 'main',
      headCommitId: commitId,
      protected: true,
    });
    d.commits.set(commitId, {
      id: commitId,
      branchId,
      parentCommitId: null,
      manifestJson: demo.manifest,
      message: 'Initial governed Security PR Auditor manifest',
      authorId: input.ownerId,
      digest: manifestDigest,
      createdAt: now,
    });
    const relId = `rel_init_${input.slug}`;
    d.releases.set(relId, {
      id: relId,
      agentId: agent.id,
      commitId,
      version: demo.manifest.metadata.version,
      releaseDigest: `${releaseDigest.slice(0, 56)}${input.slug.slice(0, 8).padEnd(8, '0')}`,
      status: 'published',
      lockfileJson: lockfile,
      policyDigest,
      evaluationReportId: `eval_init_${input.slug}`,
      scorecardJson: null,
      signedAt: now,
      createdAt: now,
    });

    await this.writeAudit({
      organizationId: org.id,
      actorType: 'user',
      actorId: input.ownerId,
      action: 'organization.provisioned',
      targetType: 'organization',
      targetId: org.id,
      metadataJson: { slug: org.slug, workspaceId: devWs.id, agentId: agent.id },
    });

    persistToDisk();
    return { organization: org, workspace: devWs, agent };
  }

  async writeAudit(event: {
    organizationId: string;
    actorType: string;
    actorId: string;
    action: string;
    targetType?: string;
    targetId?: string;
    metadataJson?: unknown;
  }) {
    const timestamp = new Date().toISOString();
    const prevEntry = db().audits[0];
    const previousAuditDigest =
      (prevEntry?.metadataJson as Record<string, unknown> | undefined)?.auditEntryDigest ??
      'sha256:' + '0'.repeat(64);

    const auditEntryDigest = computeDigest({
      organizationId: event.organizationId,
      actorType: event.actorType,
      actorId: event.actorId,
      action: event.action,
      targetType: event.targetType ?? null,
      targetId: event.targetId ?? null,
      previousAuditDigest,
      timestamp,
    });

    const baseMeta =
      event.metadataJson && typeof event.metadataJson === 'object'
        ? (event.metadataJson as Record<string, unknown>)
        : {};

    db().audits.unshift({
      id: id('aud'),
      organizationId: event.organizationId,
      actorType: event.actorType,
      actorId: event.actorId,
      action: event.action,
      targetType: event.targetType ?? null,
      targetId: event.targetId ?? null,
      metadataJson: {
        ...baseMeta,
        previousAuditDigest,
        auditEntryDigest,
      },
      timestamp,
    });
    persistToDisk();
  }

  async listAuditLogs(organizationId: string, limit = 50) {
    await this.ensureSeed();
    return db()
      .audits.filter((a) => a.organizationId === organizationId)
      .slice(0, limit);
  }
}
