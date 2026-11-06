import type { Prisma } from '@prisma/client';
import { prisma } from '../db';
import { computeDigest } from '../domain/manifest/digest';
import type { AgentManifest } from '../domain/manifest/schema';
import { getDemoAgent, DEMO_ORG, DEMO_WORKSPACE } from '../../fixtures/demo-agents';
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
import type { AgentLockfile } from '../domain/release/lockfile';
import type { Scorecard } from '../domain/eval/gates';
import type { EvidenceBundle } from '../domain/evidence/schema';

function toJson(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}

function mapAgent(a: {
  id: string;
  workspaceId: string;
  slug: string;
  name: string;
  ownerId: string;
  status: string;
  killSwitch: boolean;
  createdAt: Date;
  updatedAt: Date;
}): StoredAgent {
  return {
    id: a.id,
    workspaceId: a.workspaceId,
    slug: a.slug,
    name: a.name,
    ownerId: a.ownerId,
    status: a.status,
    killSwitch: a.killSwitch,
    createdAt: a.createdAt.toISOString(),
    updatedAt: a.updatedAt.toISOString(),
  };
}

export class PrismaStore implements ForgeStore {
  readonly mode = 'prisma' as const;

  async ensureSeed(): Promise<void> {
    const existing = await prisma.organization.findUnique({ where: { slug: DEMO_ORG.slug } });
    if (existing) {
      const agent = await prisma.agent.findFirst({
        where: { workspaceId: DEMO_WORKSPACE.id, slug: 'security-pr-auditor' },
      });
      if (agent) return;
    }

    const demo = getDemoAgent();
    const { lockfile, releaseDigest, manifestDigest, policyDigest } = buildLockfile({
      manifest: demo.manifest,
      policySource: demo.policySource,
      createdAt: '2026-01-01T00:00:00.000Z',
    });

    await prisma.organization.upsert({
      where: { slug: DEMO_ORG.slug },
      update: {},
      create: {
        id: DEMO_ORG.id,
        name: DEMO_ORG.name,
        slug: DEMO_ORG.slug,
        plan: DEMO_ORG.plan,
      },
    });

    await prisma.workspace.upsert({
      where: {
        organizationId_name_environment: {
          organizationId: DEMO_ORG.id,
          name: DEMO_WORKSPACE.name,
          environment: DEMO_WORKSPACE.environment,
        },
      },
      update: {},
      create: {
        id: DEMO_WORKSPACE.id,
        organizationId: DEMO_ORG.id,
        name: DEMO_WORKSPACE.name,
        environment: DEMO_WORKSPACE.environment,
      },
    });

    for (const [slug, contract, digest] of [
      ['github-pr-reader', demo.contracts.github, demo.contracts.digests.githubPrReader],
      ['dependency-vulnerability-db', demo.contracts.vuln, demo.contracts.digests.vulnLookup],
      ['github-draft-comment', demo.contracts.draft, demo.contracts.digests.draftComment],
    ] as const) {
      await prisma.capabilityContract.upsert({
        where: {
          workspaceId_slug_version: {
            workspaceId: DEMO_WORKSPACE.id,
            slug,
            version: '0.1.0',
          },
        },
        update: { contractJson: toJson(contract), digest, status: 'active' },
        create: {
          workspaceId: DEMO_WORKSPACE.id,
          slug,
          version: '0.1.0',
          contractJson: toJson(contract),
          digest,
          trustTier: contract.metadata.trustTier,
          status: 'active',
        },
      });
    }

    await prisma.policyBundle.upsert({
      where: {
        workspaceId_version: { workspaceId: DEMO_WORKSPACE.id, version: '0.1.0' },
      },
      update: { source: toJson(demo.policySource), digest: policyDigest },
      create: {
        workspaceId: DEMO_WORKSPACE.id,
        version: '0.1.0',
        source: toJson(demo.policySource),
        digest: policyDigest,
        status: 'active',
      },
    });

    const agent = await prisma.agent.upsert({
      where: {
        workspaceId_slug: { workspaceId: DEMO_WORKSPACE.id, slug: demo.slug },
      },
      update: {},
      create: {
        id: demo.id,
        workspaceId: DEMO_WORKSPACE.id,
        slug: demo.slug,
        name: demo.name,
        ownerId: demo.ownerId,
        status: 'active',
        killSwitch: false,
      },
    });

    let branch = await prisma.agentBranch.findUnique({
      where: { agentId_name: { agentId: agent.id, name: 'main' } },
    });
    if (!branch) {
      branch = await prisma.agentBranch.create({
        data: { agentId: agent.id, name: 'main', protected: true },
      });
    }

    const existingCommit = await prisma.agentCommit.findFirst({
      where: { branchId: branch.id, digest: manifestDigest },
    });
    const commit =
      existingCommit ??
      (await prisma.agentCommit.create({
        data: {
          branchId: branch.id,
          manifestJson: toJson(demo.manifest),
          message: 'Initial Security PR Auditor manifest',
          authorId: demo.ownerId,
          digest: manifestDigest,
        },
      }));

    await prisma.agentBranch.update({
      where: { id: branch.id },
      data: { headCommitId: commit.id },
    });

    await prisma.agentRelease.upsert({
      where: { releaseDigest },
      update: {},
      create: {
        agentId: agent.id,
        commitId: commit.id,
        version: demo.manifest.metadata.version,
        releaseDigest,
        status: 'published',
        lockfileJson: toJson(lockfile),
        policyDigest,
        signedAt: new Date(),
      },
    });
  }

  async listWorkspaces(organizationId?: string) {
    await this.ensureSeed();
    const rows = await prisma.workspace.findMany({
      where: organizationId ? { organizationId } : undefined,
      orderBy: { createdAt: 'asc' },
    });
    return rows.map((w) => ({
      id: w.id,
      organizationId: w.organizationId,
      name: w.name,
      environment: w.environment,
    }));
  }

  async listAgents(workspaceId?: string) {
    await this.ensureSeed();
    const rows = await prisma.agent.findMany({
      where: workspaceId ? { workspaceId } : undefined,
      orderBy: { createdAt: 'desc' },
    });
    return rows.map(mapAgent);
  }

  async getAgent(agentId: string) {
    await this.ensureSeed();
    const row = await prisma.agent.findUnique({ where: { id: agentId } });
    return row ? mapAgent(row) : null;
  }

  async createAgent(input: {
    workspaceId: string;
    slug: string;
    name: string;
    ownerId: string;
  }) {
    const row = await prisma.agent.create({
      data: {
        workspaceId: input.workspaceId,
        slug: input.slug,
        name: input.name,
        ownerId: input.ownerId,
      },
    });
    await this.ensureBranch(row.id, 'main');
    return mapAgent(row);
  }

  async updateAgent(
    agentId: string,
    patch: Partial<Pick<StoredAgent, 'name' | 'status' | 'killSwitch'>>
  ) {
    const row = await prisma.agent.update({ where: { id: agentId }, data: patch });
    return mapAgent(row);
  }

  async getBranch(agentId: string, name: string) {
    const row = await prisma.agentBranch.findUnique({
      where: { agentId_name: { agentId, name } },
    });
    if (!row) return null;
    return {
      id: row.id,
      agentId: row.agentId,
      name: row.name,
      headCommitId: row.headCommitId,
      protected: row.protected,
    } satisfies StoredBranch;
  }

  async ensureBranch(agentId: string, name: string) {
    const existing = await this.getBranch(agentId, name);
    if (existing) return existing;
    const row = await prisma.agentBranch.create({
      data: { agentId, name, protected: name === 'main' },
    });
    return {
      id: row.id,
      agentId: row.agentId,
      name: row.name,
      headCommitId: row.headCommitId,
      protected: row.protected,
    };
  }

  async listCommits(agentId: string) {
    await this.ensureSeed();
    const branches = await prisma.agentBranch.findMany({ where: { agentId } });
    const rows = await prisma.agentCommit.findMany({
      where: { branchId: { in: branches.map((b) => b.id) } },
      orderBy: { createdAt: 'desc' },
    });
    return rows.map(
      (c): StoredCommit => ({
        id: c.id,
        branchId: c.branchId,
        parentCommitId: c.parentCommitId,
        manifestJson: c.manifestJson as unknown as AgentManifest,
        message: c.message,
        authorId: c.authorId,
        digest: c.digest,
        createdAt: c.createdAt.toISOString(),
      })
    );
  }

  async createCommit(input: {
    agentId: string;
    branchName?: string;
    manifest: AgentManifest;
    message: string;
    authorId: string;
    parentCommitId?: string | null;
  }) {
    const branch = await this.ensureBranch(input.agentId, input.branchName ?? 'main');
    const digest = computeDigest(input.manifest);
    const row = await prisma.agentCommit.create({
      data: {
        branchId: branch.id,
        parentCommitId: input.parentCommitId ?? branch.headCommitId,
        manifestJson: toJson(input.manifest),
        message: input.message,
        authorId: input.authorId,
        digest,
      },
    });
    await prisma.agentBranch.update({
      where: { id: branch.id },
      data: { headCommitId: row.id },
    });
    return {
      id: row.id,
      branchId: row.branchId,
      parentCommitId: row.parentCommitId,
      manifestJson: input.manifest,
      message: row.message,
      authorId: row.authorId,
      digest: row.digest,
      createdAt: row.createdAt.toISOString(),
    };
  }

  async getCommit(commitId: string) {
    const c = await prisma.agentCommit.findUnique({ where: { id: commitId } });
    if (!c) return null;
    return {
      id: c.id,
      branchId: c.branchId,
      parentCommitId: c.parentCommitId,
      manifestJson: c.manifestJson as unknown as AgentManifest,
      message: c.message,
      authorId: c.authorId,
      digest: c.digest,
      createdAt: c.createdAt.toISOString(),
    };
  }

  async listChangeProposals(agentId: string) {
    await this.ensureSeed();
    const rows = await prisma.changeProposal.findMany({
      where: { agentId },
      orderBy: { createdAt: 'desc' },
    });
    return rows.map(
      (p): StoredChangeProposal => ({
        id: p.id,
        agentId: p.agentId,
        sourceCommitId: p.sourceCommitId,
        targetBranchId: p.targetBranchId,
        diffJson: p.diffJson,
        riskSummary: p.riskSummary,
        status: p.status as StoredChangeProposal['status'],
        createdAt: p.createdAt.toISOString(),
        updatedAt: p.updatedAt.toISOString(),
      })
    );
  }

  async createChangeProposal(input: {
    agentId: string;
    sourceCommitId: string;
    targetBranchId: string;
    diffJson: unknown;
    riskSummary?: string | null;
  }) {
    const p = await prisma.changeProposal.create({
      data: {
        agentId: input.agentId,
        sourceCommitId: input.sourceCommitId,
        targetBranchId: input.targetBranchId,
        diffJson: toJson(input.diffJson),
        riskSummary: input.riskSummary ?? null,
        status: 'open',
      },
    });
    return {
      id: p.id,
      agentId: p.agentId,
      sourceCommitId: p.sourceCommitId,
      targetBranchId: p.targetBranchId,
      diffJson: p.diffJson,
      riskSummary: p.riskSummary,
      status: p.status as StoredChangeProposal['status'],
      createdAt: p.createdAt.toISOString(),
      updatedAt: p.updatedAt.toISOString(),
    };
  }

  async updateChangeProposal(
    proposalId: string,
    patch: Partial<Pick<StoredChangeProposal, 'status' | 'riskSummary'>>
  ) {
    const p = await prisma.changeProposal.update({
      where: { id: proposalId },
      data: {
        status: patch.status,
        riskSummary: patch.riskSummary,
      },
    });
    return {
      id: p.id,
      agentId: p.agentId,
      sourceCommitId: p.sourceCommitId,
      targetBranchId: p.targetBranchId,
      diffJson: p.diffJson,
      riskSummary: p.riskSummary,
      status: p.status as StoredChangeProposal['status'],
      createdAt: p.createdAt.toISOString(),
      updatedAt: p.updatedAt.toISOString(),
    };
  }

  async listCapabilities(workspaceId: string) {
    await this.ensureSeed();
    const rows = await prisma.capabilityContract.findMany({ where: { workspaceId } });
    return rows.map(
      (c): StoredCapability => ({
        id: c.id,
        workspaceId: c.workspaceId,
        slug: c.slug,
        version: c.version,
        contractJson: c.contractJson,
        digest: c.digest,
        trustTier: c.trustTier,
        status: c.status,
      })
    );
  }

  async getPolicyBundle(workspaceId: string) {
    await this.ensureSeed();
    const p = await prisma.policyBundle.findFirst({
      where: { workspaceId, status: 'active' },
      orderBy: { createdAt: 'desc' },
    });
    if (!p) return null;
    return {
      id: p.id,
      workspaceId: p.workspaceId,
      version: p.version,
      source: p.source,
      digest: p.digest,
      status: p.status,
    } satisfies StoredPolicyBundle;
  }

  async listReleases(agentId: string) {
    await this.ensureSeed();
    const rows = await prisma.agentRelease.findMany({
      where: { agentId },
      orderBy: { createdAt: 'desc' },
    });
    return rows.map((r) => this.mapRelease(r));
  }

  private mapRelease(r: {
    id: string;
    agentId: string;
    commitId: string;
    version: string;
    releaseDigest: string;
    status: string;
    lockfileJson: Prisma.JsonValue;
    policyDigest: string;
    evaluationReportId: string | null;
    signedAt: Date | null;
    createdAt: Date;
  }): StoredRelease {
    return {
      id: r.id,
      agentId: r.agentId,
      commitId: r.commitId,
      version: r.version,
      releaseDigest: r.releaseDigest,
      status: r.status,
      lockfileJson: r.lockfileJson as unknown as AgentLockfile,
      policyDigest: r.policyDigest,
      evaluationReportId: r.evaluationReportId,
      signedAt: r.signedAt?.toISOString() ?? null,
      createdAt: r.createdAt.toISOString(),
    };
  }

  async getRelease(releaseId: string) {
    const r = await prisma.agentRelease.findUnique({ where: { id: releaseId } });
    return r ? this.mapRelease(r) : null;
  }

  async getReleaseByDigest(digest: string) {
    const r = await prisma.agentRelease.findUnique({ where: { releaseDigest: digest } });
    return r ? this.mapRelease(r) : null;
  }

  async createRelease(input: Omit<StoredRelease, 'id' | 'createdAt'> & { id?: string }) {
    const r = await prisma.agentRelease.create({
      data: {
        id: input.id,
        agentId: input.agentId,
        commitId: input.commitId,
        version: input.version,
        releaseDigest: input.releaseDigest,
        status: input.status,
        lockfileJson: toJson(input.lockfileJson),
        policyDigest: input.policyDigest,
        evaluationReportId: input.evaluationReportId,
        signedAt: input.signedAt ? new Date(input.signedAt) : null,
      },
    });
    return this.mapRelease(r);
  }

  async listRuns(agentId: string) {
    await this.ensureSeed();
    const rows = await prisma.run.findMany({
      where: { agentId },
      orderBy: { createdAt: 'desc' },
    });
    return rows.map((r) => this.mapRun(r));
  }

  async listAllRuns(workspaceId?: string) {
    await this.ensureSeed();
    const rows = await prisma.run.findMany({
      where: workspaceId ? { workspaceId } : undefined,
      orderBy: { createdAt: 'desc' },
    });
    return Promise.all(rows.map((r) => this.getRun(r.id))).then((res) =>
      res.filter((r): r is StoredRun => r !== null)
    );
  }

  private mapRun(r: {
    id: string;
    workspaceId: string;
    agentId: string;
    agentReleaseId: string;
    status: string;
    inputHash: string | null;
    outputHash: string | null;
    budgetJson: Prisma.JsonValue;
    traceId: string;
    retryOfRunId: string | null;
    startedAt: Date;
    endedAt: Date | null;
    createdAt: Date;
  }): StoredRun {
    return {
      id: r.id,
      workspaceId: r.workspaceId,
      agentId: r.agentId,
      agentReleaseId: r.agentReleaseId,
      status: r.status,
      inputHash: r.inputHash,
      outputHash: r.outputHash,
      budgetJson: r.budgetJson,
      traceId: r.traceId,
      retryOfRunId: r.retryOfRunId,
      startedAt: r.startedAt.toISOString(),
      endedAt: r.endedAt?.toISOString() ?? null,
      createdAt: r.createdAt.toISOString(),
    };
  }

  async getRun(runId: string) {
    const r = await prisma.run.findUnique({ where: { id: runId } });
    if (!r) return null;
    const mapped = this.mapRun(r);
    // Evidence/output stored as EvidenceArtifact with type output + metadata in audits isn't ideal.
    // We keep evidence JSON in an artifact uri memory:// or as attachment with digest only.
    // For full bundle, look for artifact type "evaluation" with uri starting with json:
    const artifacts = await prisma.evidenceArtifact.findMany({ where: { runId } });
    const bundleArt = artifacts.find((a) => a.type === 'attachment' && a.uri.startsWith('bundle:'));
    if (bundleArt) {
      try {
        mapped.evidenceBundleJson = JSON.parse(
          decodeURIComponent(bundleArt.uri.replace(/^bundle:/, ''))
        ) as EvidenceBundle;
      } catch {
        /* ignore */
      }
    }
    const outputArt = artifacts.find((a) => a.type === 'output' && a.uri.startsWith('json:'));
    if (outputArt) {
      try {
        mapped.outputJson = JSON.parse(decodeURIComponent(outputArt.uri.replace(/^json:/, '')));
      } catch {
        /* ignore */
      }
    }
    // Prefer scorecard from release if needed — scorecardJson on run via output
    return mapped;
  }

  async createRun(input: Omit<StoredRun, 'createdAt'> & { id?: string }) {
    const r = await prisma.run.create({
      data: {
        id: input.id,
        workspaceId: input.workspaceId,
        agentId: input.agentId,
        agentReleaseId: input.agentReleaseId,
        status: input.status,
        inputHash: input.inputHash,
        outputHash: input.outputHash,
        budgetJson: toJson(input.budgetJson ?? {}),
        traceId: input.traceId,
        retryOfRunId: input.retryOfRunId,
        startedAt: new Date(input.startedAt),
        endedAt: input.endedAt ? new Date(input.endedAt) : null,
      },
    });
    if (input.evidenceBundleJson) {
      await this.addEvidenceArtifact({
        runId: r.id,
        type: 'attachment',
        uri: `bundle:${encodeURIComponent(JSON.stringify(input.evidenceBundleJson))}`,
        digest: input.evidenceBundleJson.integrity.bundleDigest,
        classification: 'internal',
      });
    }
    if (input.outputJson !== undefined) {
      await this.addEvidenceArtifact({
        runId: r.id,
        type: 'output',
        uri: `json:${encodeURIComponent(JSON.stringify(input.outputJson))}`,
        digest: input.outputHash ?? computeDigest(input.outputJson),
        classification: 'internal',
      });
    }
    return this.mapRun(r);
  }

  async updateRun(runId: string, patch: Partial<StoredRun>) {
    const r = await prisma.run.update({
      where: { id: runId },
      data: {
        status: patch.status,
        inputHash: patch.inputHash,
        outputHash: patch.outputHash,
        budgetJson: patch.budgetJson !== undefined ? toJson(patch.budgetJson) : undefined,
        endedAt: patch.endedAt ? new Date(patch.endedAt) : undefined,
      },
    });
    if (patch.evidenceBundleJson) {
      await this.addEvidenceArtifact({
        runId,
        type: 'attachment',
        uri: `bundle:${encodeURIComponent(JSON.stringify(patch.evidenceBundleJson))}`,
        digest: patch.evidenceBundleJson.integrity.bundleDigest,
        classification: 'internal',
      });
    }
    if (patch.outputJson !== undefined) {
      await this.addEvidenceArtifact({
        runId,
        type: 'output',
        uri: `json:${encodeURIComponent(JSON.stringify(patch.outputJson))}`,
        digest: patch.outputHash ?? computeDigest(patch.outputJson),
        classification: 'internal',
      });
    }
    return this.mapRun(r);
  }

  async addRunEvent(event: Omit<StoredRunEvent, 'id'>) {
    const row = await prisma.runEvent.create({
      data: {
        runId: event.runId,
        sequence: event.sequence,
        type: event.type,
        payloadRedactedJson: event.payloadRedactedJson
          ? toJson(event.payloadRedactedJson)
          : undefined,
        timestamp: new Date(event.timestamp),
      },
    });
    return {
      id: row.id,
      runId: row.runId,
      sequence: row.sequence,
      type: row.type,
      payloadRedactedJson: row.payloadRedactedJson,
      timestamp: row.timestamp.toISOString(),
    };
  }

  async listRunEvents(runId: string) {
    const rows = await prisma.runEvent.findMany({
      where: { runId },
      orderBy: { sequence: 'asc' },
    });
    return rows.map((row) => ({
      id: row.id,
      runId: row.runId,
      sequence: row.sequence,
      type: row.type,
      payloadRedactedJson: row.payloadRedactedJson,
      timestamp: row.timestamp.toISOString(),
    }));
  }

  async addPolicyDecision(d: Omit<StoredPolicyDecision, 'id'>) {
    const row = await prisma.policyDecision.create({
      data: {
        runId: d.runId,
        action: d.action,
        resource: d.resource,
        decision: d.decision,
        reasonCode: d.reasonCode,
        policyDigest: d.policyDigest,
        timestamp: new Date(d.timestamp),
      },
    });
    return {
      id: row.id,
      runId: row.runId,
      action: row.action,
      resource: row.resource,
      decision: row.decision,
      reasonCode: row.reasonCode,
      policyDigest: row.policyDigest,
      timestamp: row.timestamp.toISOString(),
    };
  }

  async listPolicyDecisions(runId: string) {
    const rows = await prisma.policyDecision.findMany({ where: { runId } });
    return rows.map((row) => ({
      id: row.id,
      runId: row.runId,
      action: row.action,
      resource: row.resource,
      decision: row.decision,
      reasonCode: row.reasonCode,
      policyDigest: row.policyDigest,
      timestamp: row.timestamp.toISOString(),
    }));
  }

  async addToolInvocation(t: Omit<StoredToolInvocation, 'id'>) {
    const row = await prisma.toolInvocation.create({
      data: {
        runId: t.runId,
        action: t.action,
        status: t.status,
        latencyMs: t.latencyMs,
        costUsd: t.costUsd,
        timestamp: new Date(t.timestamp),
      },
    });
    return {
      id: row.id,
      runId: row.runId,
      action: row.action,
      capability: t.capability,
      status: row.status,
      latencyMs: row.latencyMs,
      costUsd: row.costUsd,
      timestamp: row.timestamp.toISOString(),
    };
  }

  async listToolInvocations(runId: string) {
    const rows = await prisma.toolInvocation.findMany({ where: { runId } });
    return rows.map((row) => ({
      id: row.id,
      runId: row.runId,
      action: row.action,
      capability: 'unknown',
      status: row.status,
      latencyMs: row.latencyMs,
      costUsd: row.costUsd,
      timestamp: row.timestamp.toISOString(),
    }));
  }

  async addEvidenceArtifact(a: Omit<StoredEvidenceArtifact, 'id'>) {
    const row = await prisma.evidenceArtifact.create({
      data: {
        runId: a.runId,
        type: a.type,
        uri: a.uri,
        digest: a.digest,
        classification: a.classification,
      },
    });
    return {
      id: row.id,
      runId: row.runId,
      type: row.type,
      uri: row.uri,
      digest: row.digest,
      classification: row.classification,
    };
  }

  async listApprovals(organizationId: string) {
    await this.ensureSeed();
    const rows = await prisma.approvalRequest.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'desc' },
    });
    return rows.map((r) => this.mapApproval(r));
  }

  private mapApproval(r: {
    id: string;
    organizationId: string;
    resourceType: string;
    resourceId: string;
    requestedBy: string;
    approverId: string | null;
    decision: string | null;
    reason: string | null;
    expiresAt: Date | null;
    createdAt: Date;
    updatedAt: Date;
  }): StoredApproval {
    return {
      id: r.id,
      organizationId: r.organizationId,
      resourceType: r.resourceType,
      resourceId: r.resourceId,
      requestedBy: r.requestedBy,
      approverId: r.approverId,
      decision: r.decision,
      reason: r.reason,
      expiresAt: r.expiresAt?.toISOString() ?? null,
      createdAt: r.createdAt.toISOString(),
      updatedAt: r.updatedAt.toISOString(),
    };
  }

  async getApproval(approvalId: string) {
    const r = await prisma.approvalRequest.findUnique({ where: { id: approvalId } });
    return r ? this.mapApproval(r) : null;
  }

  async createApproval(input: Omit<StoredApproval, 'updatedAt'> & { id?: string }) {
    const r = await prisma.approvalRequest.create({
      data: {
        id: input.id,
        organizationId: input.organizationId,
        resourceType: input.resourceType,
        resourceId: input.resourceId,
        requestedBy: input.requestedBy,
        approverId: input.approverId,
        decision: input.decision,
        reason: input.reason ?? input.impactSummary ?? null,
        expiresAt: input.expiresAt ? new Date(input.expiresAt) : null,
      },
    });
    const mapped = this.mapApproval(r);
    mapped.impactSummary = input.impactSummary;
    mapped.permissions = input.permissions;
    return mapped;
  }

  async updateApproval(approvalId: string, patch: Partial<StoredApproval>) {
    const r = await prisma.approvalRequest.update({
      where: { id: approvalId },
      data: {
        decision: patch.decision,
        reason: patch.reason,
        approverId: patch.approverId,
      },
    });
    return this.mapApproval(r);
  }

  async getWorkspace(workspaceId: string) {
    await this.ensureSeed();
    const w = await prisma.workspace.findUnique({ where: { id: workspaceId } });
    if (!w) return null;
    return {
      id: w.id,
      organizationId: w.organizationId,
      name: w.name,
      environment: w.environment,
    } satisfies StoredWorkspace;
  }

  async getOrganization(organizationId: string) {
    await this.ensureSeed();
    const o = await prisma.organization.findUnique({ where: { id: organizationId } });
    if (!o) return null;
    return {
      id: o.id,
      name: o.name,
      slug: o.slug,
      plan: o.plan,
    } satisfies StoredOrganization;
  }

  async provisionOrganization(input: {
    id: string;
    name: string;
    slug: string;
    plan?: string;
    ownerId: string;
  }) {
    await this.ensureSeed();
    const org = await prisma.organization.upsert({
      where: { slug: input.slug },
      update: { name: input.name, plan: input.plan ?? 'starter' },
      create: {
        id: input.id,
        name: input.name,
        slug: input.slug,
        plan: input.plan ?? 'starter',
      },
    });
    const ws = await prisma.workspace.upsert({
      where: {
        organizationId_name_environment: {
          organizationId: org.id,
          name: `${input.name} (Development)`,
          environment: 'development',
        },
      },
      update: {},
      create: {
        id: `ws_${input.slug}_dev`,
        organizationId: org.id,
        name: `${input.name} (Development)`,
        environment: 'development',
      },
    });
    const agent = await prisma.agent.upsert({
      where: {
        workspaceId_slug: {
          workspaceId: ws.id,
          slug: 'security-pr-auditor',
        },
      },
      update: {},
      create: {
        id: `agent_security_pr_auditor_${input.slug}`,
        workspaceId: ws.id,
        slug: 'security-pr-auditor',
        name: 'Security PR Auditor',
        ownerId: input.ownerId,
        status: 'active',
        killSwitch: false,
      },
    });
    await this.writeAudit({
      organizationId: org.id,
      actorType: 'user',
      actorId: input.ownerId,
      action: 'organization.provisioned',
      targetType: 'organization',
      targetId: org.id,
      metadataJson: { slug: org.slug, workspaceId: ws.id, agentId: agent.id },
    });
    return {
      organization: { id: org.id, name: org.name, slug: org.slug, plan: org.plan },
      workspace: { id: ws.id, organizationId: ws.organizationId, name: ws.name, environment: ws.environment },
      agent: mapAgent(agent),
    };
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
    const prevRow = await prisma.auditLog.findFirst({
      where: { organizationId: event.organizationId },
      orderBy: { timestamp: 'desc' },
    });
    const previousAuditDigest =
      (prevRow?.metadataJson as Record<string, unknown> | undefined)?.auditEntryDigest ??
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
    await prisma.auditLog.create({
      data: {
        organizationId: event.organizationId,
        actorType: event.actorType,
        actorId: event.actorId,
        action: event.action,
        targetType: event.targetType,
        targetId: event.targetId,
        metadataJson: toJson({
          ...baseMeta,
          previousAuditDigest,
          auditEntryDigest,
        }),
      },
    });
  }

  async listAuditLogs(organizationId: string, limit = 50): Promise<StoredAuditLog[]> {
    await this.ensureSeed();
    const rows = await prisma.auditLog.findMany({
      where: { organizationId },
      orderBy: { timestamp: 'desc' },
      take: limit,
    });
    return rows.map((a) => ({
      id: a.id,
      organizationId: a.organizationId,
      actorType: a.actorType,
      actorId: a.actorId,
      action: a.action,
      targetType: a.targetType,
      targetId: a.targetId,
      metadataJson: a.metadataJson,
      timestamp: a.timestamp.toISOString(),
    }));
  }
}

// silence unused Scorecard import warning if any
export type { Scorecard };
