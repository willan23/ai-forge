/**
 * Demo seed — creates org/workspace/agent metadata when DATABASE_URL is available.
 * Domain fixtures in src/fixtures work without a database for the MVP demo path.
 */

import { getDemoAgent, DEMO_ORG, DEMO_WORKSPACE } from '../src/fixtures/demo-agents';
import { buildLockfile } from '../src/lib/domain/release/lockfile';
import { computeDigest } from '../src/lib/domain/manifest/digest';
import type { Prisma } from '@prisma/client';

function toJson(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}

async function main() {
  const agent = getDemoAgent();
  const { lockfile, releaseDigest, manifestDigest, policyDigest } = buildLockfile({
    manifest: agent.manifest,
    policySource: agent.policySource,
  });

  console.log('AI Forge demo seed (in-memory preview)');
  console.log('Organization:', DEMO_ORG.slug);
  console.log('Workspace:', DEMO_WORKSPACE.name, DEMO_WORKSPACE.environment);
  console.log('Agent:', agent.slug);
  console.log('Manifest digest:', manifestDigest);
  console.log('Policy digest:', policyDigest);
  console.log('Release digest:', releaseDigest);
  console.log('Lockfile capabilities:', lockfile.capabilities.map((c) => c.name).join(', '));
  console.log('Contract digests:', agent.contracts.digests);
  console.log('Commit digest check:', computeDigest(agent.manifest) === manifestDigest);

  if (!process.env.DATABASE_URL) {
    console.log('\nDATABASE_URL not set — skipping Prisma persistence.');
    console.log('Fixtures are available via src/fixtures and /api/demo/run-security-audit.');
    return;
  }

  const { PrismaClient } = await import('@prisma/client');
  const prisma = new PrismaClient();

  try {
    const org = await prisma.organization.upsert({
      where: { slug: DEMO_ORG.slug },
      update: {},
      create: {
        id: DEMO_ORG.id,
        name: DEMO_ORG.name,
        slug: DEMO_ORG.slug,
        plan: DEMO_ORG.plan,
      },
    });

    const workspace = await prisma.workspace.upsert({
      where: {
        organizationId_name_environment: {
          organizationId: org.id,
          name: DEMO_WORKSPACE.name,
          environment: DEMO_WORKSPACE.environment,
        },
      },
      update: {},
      create: {
        id: DEMO_WORKSPACE.id,
        organizationId: org.id,
        name: DEMO_WORKSPACE.name,
        environment: DEMO_WORKSPACE.environment,
      },
    });

    for (const [name, contract, digest] of [
      ['github-pr-reader', agent.contracts.github, agent.contracts.digests.githubPrReader],
      ['dependency-vulnerability-db', agent.contracts.vuln, agent.contracts.digests.vulnLookup],
      ['github-draft-comment', agent.contracts.draft, agent.contracts.digests.draftComment],
    ] as const) {
      await prisma.capabilityContract.upsert({
        where: {
          workspaceId_slug_version: {
            workspaceId: workspace.id,
            slug: name,
            version: '0.1.0',
          },
        },
        update: {
          contractJson: toJson(contract),
          digest,
          status: 'active',
        },
        create: {
          workspaceId: workspace.id,
          slug: name,
          version: '0.1.0',
          contractJson: toJson(contract),
          digest,
          trustTier: contract.metadata.trustTier,
          status: 'active',
        },
      });
    }

    const dbAgent = await prisma.agent.upsert({
      where: {
        workspaceId_slug: { workspaceId: workspace.id, slug: agent.slug },
      },
      update: { name: agent.name, killSwitch: false, status: 'active' },
      create: {
        id: agent.id,
        workspaceId: workspace.id,
        slug: agent.slug,
        name: agent.name,
        ownerId: agent.ownerId,
        status: 'active',
        killSwitch: false,
      },
    });

    let branch = await prisma.agentBranch.findUnique({
      where: { agentId_name: { agentId: dbAgent.id, name: 'main' } },
    });
    if (!branch) {
      branch = await prisma.agentBranch.create({
        data: { agentId: dbAgent.id, name: 'main', protected: true },
      });
    }

    const commit = await prisma.agentCommit.create({
      data: {
        branchId: branch.id,
        manifestJson: toJson(agent.manifest),
        message: 'Initial Security PR Auditor manifest',
        authorId: agent.ownerId,
        digest: manifestDigest,
      },
    });

    await prisma.agentBranch.update({
      where: { id: branch.id },
      data: { headCommitId: commit.id },
    });

    await prisma.policyBundle.upsert({
      where: {
        workspaceId_version: { workspaceId: workspace.id, version: '0.1.0' },
      },
      update: { source: toJson(agent.policySource), digest: policyDigest },
      create: {
        workspaceId: workspace.id,
        version: '0.1.0',
        source: toJson(agent.policySource),
        digest: policyDigest,
        status: 'active',
      },
    });

    await prisma.agentRelease.upsert({
      where: { releaseDigest },
      update: {},
      create: {
        agentId: dbAgent.id,
        commitId: commit.id,
        version: agent.manifest.metadata.version,
        releaseDigest,
        status: 'published',
        lockfileJson: toJson(lockfile),
        policyDigest,
        signedAt: new Date(),
      },
    });

    console.log('\nPersisted demo org, workspace, contracts, agent, commit, and release.');
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
