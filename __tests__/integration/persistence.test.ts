import { describe, it, expect, beforeEach } from 'vitest';
import { clearStoreCache, resetMemoryStore, getStore } from '../../src/lib/store';
import { demoAuthContext } from '../../src/lib/auth/session';
import {
  createReleaseService,
  startRunService,
  exportEvidenceService,
} from '../../src/lib/services/platform';

describe('integration persistence path', () => {
  beforeEach(() => {
    process.env.AI_FORGE_STORE = 'memory';
    resetMemoryStore();
    clearStoreCache();
  });

  it('persists run events, policy decisions and evidence on the store', async () => {
    const ctx = demoAuthContext();
    const store = await getStore();
    const agent = (await store.listAgents())[0];
    const commits = await store.listCommits(agent.id);
    const release = await createReleaseService(ctx, agent.id, {
      commitId: commits[0].id,
    });
    expect(release.ok).toBe(true);
    if (!release.ok) return;

    const run = await startRunService(ctx, agent.id, {
      releaseId: release.release.id,
      fixture: 'sqli',
    });

    const events = await store.listRunEvents(run.run.id);
    const decisions = await store.listPolicyDecisions(run.run.id);
    const tools = await store.listToolInvocations(run.run.id);
    const stored = await store.getRun(run.run.id);

    expect(events.length).toBeGreaterThan(2);
    expect(decisions.some((d) => d.reasonCode === 'read_within_contract')).toBe(true);
    expect(decisions.some((d) => d.reasonCode === 'write_requires_approval')).toBe(true);
    expect(tools.length).toBeGreaterThan(0);
    expect(stored?.evidenceBundleJson?.integrity.bundleDigest).toMatch(/^sha256:/);

    const exported = await exportEvidenceService(ctx, agent.id, run.run.id);
    expect(exported?.json.length).toBeGreaterThan(50);
  });
});
