import { describe, it, expect } from 'vitest';
import { validateManifest } from '../../src/lib/domain/manifest/validate';
import { getDemoAgent } from '../../src/fixtures/demo-agents';

describe('manifest validation', () => {
  it('accepts the Security PR Auditor demo manifest', () => {
    const agent = getDemoAgent();
    const result = validateManifest(agent.manifest);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it('rejects autonomy level 3+ with approvalPolicy never', () => {
    const agent = getDemoAgent();
    const bad = structuredClone(agent.manifest);
    bad.spec.autonomy.level = 3;
    bad.spec.autonomy.approvalPolicy = 'never';
    const result = validateManifest(bad);
    expect(result.valid).toBe(false);
  });

  it('rejects secret-like fields', () => {
    const agent = getDemoAgent();
    // Bypass Zod first by injecting after a shallow clone of a valid shape
    const bad = structuredClone(agent.manifest) as Record<string, unknown>;
    (bad as { spec: Record<string, unknown> }).spec.password = 'hunter2';
    const result = validateManifest(bad);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.toLowerCase().includes('secret') || e.toLowerCase().includes('password'))).toBe(
      true
    );
  });
});
