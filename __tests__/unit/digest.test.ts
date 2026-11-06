import { describe, it, expect } from 'vitest';
import { canonicalize, computeDigest, verifyDigest } from '../../src/lib/domain/manifest/digest';

describe('canonical digest', () => {
  it('sorts object keys deterministically', () => {
    const a = canonicalize({ b: 1, a: 2 });
    const b = canonicalize({ a: 2, b: 1 });
    expect(a).toBe(b);
  });

  it('produces sha256: hex digest', () => {
    const digest = computeDigest({ hello: 'world' });
    expect(digest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(verifyDigest({ hello: 'world' }, digest)).toBe(true);
    expect(verifyDigest({ hello: 'other' }, digest)).toBe(false);
  });
});
