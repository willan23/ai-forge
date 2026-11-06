import { createHash } from 'crypto';

/**
 * Serialize an object to canonical JSON (sorted keys, no whitespace).
 * This ensures deterministic hashing regardless of key order.
 */
export function canonicalize(obj: unknown): string {
  return JSON.stringify(obj, (_, value) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return Object.keys(value)
        .sort()
        .reduce<Record<string, unknown>>((sorted, key) => {
          sorted[key] = value[key];
          return sorted;
        }, {});
    }
    return value;
  });
}

/**
 * Compute SHA-256 digest of an object using canonical JSON serialization.
 * Returns in the format `sha256:<64-hex-chars>`.
 */
export function computeDigest(obj: unknown): `sha256:${string}` {
  const canonical = canonicalize(obj);
  const hash = createHash('sha256').update(canonical, 'utf-8').digest('hex');
  return `sha256:${hash}`;
}

/**
 * Verify that a given digest matches the object's computed digest.
 */
export function verifyDigest(obj: unknown, expectedDigest: string): boolean {
  return computeDigest(obj) === expectedDigest;
}
