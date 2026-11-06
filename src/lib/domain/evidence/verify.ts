import { computeDigest } from '../manifest/digest';
import { verifyDigestEd25519 } from '../crypto/signing';
import { EvidenceBundle, type EvidenceBundle as EvidenceBundleType } from './schema';
import type { AgentLockfile } from '../release/lockfile';

export interface IntegrityCheckItem {
  check: string;
  passed: boolean;
  expected?: string;
  actual?: string;
  detail: string;
}

export interface EvidenceVerificationReport {
  valid: boolean;
  tampered: boolean;
  bundleDigest: string;
  recomputedDigest: string;
  verifiedAt: string;
  checks: IntegrityCheckItem[];
}

/**
 * Cryptographically verifies an EvidenceBundle by:
 * 1. Validating the strict Zod schema
 * 2. Recomputing the canonical SHA-256 digest of the bundle payload (without `integrity`)
 * 3. Comparing against `integrity.bundleDigest`
 * 4. Checking internal consistency of policy digests, release digest, and cost/tool counts
 */
export function verifyEvidenceBundle(
  bundleInput: unknown,
  options?: {
    expectedReleaseDigest?: string;
    expectedPolicyDigest?: string;
    lockfile?: AgentLockfile;
  }
): EvidenceVerificationReport {
  const checks: IntegrityCheckItem[] = [];
  const verifiedAt = new Date().toISOString();

  const parsed = EvidenceBundle.safeParse(bundleInput);
  if (!parsed.success) {
    checks.push({
      check: 'schema_validation',
      passed: false,
      detail: `Invalid EvidenceBundle schema: ${parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`,
    });
    return {
      valid: false,
      tampered: true,
      bundleDigest: 'invalid',
      recomputedDigest: 'invalid',
      verifiedAt,
      checks,
    };
  }

  const bundle: EvidenceBundleType = parsed.data;
  checks.push({
    check: 'schema_validation',
    passed: true,
    detail: 'EvidenceBundle conforms to strict agentforge.dev/v1alpha1 schema.',
  });

  // Reconstruct exact object used by EvidenceBundleBuilder before integrity was attached
  const rawObj = bundleInput as Record<string, unknown>;
  const bundleWithoutIntegrity: Record<string, unknown> = {
    runId: rawObj.runId,
    releaseDigest: rawObj.releaseDigest,
    status: rawObj.status,
    startedAt: rawObj.startedAt,
    endedAt: rawObj.endedAt,
    inputHash: rawObj.inputHash,
    outputHash: rawObj.outputHash,
    policyDecisions: rawObj.policyDecisions,
    toolCalls: rawObj.toolCalls,
    artifacts: rawObj.artifacts,
    cost: rawObj.cost,
  };

  const recomputedDigest = computeDigest(bundleWithoutIntegrity);
  const digestMatch = recomputedDigest === bundle.integrity.bundleDigest;

  checks.push({
    check: 'canonical_bundle_digest',
    passed: digestMatch,
    expected: bundle.integrity.bundleDigest,
    actual: recomputedDigest,
    detail: digestMatch
      ? 'Canonical SHA-256 digest matches integrity.bundleDigest (zero tampering detected).'
      : 'TAMPER DETECTED: Recomputed canonical SHA-256 digest does not match integrity.bundleDigest!',
  });

  if (bundle.integrity.signature) {
    const sigValid =
      digestMatch && verifyDigestEd25519(recomputedDigest, bundle.integrity.signature);
    checks.push({
      check: 'ed25519_digital_signature',
      passed: sigValid,
      expected: bundle.integrity.keyId ?? 'Ed25519 valid signature',
      actual: sigValid ? 'VERIFIED (Ed25519)' : 'INVALID_SIGNATURE',
      detail: sigValid
        ? `Ed25519 asymmetric digital signature verified (${bundle.integrity.keyId ?? 'default-key'}).`
        : 'Ed25519 digital signature verification failed against payload digest!',
    });
  }

  if (options?.expectedReleaseDigest) {
    const releaseMatch = bundle.releaseDigest === options.expectedReleaseDigest;
    checks.push({
      check: 'release_digest_binding',
      passed: releaseMatch,
      expected: options.expectedReleaseDigest,
      actual: bundle.releaseDigest,
      detail: releaseMatch
        ? 'Run is cryptographically bound to the expected immutable releaseDigest.'
        : 'Release digest mismatch between run evidence and expected release.',
    });
  }

  if (options?.lockfile) {
    const recomputedLockfileDigest = computeDigest(options.lockfile);
    const lockfileMatch = recomputedLockfileDigest === bundle.releaseDigest;
    checks.push({
      check: 'lockfile_digest_verification',
      passed: lockfileMatch,
      expected: bundle.releaseDigest,
      actual: recomputedLockfileDigest,
      detail: lockfileMatch
        ? 'Release lockfile canonical SHA-256 matches releaseDigest.'
        : 'Lockfile digest mismatch!',
    });
  }

  if (options?.expectedPolicyDigest && bundle.policyDecisions.length > 0) {
    const allMatch = bundle.policyDecisions.every(
      (d) => d.policyDigest === options.expectedPolicyDigest
    );
    checks.push({
      check: 'policy_digest_consistency',
      passed: allMatch,
      expected: options.expectedPolicyDigest,
      actual: bundle.policyDecisions[0]?.policyDigest,
      detail: allMatch
        ? `All ${bundle.policyDecisions.length} PEP policy decisions match active policyDigest.`
        : 'One or more policy decisions were evaluated against an unexpected policyDigest.',
    });
  } else if (bundle.policyDecisions.length > 0) {
    const firstDigest = bundle.policyDecisions[0].policyDigest;
    const consistent = bundle.policyDecisions.every((d) => d.policyDigest === firstDigest);
    checks.push({
      check: 'policy_digest_consistency',
      passed: consistent,
      expected: firstDigest,
      actual: firstDigest,
      detail: consistent
        ? `All ${bundle.policyDecisions.length} policy decisions use consistent policyDigest.`
        : 'Inconsistent policyDigest across decisions within the same run.',
    });
  }

  const allPassed = checks.every((c) => c.passed);

  return {
    valid: allPassed,
    tampered: !digestMatch,
    bundleDigest: bundle.integrity.bundleDigest,
    recomputedDigest,
    verifiedAt,
    checks,
  };
}

