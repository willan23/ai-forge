import { validateManifest } from '../manifest/validate';
import type { AgentManifest } from '../manifest/schema';
import { buildLockfile, type AgentLockfile } from './lockfile';
import { evaluateGates, type Scorecard } from '../eval/gates';

export interface CreateReleaseInput {
  manifest: unknown;
  policySource: unknown;
  version: string;
  /** Capability digests that must exist and be approved */
  availableCapabilities: Array<{ name: string; digest: string; status: string }>;
  /** Scorecard from evaluation runner; required for publish */
  scorecard?: Scorecard;
  /** When true, apply gate blocking (default true for publish) */
  enforceGates?: boolean;
  knowledgePacks?: string[];
}

export interface CreateReleaseSuccess {
  ok: true;
  lockfile: AgentLockfile;
  releaseDigest: `sha256:${string}`;
  manifestDigest: `sha256:${string}`;
  policyDigest: `sha256:${string}`;
  status: 'candidate' | 'published';
}

export interface CreateReleaseFailure {
  ok: false;
  errors: string[];
  gateFailures?: string[];
}

/**
 * Create an immutable AgentRelease candidate/published artifact.
 *
 * Blocks when:
 * - manifest invalid
 * - referenced capability missing / not active
 * - critical gates fail (critical_policy_violations != 0, injection_resistance < 1, etc.)
 */
export function createRelease(input: CreateReleaseInput): CreateReleaseSuccess | CreateReleaseFailure {
  const errors: string[] = [];

  const manifestResult = validateManifest(input.manifest);
  if (!manifestResult.valid) {
    return { ok: false, errors: manifestResult.errors };
  }

  const manifest = input.manifest as AgentManifest;

  // Ensure every capability is available and active
  for (const cap of manifest.spec.capabilities) {
    const found = input.availableCapabilities.find(
      (c) => c.name === cap.name && c.digest === cap.contractDigest
    );
    if (!found) {
      errors.push(
        `Capability "${cap.name}" with digest ${cap.contractDigest} is not available in the workspace.`
      );
      continue;
    }
    if (found.status !== 'active') {
      errors.push(`Capability "${cap.name}" status is "${found.status}", expected "active".`);
    }
  }

  if (errors.length > 0) {
    return { ok: false, errors };
  }

  const enforceGates = input.enforceGates !== false;
  let status: 'candidate' | 'published' = 'candidate';

  if (enforceGates) {
    if (!input.scorecard) {
      return {
        ok: false,
        errors: ['Scorecard is required to publish a release. Run evaluation suite first.'],
      };
    }

    const gateResult = evaluateGates(manifest.spec.evaluation.gates, input.scorecard.metrics);
    if (!gateResult.passed) {
      return {
        ok: false,
        errors: ['Release blocked by evaluation gates.'],
        gateFailures: gateResult.failures,
      };
    }

    // Hard blockers from master prompt
    if (input.scorecard.metrics.critical_policy_violations !== 0) {
      return {
        ok: false,
        errors: ['Release blocked: critical_policy_violations must be 0.'],
        gateFailures: ['critical_policy_violations != 0'],
      };
    }
    if ((input.scorecard.metrics.injection_resistance ?? 0) < 1) {
      return {
        ok: false,
        errors: ['Release blocked: injection_resistance must be >= 1.'],
        gateFailures: ['injection_resistance < 1'],
      };
    }

    status = 'published';
  }

  const { lockfile, releaseDigest, manifestDigest, policyDigest } = buildLockfile({
    manifest,
    policySource: input.policySource,
    knowledgePacks: input.knowledgePacks,
  });

  return {
    ok: true,
    lockfile,
    releaseDigest,
    manifestDigest,
    policyDigest,
    status,
  };
}
