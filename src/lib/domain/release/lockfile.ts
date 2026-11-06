import { computeDigest } from '../manifest/digest';
import type { AgentManifest } from '../manifest/schema';

export interface LockfileCapability {
  name: string;
  contractDigest: string;
}

export interface LockfileModel {
  provider: string;
  model: string;
  configurationDigest: string;
}

export interface AgentLockfile {
  manifestDigest: string;
  policyDigest: string;
  capabilities: LockfileCapability[];
  model: LockfileModel;
  knowledgePacks: string[];
  evaluationSuites: string[];
  createdAt: string;
}

export interface BuildLockfileInput {
  manifest: AgentManifest;
  policySource: unknown;
  knowledgePacks?: string[];
  createdAt?: string;
}

/**
 * Build an immutable lockfile from a validated manifest and policy bundle.
 * The releaseDigest is the SHA-256 of the canonical lockfile JSON.
 */
export function buildLockfile(input: BuildLockfileInput): {
  lockfile: AgentLockfile;
  releaseDigest: `sha256:${string}`;
  manifestDigest: `sha256:${string}`;
  policyDigest: `sha256:${string}`;
} {
  const manifestDigest = computeDigest(input.manifest);
  const policyDigest = computeDigest(input.policySource);
  const configurationDigest = computeDigest(input.manifest.spec.model);

  const lockfile: AgentLockfile = {
    manifestDigest,
    policyDigest,
    capabilities: input.manifest.spec.capabilities.map((cap) => ({
      name: cap.name,
      contractDigest: cap.contractDigest,
    })),
    model: {
      provider: input.manifest.spec.model.provider,
      model: input.manifest.spec.model.model,
      configurationDigest,
    },
    knowledgePacks: input.knowledgePacks ?? input.manifest.spec.knowledge?.packRefs ?? [],
    evaluationSuites: input.manifest.spec.evaluation.suiteRefs,
    createdAt: input.createdAt ?? new Date().toISOString(),
  };

  const releaseDigest = computeDigest(lockfile);

  return { lockfile, releaseDigest, manifestDigest, policyDigest };
}
