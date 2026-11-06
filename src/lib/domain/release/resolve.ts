import type { AgentLockfile } from './lockfile';
import { verifyDigest } from '../manifest/digest';
import type { AgentManifest } from '../manifest/schema';

export interface ResolvedRelease {
  releaseDigest: string;
  version: string;
  status: string;
  lockfile: AgentLockfile;
  manifest: AgentManifest;
  policyDigest: string;
}

export interface ResolveReleaseError {
  code:
    | 'digest_mismatch'
    | 'lockfile_invalid'
    | 'manifest_digest_mismatch'
    | 'not_executable'
    | 'not_found';
  message: string;
}

/**
 * Resolve a release for execution. Runtime must use exact digests — never "latest".
 */
export function resolveRelease(params: {
  releaseDigest: string;
  version: string;
  status: string;
  lockfile: unknown;
  manifest: unknown;
}): { ok: true; release: ResolvedRelease } | { ok: false; error: ResolveReleaseError } {
  const { releaseDigest, version, status, lockfile, manifest } = params;

  if (!lockfile || typeof lockfile !== 'object') {
    return { ok: false, error: { code: 'lockfile_invalid', message: 'Lockfile is missing or invalid.' } };
  }

  const typedLockfile = lockfile as AgentLockfile;

  if (!verifyDigest(typedLockfile, releaseDigest)) {
    return {
      ok: false,
      error: {
        code: 'digest_mismatch',
        message: `Lockfile does not match releaseDigest ${releaseDigest}.`,
      },
    };
  }

  if (!verifyDigest(manifest, typedLockfile.manifestDigest)) {
    return {
      ok: false,
      error: {
        code: 'manifest_digest_mismatch',
        message: 'Manifest does not match lockfile.manifestDigest.',
      },
    };
  }

  // Executable statuses for MVP: published or candidate in non-prod demos
  const executable = status === 'published' || status === 'candidate';
  if (!executable) {
    return {
      ok: false,
      error: {
        code: 'not_executable',
        message: `Release status "${status}" cannot be executed. Use published or candidate.`,
      },
    };
  }

  return {
    ok: true,
    release: {
      releaseDigest,
      version,
      status,
      lockfile: typedLockfile,
      manifest: manifest as AgentManifest,
      policyDigest: typedLockfile.policyDigest,
    },
  };
}
