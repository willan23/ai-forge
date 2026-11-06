import type { EvidenceBundle } from './schema';
import { EvidenceBundle as EvidenceBundleSchema } from './schema';
import { EvidenceBundleBuilder } from './bundle';

/**
 * Export an evidence bundle as validated JSON string (pretty-printed).
 */
export function exportEvidenceBundleJson(bundle: EvidenceBundle): string {
  const parsed = EvidenceBundleSchema.parse(bundle);
  return JSON.stringify(parsed, null, 2);
}

/**
 * Validate and parse an evidence bundle from JSON.
 */
export function parseEvidenceBundleJson(json: string): EvidenceBundle {
  return EvidenceBundleSchema.parse(JSON.parse(json));
}

export { EvidenceBundleBuilder };
