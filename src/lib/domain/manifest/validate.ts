import { AgentManifest, detectSecretFields } from './schema';

export interface ManifestValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Validate an AgentManifest beyond schema validation.
 * Checks business rules that Zod alone cannot enforce.
 */
export function validateManifest(manifest: unknown): ManifestValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Secret field detection — manifests must NEVER contain secret values
  // (run before Zod so forbidden keys are reported even under .strict())
  const secretFields = detectSecretFields(manifest);
  for (const field of secretFields) {
    errors.push(
      `Forbidden secret field detected: "${field}". Manifests must not include secret, apiKey, token, or password fields.`
    );
  }

  // Zod schema validation
  const parseResult = AgentManifest.safeParse(manifest);
  if (!parseResult.success) {
    for (const issue of parseResult.error.issues) {
      errors.push(`${issue.path.join('.')}: ${issue.message}`);
    }
    return { valid: false, errors, warnings };
  }

  if (secretFields.length > 0) {
    return { valid: false, errors, warnings };
  }

  const data = parseResult.data;

  // Autonomy level 3–5 restrictions (already in Zod, but double-check)
  if (data.spec.autonomy.level >= 3 && data.spec.autonomy.approvalPolicy === 'never') {
    errors.push('Autonomy levels 3–5 cannot use approvalPolicy "never".');
  }

  // Budget sanity checks
  if (data.spec.budgets.maxCostUsd <= 0) {
    errors.push('maxCostUsd must be positive.');
  }
  if (data.spec.budgets.maxToolCalls <= 0) {
    warnings.push('maxToolCalls is 0 — the agent cannot invoke any tools.');
  }
  if (data.spec.budgets.maxRunSeconds <= 0) {
    errors.push('maxRunSeconds must be positive.');
  }

  // Capability contract digest format validation
  for (const cap of data.spec.capabilities) {
    if (!cap.contractDigest.match(/^sha256:[a-f0-9]{64}$/)) {
      errors.push(`Capability "${cap.name}" has invalid contractDigest format. Expected sha256:<64 hex chars>.`);
    }
    if (cap.actions.length === 0) {
      errors.push(`Capability "${cap.name}" must declare at least one action.`);
    }
  }

  // Evaluation gates must include at least one critical gate
  const hasCriticalGate = data.spec.evaluation.gates.some((g) => g.severity === 'critical');
  if (!hasCriticalGate) {
    warnings.push('No critical severity gate defined. Consider adding a critical gate for policy violations or injection resistance.');
  }

  // Check for duplicate capability names
  const capNames = data.spec.capabilities.map((c) => c.name);
  const uniqueCapNames = new Set(capNames);
  if (uniqueCapNames.size !== capNames.length) {
    errors.push('Duplicate capability names detected.');
  }

  return { valid: errors.length === 0, errors, warnings };
}
