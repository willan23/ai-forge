import { CapabilityContract } from './schema';

export interface ContractValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Validate a CapabilityContract beyond Zod schema checks.
 */
export function validateContract(contract: unknown): ContractValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  const parseResult = CapabilityContract.safeParse(contract);
  if (!parseResult.success) {
    for (const issue of parseResult.error.issues) {
      errors.push(`${issue.path.join('.')}: ${issue.message}`);
    }
    return { valid: false, errors, warnings };
  }

  const data = parseResult.data;

  // Write/delete actions should require approval unless explicitly documented
  for (const action of data.spec.actions) {
    if ((action.effect === 'write' || action.effect === 'delete') && action.approval === 'never') {
      errors.push(
        `Action "${action.name}" has effect "${action.effect}" but approval is "never". Risk actions require approval.`
      );
    }
    if (action.effect === 'delete' && action.reversible) {
      warnings.push(`Action "${action.name}" is delete but marked reversible — verify rollback path.`);
    }
  }

  // High/critical risk connectors must require a human owner
  if (
    (data.spec.risk.level === 'high' || data.spec.risk.level === 'critical') &&
    !data.spec.risk.requiresHumanOwner
  ) {
    errors.push('High/critical risk contracts must set requiresHumanOwner to true.');
  }

  // Short-lived delegation should define TTL
  if (
    data.spec.authentication.delegation === 'short-lived' &&
    data.spec.authentication.maxTtlSeconds === undefined
  ) {
    errors.push('short-lived delegation requires maxTtlSeconds.');
  }

  // Resources must have at least one pattern
  if (data.spec.resources.length === 0) {
    warnings.push('No resources declared — all resource checks will fail at runtime.');
  }

  // Duplicate action names
  const names = data.spec.actions.map((a) => a.name);
  if (new Set(names).size !== names.length) {
    errors.push('Duplicate action names detected in capability contract.');
  }

  return { valid: errors.length === 0, errors, warnings };
}
