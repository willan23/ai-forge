import { computeDigest } from './digest';
import type { AgentManifest } from './schema';

export interface ManifestDiffChange {
  field: string;
  category: 'autonomy' | 'capabilities' | 'budgets' | 'data' | 'evaluation' | 'instructions' | 'metadata';
  before: unknown;
  after: unknown;
  riskImpact: 'low' | 'medium' | 'high' | 'critical';
  summary: string;
}

export interface ManifestDiffReport {
  baseDigest: string;
  targetDigest: string;
  identical: boolean;
  overallRisk: 'low' | 'medium' | 'high' | 'critical';
  riskSummary: string;
  changes: ManifestDiffChange[];
}

const RISK_ORDER: Record<ManifestDiffReport['overallRisk'], number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function maxRisk(
  a: ManifestDiffReport['overallRisk'],
  b: ManifestDiffReport['overallRisk']
): ManifestDiffReport['overallRisk'] {
  return RISK_ORDER[a] >= RISK_ORDER[b] ? a : b;
}

/**
 * Computes a semantic governance diff and blast-radius risk assessment
 * between two AgentManifest versions.
 */
export function computeManifestDiff(
  base: AgentManifest,
  target: AgentManifest
): ManifestDiffReport {
  const baseDigest = computeDigest(base);
  const targetDigest = computeDigest(target);
  const changes: ManifestDiffChange[] = [];

  if (baseDigest === targetDigest) {
    return {
      baseDigest,
      targetDigest,
      identical: true,
      overallRisk: 'low',
      riskSummary: 'No changes detected between base and target manifest.',
      changes: [],
    };
  }

  // 1. Metadata version / owner
  if (base.metadata.version !== target.metadata.version) {
    changes.push({
      field: 'metadata.version',
      category: 'metadata',
      before: base.metadata.version,
      after: target.metadata.version,
      riskImpact: 'low',
      summary: `Version bumped from ${base.metadata.version} to ${target.metadata.version}.`,
    });
  }

  // 2. Autonomy level & approval policy
  if (base.spec.autonomy.level !== target.spec.autonomy.level) {
    const increased = target.spec.autonomy.level > base.spec.autonomy.level;
    changes.push({
      field: 'spec.autonomy.level',
      category: 'autonomy',
      before: base.spec.autonomy.level,
      after: target.spec.autonomy.level,
      riskImpact: increased ? (target.spec.autonomy.level >= 3 ? 'critical' : 'high') : 'low',
      summary: increased
        ? `Autonomy level increased from L${base.spec.autonomy.level} to L${target.spec.autonomy.level}.`
        : `Autonomy level reduced from L${base.spec.autonomy.level} to L${target.spec.autonomy.level}.`,
    });
  }

  if (base.spec.autonomy.approvalPolicy !== target.spec.autonomy.approvalPolicy) {
    const relaxed = target.spec.autonomy.approvalPolicy === 'never';
    changes.push({
      field: 'spec.autonomy.approvalPolicy',
      category: 'autonomy',
      before: base.spec.autonomy.approvalPolicy,
      after: target.spec.autonomy.approvalPolicy,
      riskImpact: relaxed ? 'critical' : 'medium',
      summary: `Approval policy changed from "${base.spec.autonomy.approvalPolicy}" to "${target.spec.autonomy.approvalPolicy}".`,
    });
  }

  // 3. Capabilities & actions
  const baseCaps = new Map(base.spec.capabilities.map((c) => [c.name, c]));
  const targetCaps = new Map(target.spec.capabilities.map((c) => [c.name, c]));

  for (const [name, cap] of targetCaps) {
    const prev = baseCaps.get(name);
    if (!prev) {
      const hasWriteOrDelete = cap.actions.some(
        (a) => a.includes('write') || a.includes('delete') || a.includes('merge') || a.includes('comment')
      );
      changes.push({
        field: `spec.capabilities[${name}]`,
        category: 'capabilities',
        before: null,
        after: { name: cap.name, actions: cap.actions, contractDigest: cap.contractDigest },
        riskImpact: hasWriteOrDelete ? 'high' : 'medium',
        summary: `Added capability "${name}" with actions [${cap.actions.join(', ')}].`,
      });
    } else {
      const prevActions = prev.actions.join(',');
      const nextActions = cap.actions.join(',');
      if (prevActions !== nextActions || prev.contractDigest !== cap.contractDigest) {
        changes.push({
          field: `spec.capabilities[${name}]`,
          category: 'capabilities',
          before: { actions: prev.actions, contractDigest: prev.contractDigest },
          after: { actions: cap.actions, contractDigest: cap.contractDigest },
          riskImpact: 'medium',
          summary: `Updated capability "${name}" actions or contract digest.`,
        });
      }
    }
  }

  for (const [name, prev] of baseCaps) {
    if (!targetCaps.has(name)) {
      changes.push({
        field: `spec.capabilities[${name}]`,
        category: 'capabilities',
        before: { name: prev.name, actions: prev.actions },
        after: null,
        riskImpact: 'low',
        summary: `Removed capability "${name}".`,
      });
    }
  }

  // 4. Data classification & egress
  if (base.spec.data.maxClassification !== target.spec.data.maxClassification) {
    changes.push({
      field: 'spec.data.maxClassification',
      category: 'data',
      before: base.spec.data.maxClassification,
      after: target.spec.data.maxClassification,
      riskImpact:
        target.spec.data.maxClassification === 'restricted' ||
        target.spec.data.maxClassification === 'confidential'
          ? 'high'
          : 'medium',
      summary: `Max data classification changed from "${base.spec.data.maxClassification}" to "${target.spec.data.maxClassification}".`,
    });
  }

  // 5. Budgets
  if (
    base.spec.budgets.maxCostUsd !== target.spec.budgets.maxCostUsd ||
    base.spec.budgets.maxToolCalls !== target.spec.budgets.maxToolCalls ||
    base.spec.budgets.maxRunSeconds !== target.spec.budgets.maxRunSeconds
  ) {
    const costIncreased = target.spec.budgets.maxCostUsd > base.spec.budgets.maxCostUsd;
    changes.push({
      field: 'spec.budgets',
      category: 'budgets',
      before: base.spec.budgets,
      after: target.spec.budgets,
      riskImpact: costIncreased ? 'medium' : 'low',
      summary: `Run budgets updated ($${base.spec.budgets.maxCostUsd}→$${target.spec.budgets.maxCostUsd}, ${base.spec.budgets.maxToolCalls}→${target.spec.budgets.maxToolCalls} calls).`,
    });
  }

  // 6. Instructions & prompt injection guardrails
  if (base.spec.instructions !== target.spec.instructions) {
    const lostUntrustedWarning =
      base.spec.instructions.toLowerCase().includes('não confiáveis') &&
      !target.spec.instructions.toLowerCase().includes('não confiáveis') &&
      !target.spec.instructions.toLowerCase().includes('untrusted');
    changes.push({
      field: 'spec.instructions',
      category: 'instructions',
      before: base.spec.instructions,
      after: target.spec.instructions,
      riskImpact: lostUntrustedWarning ? 'critical' : 'medium',
      summary: lostUntrustedWarning
        ? 'CRITICAL: System instructions removed untrusted-input defense directives!'
        : 'System instructions updated.',
    });
  }

  // 7. Evaluation gates
  if (JSON.stringify(base.spec.evaluation.gates) !== JSON.stringify(target.spec.evaluation.gates)) {
    const hadCritical = base.spec.evaluation.gates.filter((g) => g.severity === 'critical').length;
    const hasCritical = target.spec.evaluation.gates.filter((g) => g.severity === 'critical').length;
    changes.push({
      field: 'spec.evaluation.gates',
      category: 'evaluation',
      before: base.spec.evaluation.gates,
      after: target.spec.evaluation.gates,
      riskImpact: hasCritical < hadCritical ? 'critical' : 'medium',
      summary:
        hasCritical < hadCritical
          ? 'Critical evaluation release gates were weakened or removed!'
          : 'Evaluation release gates modified.',
    });
  }

  let overallRisk: ManifestDiffReport['overallRisk'] = 'low';
  for (const c of changes) {
    overallRisk = maxRisk(overallRisk, c.riskImpact);
  }

  const riskSummary =
    changes.length === 0
      ? 'Minor structural formatting change.'
      : `${changes.length} governance change(s) detected — highest risk impact: ${overallRisk.toUpperCase()}. ${changes.map((c) => c.summary).join(' ')}`;

  return {
    baseDigest,
    targetDigest,
    identical: false,
    overallRisk,
    riskSummary,
    changes,
  };
}

