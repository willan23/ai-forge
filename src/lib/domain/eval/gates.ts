import { z } from 'zod';
import { EvalGate } from '../manifest/schema';

export type EvalGateType = z.infer<typeof EvalGate>;

export interface ScorecardMetrics {
  task_success_rate: number;
  tool_contract_correctness: number;
  critical_policy_violations: number;
  injection_resistance: number;
  false_positive_rate: number;
  average_cost_usd: number;
  p95_latency_ms: number;
  [key: string]: number;
}

export interface Scorecard {
  releaseDigest: string;
  suite: string;
  metrics: ScorecardMetrics;
  gateResult: 'pass' | 'fail';
  failures: string[];
}

export interface GateEvaluationResult {
  passed: boolean;
  failures: string[];
}

function compare(operator: 'gte' | 'lte' | 'eq', actual: number, threshold: number): boolean {
  switch (operator) {
    case 'gte':
      return actual >= threshold;
    case 'lte':
      return actual <= threshold;
    case 'eq':
      return actual === threshold;
  }
}

/**
 * Evaluate release gates against scorecard metrics.
 * Critical gate failures always block publication.
 */
export function evaluateGates(
  gates: Array<Pick<EvalGateType, 'metric' | 'operator' | 'threshold' | 'severity'>>,
  metrics: ScorecardMetrics
): GateEvaluationResult {
  const failures: string[] = [];

  for (const gate of gates) {
    const actual = metrics[gate.metric];
    if (actual === undefined) {
      failures.push(`Missing metric "${gate.metric}" for gate evaluation.`);
      continue;
    }
    if (!compare(gate.operator, actual, gate.threshold)) {
      failures.push(
        `${gate.severity.toUpperCase()}: ${gate.metric} ${gate.operator} ${gate.threshold} failed (actual=${actual})`
      );
    }
  }

  return { passed: failures.length === 0, failures };
}

/**
 * Build a scorecard from metrics and gate evaluation.
 */
export function buildScorecard(params: {
  releaseDigest: string;
  suite: string;
  metrics: ScorecardMetrics;
  gates: Array<Pick<EvalGateType, 'metric' | 'operator' | 'threshold' | 'severity'>>;
}): Scorecard {
  const gateResult = evaluateGates(params.gates, params.metrics);
  return {
    releaseDigest: params.releaseDigest,
    suite: params.suite,
    metrics: params.metrics,
    gateResult: gateResult.passed ? 'pass' : 'fail',
    failures: gateResult.failures,
  };
}
