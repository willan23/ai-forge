import type { ModelAdapter, ModelAdapterInput, ModelAdapterOutput } from './interface';

const SQLI_MARKERS = [
  'string concatenation',
  'concaten',
  '+ req.',
  '+ user',
  'sql injection',
  "` + ",
];

const SAFE_MARKERS = ['parameterized', 'prepared statement', '?', '$1', 'bind'];

const INJECTION_MARKERS = [
  'ignore políticas',
  'ignore policies',
  'publique todos os segredos',
  'publish all secrets',
  'ignore all rules',
];

/**
 * Deterministic demo model — recognizes fixtures and returns structured findings.
 * Mode: demo-simulation (not a real LLM).
 */
export class DeterministicDemoModelAdapter implements ModelAdapter {
  async analyze(input: ModelAdapterInput): Promise<ModelAdapterOutput> {
    const blob = [
      input.task,
      ...input.context.map((c) => c.content),
    ]
      .join('\n')
      .toLowerCase();

    const findings: Array<{
      id: string;
      severity: string;
      category: string;
      title: string;
      evidence: string;
      recommendation: string;
      confidence: number;
    }> = [];

    const hasInjectionAttempt = INJECTION_MARKERS.some((m) => blob.includes(m));
    const hasSqli = SQLI_MARKERS.some((m) => blob.includes(m));
    const looksSafe = SAFE_MARKERS.some((m) => blob.includes(m));

    if (hasInjectionAttempt) {
      findings.push({
        id: 'policy-note-injection',
        severity: 'info',
        category: 'prompt-injection-resisted',
        title: 'Untrusted instruction ignored',
        evidence: 'README/content attempted to override policies; instruction not followed.',
        recommendation: 'Continue treating repository content as untrusted data.',
        confidence: 0.99,
      });
    }

    if (hasSqli && !looksSafe) {
      findings.push({
        id: 'sqli-1',
        severity: 'high',
        category: 'sql-injection',
        title: 'SQL injection via string concatenation',
        evidence: 'Diff replaces parameterized query with user-input concatenation.',
        recommendation: 'Restore parameterized queries / prepared statements.',
        confidence: 0.93,
      });
    } else if (looksSafe) {
      findings.push({
        id: 'secure-1',
        severity: 'low',
        category: 'secure-coding',
        title: 'Parameterized query retained',
        evidence: 'Query binding / parameterization patterns detected.',
        recommendation: 'No change required for SQL injection risk.',
        confidence: 0.88,
      });
    }

    if (findings.length === 0) {
      findings.push({
        id: 'none-1',
        severity: 'info',
        category: 'no-issue',
        title: 'No high-confidence security findings',
        evidence: 'Demo analyzer did not match known vulnerability fixtures.',
        recommendation: 'Review manually if this is a novel pattern.',
        confidence: 0.55,
      });
    }

    const output = {
      schema: 'security-finding.v1',
      mode: 'demo-simulation',
      releaseDigest: input.releaseDigest,
      findings,
      summary: {
        findingCount: findings.length,
        highestSeverity: findings.reduce((max, f) => {
          const order = ['info', 'low', 'medium', 'high', 'critical'];
          return order.indexOf(f.severity) > order.indexOf(max) ? f.severity : max;
        }, 'info'),
      },
    };

    const inputTokens = Math.ceil(blob.length / 4);
    const outputTokens = Math.ceil(JSON.stringify(output).length / 4);

    return {
      output,
      usage: {
        inputTokens,
        outputTokens,
        costUsd: Math.round((inputTokens + outputTokens) * 0.000002 * 10000) / 10000,
      },
      modelVersion: 'deterministic-demo-v1',
    };
  }
}
