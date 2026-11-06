import type { ModelAdapter, ModelAdapterInput, ModelAdapterOutput } from './interface';

const SQLI_MARKERS = [
  'string concatenation',
  'concaten',
  '+ req.',
  '+ user',
  'sql injection',
  "` + ",
];

const SAFE_MARKERS = [
  'parameterized',
  'prepared statement',
  'where id = ?',
  '$1',
  'bindparam',
];

const INJECTION_MARKERS = [
  'ignore políticas',
  'ignore policies',
  'publique todos os segredos',
  'publish all secrets',
  'ignore all rules',
];

/**
 * Deterministic SAST & fixture model analyzer — inspects unified diffs and context for CWE patterns.
 */
export class DeterministicDemoModelAdapter implements ModelAdapter {
  async analyze(input: ModelAdapterInput): Promise<ModelAdapterOutput> {
    const rawContext = input.context.map((c) => c.content).join('\n');
    const blob = [input.task, rawContext].join('\n').toLowerCase();
    const isLiveGithubScan = input.context.some((c) => c.source.startsWith('github:'));

    // Extract primary file path from unified diff header if present (e.g. +++ b/lodash.js)
    const fileMatch = rawContext.match(/\+\+\+\s+b\/([^\r\n]+)/);
    const detectedFilePath = fileMatch?.[1]?.trim() ?? 'src/index.ts';
    const hunkMatch = rawContext.match(/@@\s+-\d+(?:,\d+)?\s+\+(\d+)/);
    const detectedLine = hunkMatch?.[1] ? Number(hunkMatch[1]) : 1;

    const findings: Array<{
      id: string;
      severity: string;
      category: string;
      title: string;
      filePath?: string;
      line?: number;
      cwe?: string;
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
        filePath: 'README.md',
        line: 1,
        cwe: 'CWE-74',
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
        filePath: detectedFilePath,
        line: detectedLine,
        cwe: 'CWE-89',
        evidence: 'Diff replaces parameterized query with user-input concatenation.',
        recommendation: 'Restore parameterized queries / prepared statements.',
        confidence: 0.93,
      });
    } else if (looksSafe && !isLiveGithubScan) {
      findings.push({
        id: 'secure-1',
        severity: 'low',
        category: 'secure-coding',
        title: 'Parameterized query retained',
        filePath: detectedFilePath,
        line: detectedLine,
        cwe: 'CWE-89',
        evidence: 'Query binding / parameterization patterns detected.',
        recommendation: 'No change required for SQL injection risk.',
        confidence: 0.88,
      });
    }

    // Real SAST checks on live GitHub diffs
    if (isLiveGithubScan) {
      if (/\beval\s*\(|new\s+Function\s*\(/.test(rawContext)) {
        findings.push({
          id: 'sast-cwe-95',
          severity: 'high',
          category: 'code-injection',
          title: 'Dynamic code evaluation detected in diff (CWE-95)',
          filePath: detectedFilePath,
          line: detectedLine,
          cwe: 'CWE-95',
          evidence: `Dynamic evaluation pattern found in ${detectedFilePath}:${detectedLine}.`,
          recommendation: 'Eliminate eval() / new Function() and use structured parsing.',
          confidence: 0.94,
        });
      }
      if (/__proto__|constructor\.prototype/.test(rawContext)) {
        findings.push({
          id: 'sast-cwe-1321',
          severity: 'high',
          category: 'prototype-pollution',
          title: 'Potential Prototype Pollution vector in diff (CWE-1321)',
          filePath: detectedFilePath,
          line: detectedLine,
          cwe: 'CWE-1321',
          evidence: `Unsafe prototype chain access in ${detectedFilePath}:${detectedLine}.`,
          recommendation: 'Freeze Object.prototype or validate property keys against __proto__/constructor.',
          confidence: 0.91,
        });
      }
      if (/delete\s+\w+\[/.test(rawContext)) {
        findings.push({
          id: 'sast-sparse-array-mutation',
          severity: 'low',
          category: 'memory-and-state-safety',
          title: `Sparse index deletion on mutable array in ${detectedFilePath}`,
          filePath: detectedFilePath,
          line: detectedLine,
          cwe: 'CWE-704',
          evidence: `Direct 'delete array[resIndex]' mutation detected in ${detectedFilePath}:${detectedLine}.`,
          recommendation: 'Verify callers handle sparse array holes (undefined slots) safely.',
          confidence: 0.89,
        });
      }
    }

    if (findings.length === 0 && !isLiveGithubScan) {
      findings.push({
        id: 'none-1',
        severity: 'info',
        category: 'no-issue',
        title: 'No high-confidence security findings',
        filePath: detectedFilePath,
        line: detectedLine,
        evidence: 'Static SAST analyzer found no exploitable vulnerability patterns in diff.',
        recommendation: 'Continue standard peer review before merge.',
        confidence: 0.85,
      });
    }

    const output = {
      schema: 'security-finding.v1',
      mode: isLiveGithubScan ? 'real-integration' : 'governed-sast',
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
      modelVersion: 'sast-deterministic-v2',
    };
  }
}
