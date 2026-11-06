/**
 * Real Vulnerability Lookup Adapter (`https://api.osv.dev/v1/query`).
 *
 * Queries the live OSV.dev Open Source Vulnerability database maintained by Google
 * for real CVEs and GHSAs affecting npm, PyPI, Go, Cargo, and Maven packages.
 */

import type { CapabilityAdapter, CapabilityInvokeRequest, CapabilityInvokeResult } from './interface';
import { DemoCredentialBroker } from '../../domain/runtime/credential-broker';

export interface RealVulnerabilityMatch {
  id: string;
  cve: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  summary: string;
  published?: string;
  referenceUrl?: string;
}

interface OsvVulnRecord {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  published?: string;
  database_specific?: {
    severity?: string;
  };
  references?: Array<{ type?: string; url?: string }>;
}

function normalizeSeverity(raw?: string): 'low' | 'medium' | 'high' | 'critical' {
  const s = (raw ?? '').toLowerCase();
  if (s.includes('crit')) return 'critical';
  if (s.includes('high')) return 'high';
  if (s.includes('mod') || s.includes('med')) return 'medium';
  return 'medium';
}

export class OsvVulnerabilityLookupAdapter implements CapabilityAdapter {
  readonly name = 'dependency-vulnerability-db';
  private readonly broker = new DemoCredentialBroker();

  async invoke(request: CapabilityInvokeRequest): Promise<CapabilityInvokeResult> {
    const started = Date.now();
    const validation = this.broker.validate(request.credential, request.action, request.resource);

    if (!validation.valid) {
      return {
        status: 'failed',
        data: null,
        provenance: {
          adapter: this.name,
          mode: 'real-integration',
          timestamp: new Date().toISOString(),
        },
        latencyMs: Date.now() - started,
        error: validation.reason,
      };
    }

    if (request.action !== 'vulnerability:lookup') {
      return {
        status: 'failed',
        data: null,
        provenance: {
          adapter: this.name,
          mode: 'real-integration',
          timestamp: new Date().toISOString(),
        },
        latencyMs: Date.now() - started,
        error: 'action_not_supported',
      };
    }

    const payload = (request.payload ?? {}) as {
      package?: string;
      version?: string;
      ecosystem?: string;
    };
    const pkg = (payload.package ?? 'lodash').trim();
    const ecosystem = payload.ecosystem ?? 'npm';
    const version = payload.version ?? (pkg === 'lodash' ? '4.17.15' : undefined);

    try {
      const body: Record<string, unknown> = {
        package: {
          name: pkg,
          ecosystem,
        },
      };
      if (version) {
        body.version = version;
      }

      const res = await fetch('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10_000),
      });

      if (!res.ok) {
        return {
          status: 'failed',
          data: { status: res.status, package: pkg },
          provenance: {
            adapter: this.name,
            mode: 'real-integration',
            timestamp: new Date().toISOString(),
          },
          latencyMs: Date.now() - started,
          error: `osv_api_http_${res.status}`,
        };
      }

      const json = (await res.json()) as { vulns?: OsvVulnRecord[] };
      const vulns = json.vulns ?? [];

      const matches: RealVulnerabilityMatch[] = vulns.slice(0, 10).map((v) => {
        const cveAlias = (v.aliases ?? []).find((a) => a.startsWith('CVE-')) ?? v.id;
        return {
          id: v.id,
          cve: cveAlias,
          severity: normalizeSeverity(v.database_specific?.severity),
          summary: (v.summary ?? v.details ?? 'Known vulnerability advisory in OSV.dev').slice(0, 280),
          published: v.published,
          referenceUrl: v.references?.[0]?.url ?? `https://osv.dev/vulnerability/${v.id}`,
        };
      });

      return {
        status: 'succeeded',
        data: {
          package: pkg,
          version: version ?? 'latest',
          ecosystem,
          totalFound: vulns.length,
          matches,
          source: 'https://api.osv.dev/v1/query',
          mode: 'real-integration',
        },
        provenance: {
          adapter: this.name,
          mode: 'real-integration',
          timestamp: new Date().toISOString(),
        },
        latencyMs: Date.now() - started,
      };
    } catch (err) {
      return {
        status: 'failed',
        data: null,
        provenance: {
          adapter: this.name,
          mode: 'real-integration',
          timestamp: new Date().toISOString(),
        },
        latencyMs: Date.now() - started,
        error: err instanceof Error ? err.message : 'osv_lookup_failed',
      };
    }
  }
}

