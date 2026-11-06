import type { CapabilityAdapter, CapabilityInvokeRequest, CapabilityInvokeResult } from './interface';
import { DemoCredentialBroker } from '../../domain/runtime/credential-broker';

const CVE_FIXTURES: Record<string, { cve: string; severity: string; summary: string }> = {
  lodash: {
    cve: 'CVE-2021-23337',
    severity: 'high',
    summary: 'Command injection in lodash template.',
  },
  express: {
    cve: 'CVE-2024-XXXX',
    severity: 'medium',
    summary: 'Demo vulnerability fixture for express.',
  },
};

/**
 * Demo vulnerability lookup — returns known CVE fixtures.
 * Mode: demo-simulation.
 */
export class DemoVulnerabilityLookupAdapter implements CapabilityAdapter {
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
          mode: 'demo-simulation',
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
          mode: 'demo-simulation',
          timestamp: new Date().toISOString(),
        },
        latencyMs: Date.now() - started,
        error: 'action_not_supported',
      };
    }

    const payload = (request.payload ?? {}) as { package?: string };
    const pkg = (payload.package ?? 'lodash').toLowerCase();
    const hit = CVE_FIXTURES[pkg];

    return {
      status: 'succeeded',
      data: {
        package: pkg,
        matches: hit ? [hit] : [],
        mode: 'demo-simulation',
      },
      provenance: {
        adapter: this.name,
        mode: 'demo-simulation',
        timestamp: new Date().toISOString(),
      },
      latencyMs: Date.now() - started + 3,
    };
  }
}
