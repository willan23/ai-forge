import type { DelegatedCredential } from '../../domain/runtime/credential-broker';

export interface CapabilityInvokeRequest {
  credential: DelegatedCredential;
  action: string;
  resource: string;
  payload: unknown;
  traceId: string;
  /** Required for write adapters such as draft-comment */
  approvalId?: string;
}

export interface CapabilityInvokeResult {
  status: 'succeeded' | 'failed';
  data: unknown;
  provenance: {
    adapter: string;
    mode: 'demo-simulation' | 'real-integration';
    timestamp: string;
  };
  latencyMs: number;
  error?: string;
}

export interface CapabilityAdapter {
  readonly name: string;
  invoke(request: CapabilityInvokeRequest): Promise<CapabilityInvokeResult>;
}
