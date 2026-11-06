/**
 * @aiforge/sdk — Official Universal Agent Governance SDK (TypeScript / Node.js)
 *
 * Connects any external agent (LangChain, OpenAI Agents SDK, Vercel AI SDK, CrewAI TS, MCP)
 * to AI Forge's 9-Rule Deterministic Policy Enforcement Point (PEP) and Ed25519 Evidence Plane.
 */

export interface AiForgeClientConfig {
  /** Base URL of the AI Forge Control Plane (e.g., "https://aiforge.company.com" or "http://localhost:3000") */
  baseUrl: string;
  /** Tenant Gateway API Key ("aiforge_live_...") generated in /settings */
  apiKey: string;
  /** Default governed Agent ID (defaults to "agent_security_pr_auditor") */
  agentId?: string;
  /** Request timeout in milliseconds (defaults to 10_000) */
  timeoutMs?: number;
  /** Custom fetch implementation for testing or edge runtimes */
  fetchImpl?: typeof fetch;
}

export interface AuthorizeToolCallInput {
  agentId?: string;
  runId?: string;
  capability: string;
  action: string;
  effect: 'read' | 'write';
  resource: string;
  dataClassification?: 'public' | 'internal' | 'confidential' | 'restricted';
  purpose?: string;
  currentCostUsd?: number;
  currentToolCalls?: number;
}

export interface AuthorizeToolCallResult {
  decision: 'allow' | 'deny' | 'approval_required';
  reasonCode: string;
  explanation?: string;
  organizationId: string;
  releaseDigest: string;
  policyDigest: string;
  delegatedCredential: {
    id: string;
    runId: string;
    releaseDigest: string;
    capability: string;
    allowedActions: string[];
    allowedResources: string[];
    issuedAt: string;
    expiresAt: string;
    purpose: string;
    signature: string;
  } | null;
}

export interface RecordedToolInvocation {
  capability: string;
  action: string;
  status: 'succeeded' | 'failed' | 'blocked';
  latencyMs: number;
  costUsd: number;
}

export interface SubmitEvidenceInput {
  agentId?: string;
  runId?: string;
  status: 'succeeded' | 'failed' | 'blocked';
  inputPayload?: unknown;
  outputPayload?: unknown;
  costUsd?: number;
  inputTokens?: number;
  outputTokens?: number;
  policyDecisions?: Array<{
    action: string;
    resource: string;
    decision: 'allow' | 'deny' | 'approval_required';
    reasonCode: string;
  }>;
  toolCalls?: RecordedToolInvocation[];
}

export class AiForgePolicyDeniedError extends Error {
  readonly decision: 'deny' | 'approval_required';
  readonly reasonCode: string;
  readonly resource: string;

  constructor(params: {
    decision: 'deny' | 'approval_required';
    reasonCode: string;
    resource: string;
    explanation?: string;
  }) {
    super(
      `AI Forge PEP blocked tool execution (${params.decision}: ${params.reasonCode}) on resource "${params.resource}"${
        params.explanation ? ` — ${params.explanation}` : ''
      }`
    );
    this.name = 'AiForgePolicyDeniedError';
    this.decision = params.decision;
    this.reasonCode = params.reasonCode;
    this.resource = params.resource;
  }
}

export class AiForgeGatewayClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly defaultAgentId: string;
  private readonly timeoutMs: number;
  private readonly fetchFn: typeof fetch;

  private readonly sessionDecisions: Array<{
    action: string;
    resource: string;
    decision: 'allow' | 'deny' | 'approval_required';
    reasonCode: string;
  }> = [];
  private readonly sessionToolCalls: RecordedToolInvocation[] = [];

  constructor(config: AiForgeClientConfig) {
    if (!config.baseUrl) throw new Error('AiForgeGatewayClient requires baseUrl');
    if (!config.apiKey) throw new Error('AiForgeGatewayClient requires apiKey');
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.apiKey = config.apiKey;
    this.defaultAgentId = config.agentId ?? 'agent_security_pr_auditor';
    this.timeoutMs = config.timeoutMs ?? 10_000;
    this.fetchFn = config.fetchImpl ?? fetch;
  }

  /**
   * Evaluates the 9-Rule Deterministic Policy Enforcement Point (PEP) before a tool call.
   */
  async authorizeToolCall(input: AuthorizeToolCallInput): Promise<AuthorizeToolCallResult> {
    const res = await this.fetchFn(`${this.baseUrl}/api/v1/gateway/authorize`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        externalAgentId: input.agentId ?? this.defaultAgentId,
        externalRunId: input.runId,
        capability: input.capability,
        action: input.action,
        effect: input.effect,
        resource: input.resource,
        dataClassification: input.dataClassification ?? 'internal',
        purpose: input.purpose ?? `SDK governed tool call: ${input.capability}/${input.action}`,
        currentCostUsd: input.currentCostUsd ?? 0,
        currentToolCalls: input.currentToolCalls ?? this.sessionToolCalls.length,
      }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    const data = (await res.json()) as AuthorizeToolCallResult & { error?: string };
    if (!res.ok && !data.decision) {
      throw new Error(data.error ?? `Gateway authorization failed with HTTP ${res.status}`);
    }

    this.sessionDecisions.push({
      action: input.action,
      resource: input.resource,
      decision: data.decision,
      reasonCode: data.reasonCode,
    });

    return data;
  }

  /**
   * Wraps any asynchronous tool function with mandatory pre-execution PEP authorization,
   * fail-closed blocking on `deny` / `approval_required`, and automatic telemetry recording.
   */
  guardTool<TArgs, TResult>(
    metadata: {
      capability: string;
      action: string;
      effect: 'read' | 'write';
      resolveResource: (args: TArgs) => string;
      dataClassification?: 'public' | 'internal' | 'confidential' | 'restricted';
    },
    handler: (
      args: TArgs,
      credential: NonNullable<AuthorizeToolCallResult['delegatedCredential']>
    ) => Promise<TResult>
  ): (args: TArgs) => Promise<TResult> {
    return async (args: TArgs): Promise<TResult> => {
      const resource = metadata.resolveResource(args);
      const started = Date.now();
      const auth = await this.authorizeToolCall({
        capability: metadata.capability,
        action: metadata.action,
        effect: metadata.effect,
        resource,
        dataClassification: metadata.dataClassification,
      });

      if (auth.decision !== 'allow' || !auth.delegatedCredential) {
        this.sessionToolCalls.push({
          capability: metadata.capability,
          action: metadata.action,
          status: 'blocked',
          latencyMs: Math.max(1, Date.now() - started),
          costUsd: 0,
        });
        throw new AiForgePolicyDeniedError({
          decision: auth.decision === 'approval_required' ? 'approval_required' : 'deny',
          reasonCode: auth.reasonCode,
          resource,
          explanation: auth.explanation,
        });
      }

      try {
        const result = await handler(args, auth.delegatedCredential);
        this.sessionToolCalls.push({
          capability: metadata.capability,
          action: metadata.action,
          status: 'succeeded',
          latencyMs: Math.max(1, Date.now() - started),
          costUsd: 0,
        });
        return result;
      } catch (err) {
        this.sessionToolCalls.push({
          capability: metadata.capability,
          action: metadata.action,
          status: 'failed',
          latencyMs: Math.max(1, Date.now() - started),
          costUsd: 0,
        });
        throw err;
      }
    };
  }

  /**
   * Seals the governed execution run and generates an Ed25519 + SHA-256 signed EvidenceBundle.
   */
  async submitEvidence(input: SubmitEvidenceInput) {
    const res = await this.fetchFn(`${this.baseUrl}/api/v1/gateway/evidence`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        externalAgentId: input.agentId ?? this.defaultAgentId,
        externalRunId: input.runId,
        status: input.status,
        inputPayload: (input.inputPayload as Record<string, unknown> | undefined) ?? {},
        outputPayload: (input.outputPayload as Record<string, unknown> | undefined) ?? {},
        cost: {
          totalUsd: input.costUsd ?? 0,
          inputTokens: input.inputTokens ?? 0,
          outputTokens: input.outputTokens ?? 0,
        },
        policyDecisions: input.policyDecisions ?? this.sessionDecisions,
        toolCalls: input.toolCalls ?? this.sessionToolCalls,
      }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error ?? `Gateway evidence submission failed with HTTP ${res.status}`);
    }
    return data as {
      run: { id: string; status: string };
      evidenceBundle: {
        integrity: {
          bundleDigest: string;
          signature?: string;
          keyId?: string;
        };
      };
      verification: { valid: boolean; tampered: boolean };
    };
  }

  getRecordedDecisions() {
    return [...this.sessionDecisions];
  }

  getRecordedToolCalls() {
    return [...this.sessionToolCalls];
  }
}

