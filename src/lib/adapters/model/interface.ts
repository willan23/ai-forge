/**
 * Model Adapter Interface
 *
 * Vendor-independent interface for LLM integration.
 * Start with DeterministicDemoModelAdapter — add real adapters
 * without changing domain logic, policy engine, or evidence bundles.
 */

export interface ModelAdapterInput {
  releaseDigest: string;
  instructions: string;
  task: string;
  context: Array<{ source: string; content: string; classification: string }>;
  outputSchema: object;
  budget: { maxTokens?: number; maxCostUsd: number };
}

export interface ModelAdapterOutput {
  output: unknown;
  usage: {
    inputTokens: number;
    outputTokens: number;
    costUsd: number;
  };
  modelVersion: string;
}

export interface ModelAdapter {
  analyze(input: ModelAdapterInput): Promise<ModelAdapterOutput>;
}
