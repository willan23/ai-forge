/**
 * Budget Enforcement
 *
 * Tracks and enforces budget limits per run:
 * - maxRunSeconds: wall clock time limit
 * - maxToolCalls: maximum number of tool invocations
 * - maxCostUsd: maximum cost in USD
 */

export interface BudgetConfig {
  maxRunSeconds: number;
  maxToolCalls: number;
  maxCostUsd: number;
}

export interface BudgetState {
  startedAt: Date;
  toolCalls: number;
  costUsd: number;
}

export interface BudgetCheck {
  allowed: boolean;
  reason?: string;
  remaining: {
    seconds: number;
    toolCalls: number;
    costUsd: number;
  };
}

export function checkBudget(config: BudgetConfig, state: BudgetState): BudgetCheck {
  const elapsedSeconds = (Date.now() - state.startedAt.getTime()) / 1000;
  const remainingSeconds = config.maxRunSeconds - elapsedSeconds;
  const remainingToolCalls = config.maxToolCalls - state.toolCalls;
  const remainingCostUsd = config.maxCostUsd - state.costUsd;

  // Check time limit
  if (remainingSeconds <= 0) {
    return {
      allowed: false,
      reason: 'time_limit_exceeded',
      remaining: { seconds: 0, toolCalls: remainingToolCalls, costUsd: remainingCostUsd },
    };
  }

  // Check tool call limit
  if (remainingToolCalls <= 0) {
    return {
      allowed: false,
      reason: 'tool_call_limit_exceeded',
      remaining: { seconds: remainingSeconds, toolCalls: 0, costUsd: remainingCostUsd },
    };
  }

  // Check cost limit
  if (remainingCostUsd <= 0) {
    return {
      allowed: false,
      reason: 'cost_limit_exceeded',
      remaining: { seconds: remainingSeconds, toolCalls: remainingToolCalls, costUsd: 0 },
    };
  }

  return {
    allowed: true,
    remaining: {
      seconds: Math.round(remainingSeconds),
      toolCalls: remainingToolCalls,
      costUsd: Math.round(remainingCostUsd * 100) / 100,
    },
  };
}

/**
 * Create a budget tracker for a run.
 */
export function createBudgetTracker(config: BudgetConfig) {
  const state: BudgetState = {
    startedAt: new Date(),
    toolCalls: 0,
    costUsd: 0,
  };

  return {
    check: () => checkBudget(config, state),
    recordToolCall: (costUsd: number = 0) => {
      state.toolCalls++;
      state.costUsd += costUsd;
    },
    getState: () => ({ ...state }),
  };
}
