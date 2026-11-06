/**
 * Run State Machine
 *
 * States: QUEUED → RESOLVING_RELEASE → RUNNING → AWAITING_APPROVAL → RUNNING → SUCCEEDED
 *                                               ↘ BLOCKED
 *                                               ↘ FAILED
 *                                               ↘ CANCELLED
 *                                               ↘ TIMED_OUT
 *
 * Terminal states cannot transition back. A retry creates a new Run.
 */

export type RunStatus =
  | 'queued'
  | 'resolving_release'
  | 'running'
  | 'awaiting_approval'
  | 'succeeded'
  | 'failed'
  | 'blocked'
  | 'cancelled'
  | 'timed_out';

const TERMINAL_STATES: RunStatus[] = ['succeeded', 'failed', 'blocked', 'cancelled', 'timed_out'];

const VALID_TRANSITIONS: Record<RunStatus, RunStatus[]> = {
  queued: ['resolving_release', 'cancelled'],
  resolving_release: ['running', 'failed', 'cancelled'],
  running: ['awaiting_approval', 'succeeded', 'failed', 'blocked', 'cancelled', 'timed_out'],
  awaiting_approval: ['running', 'blocked', 'cancelled', 'timed_out'],
  succeeded: [],
  failed: [],
  blocked: [],
  cancelled: [],
  timed_out: [],
};

export interface StateTransition {
  from: RunStatus;
  to: RunStatus;
  timestamp: string;
  reason?: string;
}

export function isTerminalState(status: RunStatus): boolean {
  return TERMINAL_STATES.includes(status);
}

export function canTransition(from: RunStatus, to: RunStatus): boolean {
  return VALID_TRANSITIONS[from]?.includes(to) ?? false;
}

export function transition(currentStatus: RunStatus, newStatus: RunStatus, reason?: string): StateTransition {
  if (isTerminalState(currentStatus)) {
    throw new Error(
      `Cannot transition from terminal state "${currentStatus}". Create a new Run instead (retryOfRunId).`
    );
  }

  if (!canTransition(currentStatus, newStatus)) {
    throw new Error(
      `Invalid state transition: "${currentStatus}" → "${newStatus}". ` +
      `Valid transitions from "${currentStatus}": [${VALID_TRANSITIONS[currentStatus].join(', ')}]`
    );
  }

  return {
    from: currentStatus,
    to: newStatus,
    timestamp: new Date().toISOString(),
    reason,
  };
}

/**
 * Get all valid next states from the current state.
 */
export function getValidNextStates(currentStatus: RunStatus): RunStatus[] {
  return VALID_TRANSITIONS[currentStatus] ?? [];
}
