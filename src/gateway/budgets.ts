/**
 * Session budgets for the gateway: hard caps on what one proxied
 * session may consume. When a cap is hit the circuit trips and every
 * further `tools/call` is denied until the session ends.
 *
 * Budgets are measured in quantities the proxy can observe honestly:
 * number of forwarded tool calls, total tool-result bytes, and wall
 * time. Token/cost estimation is deliberately out of scope for v1.
 */

export interface BudgetLimits {
  /** Max forwarded tools/call requests per session. */
  maxCalls?: number;
  /** Max total tool-result bytes per session. */
  maxResultBytes?: number;
  /** Max session wall time in milliseconds. */
  maxSessionMs?: number;
}

export interface BudgetTracker {
  /** Deny reason if a new call would exceed budget, else null. */
  checkBeforeCall(): string | null;
  /** Record a forwarded call. */
  recordCall(): void;
  /** Record a completed call's result size; returns a trip notice or null. */
  recordResult(resultBytes: number): string | null;
  /** True once any cap has tripped. */
  readonly tripped: boolean;
  /** Human-readable summary of the cap that tripped, if any. */
  readonly tripReason: string | null;
}

export function createBudgetTracker(limits: BudgetLimits | undefined): BudgetTracker | undefined {
  if (!limits) return undefined;
  const startedAt = Date.now();
  let calls = 0;
  let resultBytes = 0;
  let tripReason: string | null = null;

  const checkWallTime = (): string | null => {
    if (limits.maxSessionMs !== undefined && Date.now() - startedAt >= limits.maxSessionMs) {
      return `budget exceeded: session wall time over ${limits.maxSessionMs}ms`;
    }
    return null;
  };

  return {
    get tripped() {
      return tripReason !== null;
    },
    get tripReason() {
      return tripReason;
    },
    checkBeforeCall(): string | null {
      if (tripReason) return `circuit tripped: ${tripReason}`;
      const wall = checkWallTime();
      if (wall) {
        tripReason = wall;
        return `circuit tripped: ${wall}`;
      }
      if (limits.maxCalls !== undefined && calls >= limits.maxCalls) {
        tripReason = `budget exceeded: max ${limits.maxCalls} tool calls per session`;
        return `circuit tripped: ${tripReason}`;
      }
      return null;
    },
    recordCall(): void {
      calls += 1;
    },
    recordResult(bytes: number): string | null {
      resultBytes += bytes;
      if (limits.maxResultBytes !== undefined && resultBytes > limits.maxResultBytes) {
        tripReason = `budget exceeded: max ${limits.maxResultBytes} result bytes per session`;
        return tripReason;
      }
      return null;
    },
  };
}
