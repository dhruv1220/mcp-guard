import { describe, expect, it, vi } from "vitest";
import { createBudgetTracker } from "../src/gateway/budgets.js";

describe("createBudgetTracker", () => {
  it("returns undefined when no limits are configured", () => {
    expect(createBudgetTracker(undefined)).toBeUndefined();
  });

  it("allows calls under the maxCalls cap", () => {
    const t = createBudgetTracker({ maxCalls: 2 })!;
    expect(t.checkBeforeCall()).toBeNull();
    t.recordCall();
    expect(t.checkBeforeCall()).toBeNull();
    t.recordCall();
    expect(t.tripped).toBe(false);
  });

  it("trips the circuit at maxCalls and denies everything after", () => {
    const t = createBudgetTracker({ maxCalls: 1 })!;
    t.recordCall();
    const reason = t.checkBeforeCall();
    expect(reason).toContain("max 1 tool calls");
    expect(t.tripped).toBe(true);
    expect(t.checkBeforeCall()).toContain("circuit tripped");
  });

  it("trips when cumulative result bytes exceed the cap", () => {
    const t = createBudgetTracker({ maxResultBytes: 100 })!;
    expect(t.recordResult(60)).toBeNull();
    expect(t.recordResult(50)).toContain("max 100 result bytes");
    expect(t.tripped).toBe(true);
    expect(t.checkBeforeCall()).toContain("circuit tripped");
  });

  it("trips when the session wall time is exceeded", () => {
    vi.useFakeTimers();
    try {
      const t = createBudgetTracker({ maxSessionMs: 1000 })!;
      expect(t.checkBeforeCall()).toBeNull();
      vi.advanceTimersByTime(1500);
      expect(t.checkBeforeCall()).toContain("wall time");
      expect(t.tripped).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("combines independent caps", () => {
    const t = createBudgetTracker({ maxCalls: 10, maxResultBytes: 50 })!;
    t.recordCall();
    expect(t.checkBeforeCall()).toBeNull();
    t.recordResult(1000);
    expect(t.checkBeforeCall()).toContain("circuit tripped");
  });
});
