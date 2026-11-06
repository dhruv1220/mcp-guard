import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AuditError,
  formatAuditTable,
  summarizeAudit,
} from "../src/audit-report.js";

function fixture(lines: string[]): string {
  const dir = mkdtempSync(join(tmpdir(), "mcpguard-audit-"));
  const path = join(dir, "audit.jsonl");
  writeFileSync(path, lines.join("\n") + "\n");
  return path;
}

const rec = (over: Record<string, unknown>) =>
  JSON.stringify({
    ts: "2026-10-31T10:00:00Z",
    server: "files",
    tool: "read_file",
    decision: "allow",
    reason: "allowed by policy",
    ...over,
  });

describe("summarizeAudit", () => {
  it("tallies calls, denials, reasons, and injection flags", () => {
    const path = fixture([
      rec({ tool: "read_file", durationMs: 100, resultBytes: 500 }),
      rec({ tool: "read_file", durationMs: 300, resultBytes: 1500 }),
      rec({
        tool: "delete_file",
        decision: "deny",
        reason: "denied by policy",
      }),
      rec({
        tool: "delete_file",
        decision: "deny",
        reason: "denied by policy",
      }),
      rec({
        tool: "write_file",
        decision: "deny",
        reason: "circuit tripped: budget exceeded: max 3 tool calls per session",
      }),
      rec({
        tool: "read_file",
        injectionFlags: ["ignore previous instructions"],
        durationMs: 200,
        resultBytes: 250,
      }),
      rec({
        tool: "read_file",
        budgetTrip: "budget exceeded: max 1024 result bytes per session",
        durationMs: 50,
        resultBytes: 1200,
      }),
      "this line is truncated json{",
      "",
      JSON.stringify({ server: "files" }),
    ]);
    const s = summarizeAudit(path);
    expect(s.totals).toEqual({
      calls: 7,
      allowed: 4,
      denied: 3,
      resultBytes: 3450,
      injectionFlagged: 1,
      budgetTrips: 1,
      avgDurationMs: 162.5,
      maxDurationMs: 300,
    });
    expect(s.skippedLines).toBe(2);
    expect(s.firstTs).toBe("2026-10-31T10:00:00Z");
    expect(s.denyReasons).toEqual([
      { reason: "denied by policy", count: 2 },
      {
        reason: "circuit tripped: budget exceeded: max 3 tool calls per session",
        count: 1,
      },
    ]);
    expect(s.injectionFlags).toEqual([
      { flag: "ignore previous instructions", count: 1 },
    ]);
    // Most-denied tool first; denied tools tie-break by calls.
    expect(s.tools.map((t) => t.tool)).toEqual([
      "delete_file",
      "write_file",
      "read_file",
    ]);
    expect(s.tools[0]).toMatchObject({
      server: "files",
      tool: "delete_file",
      calls: 2,
      allowed: 0,
      denied: 2,
      topDenyReasons: [{ reason: "denied by policy", count: 2 }],
    });
  });

  it("filters by server", () => {
    const path = fixture([
      rec({ server: "files", tool: "read_file" }),
      rec({ server: "other", tool: "read_file", decision: "deny", reason: "nope" }),
    ]);
    const s = summarizeAudit(path, { server: "files" });
    expect(s.totals.calls).toBe(1);
    expect(s.totals.denied).toBe(0);
  });

  it("throws on an empty log and on a log with no usable records", () => {
    expect(() => summarizeAudit(fixture([""]))).toThrow(AuditError);
    expect(() =>
      summarizeAudit(fixture(['{"server": "files"}', "garbage"]))
    ).toThrow(AuditError);
  });

  it("throws on an unreadable path", () => {
    expect(() => summarizeAudit(join(tmpdir(), "mcpguard-nope.jsonl"))).toThrow(
      AuditError
    );
  });

  it("table output reports denials and flags without repeating arguments", () => {
    const path = fixture([
      rec({ tool: "read_file", args: { path: "/safe/a.txt" } }),
      rec({ tool: "delete_file", decision: "deny", reason: "denied by policy" }),
      rec({
        tool: "read_file",
        injectionFlags: ["reveal the system prompt"],
      }),
    ]);
    const table = formatAuditTable(summarizeAudit(path));
    expect(table).toContain("3 call(s), 2 allowed, 1 denied");
    expect(table).toContain("1 × denied by policy");
    expect(table).toContain("files/delete_file");
    expect(table).toContain("1 × reveal the system prompt");
    expect(table).not.toContain("/safe/a.txt");
    expect(table).not.toContain("budget trips");
  });

  it("table output reports budget trips when a call tripped the circuit", () => {
    const path = fixture([
      rec({
        tool: "read_file",
        budgetTrip: "budget exceeded: max 1024 result bytes per session",
        resultBytes: 2048,
      }),
      rec({
        tool: "read_file",
        decision: "deny",
        reason: "circuit tripped: budget exceeded: max 1024 result bytes per session",
      }),
    ]);
    const s = summarizeAudit(path);
    expect(s.totals.budgetTrips).toBe(1);
    expect(formatAuditTable(s)).toContain("budget trips: 1");
  });
});
