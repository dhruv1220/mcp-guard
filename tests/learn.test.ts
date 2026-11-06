import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { learnPolicy, LearnError } from "../src/learn.js";

function writeAudit(dir: string, lines: string[]): string {
  const path = join(dir, "audit.jsonl");
  writeFileSync(path, lines.join("\n"));
  return path;
}

const rec = (server: string, tool: string, decision: "allow" | "deny", reason = "test") =>
  JSON.stringify({
    ts: "2026-09-26T09:00:00.000Z",
    server,
    tool,
    decision,
    reason,
  });

describe("learnPolicy", () => {
  it("emits deny-by-default with allowed tools allow and always-denied tools deny", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpguard-learn-"));
    const path = writeAudit(dir, [
      rec("files", "read_file", "allow"),
      rec("files", "read_file", "allow"),
      rec("files", "delete_file", "deny"),
      rec("files", "delete_file", "deny"),
    ]);
    const policy = learnPolicy(path);
    expect(policy.version).toBe(1);
    expect(policy.defaultAction).toBe("deny");
    expect(policy.servers?.["files"]?.tools).toEqual({
      read_file: "allow",
      delete_file: "deny",
    });
  });

  it("lets the latest decision win: deny then allow learns allow", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpguard-learn-"));
    const path = writeAudit(dir, [
      rec("files", "read_file", "deny"),
      rec("files", "read_file", "allow"),
    ]);
    expect(learnPolicy(path).servers?.["files"]?.tools?.["read_file"]).toBe("allow");
  });

  it("lets the latest decision win: allow then deny learns deny", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpguard-learn-"));
    const path = writeAudit(dir, [
      rec("files", "exec", "allow"),
      rec("files", "exec", "allow"),
      rec("files", "exec", "deny"),
    ]);
    expect(learnPolicy(path).servers?.["files"]?.tools?.["exec"]).toBe("deny");
  });

  it("ignores denials caused by a tripped budget", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpguard-learn-"));
    const path = writeAudit(dir, [
      rec("files", "read_file", "allow"),
      rec(
        "files",
        "read_file",
        "deny",
        "circuit tripped: budget exceeded: max 2 tool calls per session"
      ),
    ]);
    expect(learnPolicy(path).servers?.["files"]?.tools?.["read_file"]).toBe("allow");
  });

  it("throws when the log holds only budget denials", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpguard-learn-"));
    const path = writeAudit(dir, [
      rec("files", "read_file", "deny", "circuit tripped: budget exceeded: max 2 tool calls"),
    ]);
    expect(() => learnPolicy(path)).toThrow(LearnError);
  });

  it("filters by server and keeps each server separate", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpguard-learn-"));
    const path = writeAudit(dir, [
      rec("files", "read_file", "allow"),
      rec("git", "status", "allow"),
      rec("git", "push", "deny"),
    ]);
    const policy = learnPolicy(path, { server: "git" });
    expect(Object.keys(policy.servers ?? {})).toEqual(["git"]);
    expect(policy.servers?.["git"]?.tools).toEqual({ status: "allow", push: "deny" });
  });

  it("tolerates corrupt lines and ignores non-audit records", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpguard-learn-"));
    const path = writeAudit(dir, [
      rec("files", "read_file", "allow"),
      "{not json",
      "",
      JSON.stringify({ ts: "x", note: "heartbeat, not an audit record" }),
      JSON.stringify({ ts: "x", server: "files", tool: "x", decision: "maybe" }),
    ]);
    const policy = learnPolicy(path);
    expect(policy.servers?.["files"]?.tools).toEqual({ read_file: "allow" });
  });

  it("throws LearnError on a missing file and on an empty log", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpguard-learn-"));
    expect(() => learnPolicy(join(dir, "nope.jsonl"))).toThrow(LearnError);
    const empty = writeAudit(dir, ["", "  "]);
    expect(() => learnPolicy(empty)).toThrow(LearnError);
  });
});
