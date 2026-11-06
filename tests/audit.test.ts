import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAuditor, redactArgsForLog } from "../src/gateway/audit.js";

function tmpLog(): string {
  return join(tmpdir(), `mcpguard-audit-${Date.now()}-${Math.random().toString(36).slice(2)}.jsonl`);
}

describe("redactArgsForLog", () => {
  it("redacts explicitly listed keys", () => {
    expect(redactArgsForLog({ token: "abc", path: "/safe/a" }, ["token"])).toEqual({
      token: "[redacted]",
      path: "/safe/a",
    });
  });

  it("redacts values that look like secrets", () => {
    const out = redactArgsForLog(
      { key: "sk-live-abcdefghijklmnop", normal: "hello" },
      []
    );
    expect(out.key).toBe("[redacted]");
    expect(out.normal).toBe("hello");
  });

  it("redacts nested secrets", () => {
    const out = redactArgsForLog({ nested: { password: "hunter2-hunter2" } }, []);
    expect(out.nested).toEqual({ password: "[redacted]" });
  });

  it("redacts credentialed URLs inside string values", () => {
    const out = redactArgsForLog(
      { url: "https://admin:s3cret@internal/mcp", other: "https://example.com/x" },
      []
    );
    expect(out.url).toBe("https://•••@internal/mcp");
    expect(out.other).toBe("https://example.com/x");
    expect(JSON.stringify(out)).not.toContain("s3cret");
  });

  it("redacts credential query params inside string values", () => {
    // Short trailing token: does not trip the whole-value secret
    // heuristic, so the surgical query-param redaction is what fires.
    const out = redactArgsForLog(
      { url: "https://example.com/mcp?mode=fast&api_key=abc123" },
      []
    );
    expect(out.url).toBe("https://example.com/mcp?mode=fast&api_key=•••");
    expect(JSON.stringify(out)).not.toContain("abc123");
  });

  it("redacts the whole value when a query token is long", () => {
    // The whole-value secret heuristic fires first for long tokens, so
    // the URL is redacted wholesale rather than surgically — still no
    // credential in the output, just less context.
    const out = redactArgsForLog(
      { url: "https://example.com/mcp?api_key=sk-ant-abc123456" },
      []
    );
    expect(out.url).toBe("[redacted]");
    expect(JSON.stringify(out)).not.toContain("sk-ant-abc123456");
  });

  it("redacts credentialed URLs nested in objects", () => {
    const out = redactArgsForLog(
      { opts: { endpoint: "https://user:token123@host/i" } },
      []
    );
    expect(out.opts).toEqual({ endpoint: "https://•••@host/i" });
  });

  it("leaves ordinary values alone", () => {
    const args = { path: "/safe/notes.txt", limit: 10, flag: true };
    expect(redactArgsForLog(args, [])).toEqual(args);
  });
});

describe("createAuditor", () => {
  it("appends JSONL records with a timestamp", () => {
    const path = tmpLog();
    const auditor = createAuditor(path, true);
    auditor.log({
      server: "files",
      tool: "read_file",
      decision: "allow",
      reason: "allowed by policy",
      durationMs: 12,
      resultBytes: 42,
    });
    const [line] = readFileSync(path, "utf-8").trim().split("\n");
    const rec = JSON.parse(line!);
    expect(rec.server).toBe("files");
    expect(rec.tool).toBe("read_file");
    expect(rec.decision).toBe("allow");
    expect(rec.durationMs).toBe(12);
    expect(typeof rec.ts).toBe("string");
  });

  it("omits args when logArgs is false", () => {
    const path = tmpLog();
    const auditor = createAuditor(path, false);
    auditor.log({
      server: "files",
      tool: "read_file",
      decision: "allow",
      reason: "allowed by policy",
      args: { path: "/safe/a" },
    });
    const rec = JSON.parse(readFileSync(path, "utf-8").trim());
    expect(rec.args).toBeUndefined();
  });
});
