import { describe, expect, it } from "vitest";
import { writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decide, loadPolicy, PolicyError, type GatewayPolicy } from "../src/gateway/policy.js";

const base: GatewayPolicy = {
  version: 1,
  defaultAction: "deny",
  servers: {
    files: {
      defaultAction: "deny",
      tools: {
        read_file: {
          action: "allow",
          args: { path: { pattern: "^/safe/", maxLength: 64 } },
          redactArgs: ["token"],
        },
        delete_file: "deny",
        exec: { action: "approval" },
      },
    },
  },
};

function tmpPolicy(contents: string): string {
  const p = join(tmpdir(), `mcpguard-policy-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(p, contents);
  return p;
}

describe("loadPolicy", () => {
  it("loads a valid policy", () => {
    const p = loadPolicy(tmpPolicy(JSON.stringify(base)));
    expect(p.version).toBe(1);
    expect(p.defaultAction).toBe("deny");
  });

  it("rejects unreadable files", () => {
    expect(() => loadPolicy("/does/not/exist.json")).toThrow(PolicyError);
  });

  it("rejects invalid JSON", () => {
    expect(() => loadPolicy(tmpPolicy("{nope"))).toThrow(PolicyError);
  });

  it("rejects unsupported versions", () => {
    expect(() => loadPolicy(tmpPolicy(JSON.stringify({ ...base, version: 2 })))).toThrow(
      PolicyError
    );
  });

  it("rejects unknown default actions", () => {
    expect(() =>
      loadPolicy(tmpPolicy(JSON.stringify({ ...base, defaultAction: "maybe" })))
    ).toThrow(PolicyError);
  });

  it("accepts valid budgets and rejects bad ones", () => {
    const withBudgets = tmpPolicy(
      JSON.stringify({ ...base, budgets: { maxCalls: 10, maxResultBytes: 1024 } })
    );
    expect(loadPolicy(withBudgets).budgets).toEqual({ maxCalls: 10, maxResultBytes: 1024 });
    expect(() =>
      loadPolicy(tmpPolicy(JSON.stringify({ ...base, budgets: { maxCalls: -1 } })))
    ).toThrow(PolicyError);
    expect(() =>
      loadPolicy(tmpPolicy(JSON.stringify({ ...base, budgets: { maxTokens: 5 } })))
    ).toThrow(PolicyError);
  });
});

describe("decide", () => {
  it("allows a listed tool with conforming args", () => {
    const d = decide(base, "files", "read_file", { path: "/safe/notes.txt" });
    expect(d.action).toBe("allow");
    expect(d.redactArgs).toEqual(["token"]);
  });

  it("denies unknown tools under a deny default", () => {
    const d = decide(base, "files", "format_disk", {});
    expect(d.action).toBe("deny");
    expect(d.reason).toContain("format_disk");
  });

  it("denies explicitly denied tools", () => {
    expect(decide(base, "files", "delete_file", {}).action).toBe("deny");
  });

  it("denies tools that require approval (non-interactive)", () => {
    const d = decide(base, "files", "exec", { command: "ls" });
    expect(d.action).toBe("deny");
    expect(d.reason).toContain("approval");
  });

  it("denies when an argument violates its pattern", () => {
    const d = decide(base, "files", "read_file", { path: "/etc/passwd" });
    expect(d.action).toBe("deny");
    expect(d.reason).toContain("pattern");
  });

  it("denies when an argument exceeds maxLength", () => {
    const d = decide(base, "files", "read_file", { path: "/safe/" + "x".repeat(100) });
    expect(d.action).toBe("deny");
    expect(d.reason).toContain("max length");
  });

  it("denies when a required argument is missing", () => {
    const policy: GatewayPolicy = {
      version: 1,
      defaultAction: "allow",
      servers: {
        s: { tools: { t: { action: "allow", args: { q: { required: true } } } } },
      },
    };
    expect(decide(policy, "s", "t", {}).action).toBe("deny");
  });

  it("enforces enum constraints", () => {
    const policy: GatewayPolicy = {
      version: 1,
      defaultAction: "allow",
      servers: {
        s: { tools: { t: { action: "allow", args: { mode: { enum: ["r", "w"] } } } } },
      },
    };
    expect(decide(policy, "s", "t", { mode: "r" }).action).toBe("allow");
    expect(decide(policy, "s", "t", { mode: "x" }).action).toBe("deny");
  });

  it("falls back to the root defaultAction for unlisted servers", () => {
    const allow: GatewayPolicy = { version: 1, defaultAction: "allow" };
    expect(decide(allow, "unknown", "anything", {}).action).toBe("allow");
    expect(decide(base, "unknown", "anything", {}).action).toBe("deny");
  });

  it("honors the wildcard tool entry", () => {
    const policy: GatewayPolicy = {
      version: 1,
      defaultAction: "deny",
      servers: { s: { tools: { "*": "allow" } } },
    };
    expect(decide(policy, "s", "whatever", {}).action).toBe("allow");
  });
});
