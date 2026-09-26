import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "dist", "cli.js");

function scan(config: string, extra: string[] = []) {
  try {
    const out = execFileSync(
      "node",
      [cli, "scan", "--config", join(root, config), "--no-network", ...extra],
      { encoding: "utf-8" }
    );
    return { code: 0, out };
  } catch (err: any) {
    return { code: err.status ?? 99, out: String(err.stdout ?? "") + String(err.stderr ?? "") };
  }
}

describe("cli", () => {
  it("flags the vulnerable example and exits 1", () => {
    const { code, out } = scan("examples/vulnerable.mcp.json");
    expect(code).toBe(1);
    expect(out).toContain("[CRITICAL] risky-stdio-command");
    expect(out).toContain("[HIGH] hardcoded-secret");
    expect(out).toContain("[HIGH] no-auth");
    expect(out).toContain("[MEDIUM] wildcard-bind");
    // the fake token must never appear in output
    expect(out).not.toContain("ghp_000000000000000000000000000000000000");
  });

  it("passes the clean example with exit 0", () => {
    const { code, out } = scan("examples/clean.mcp.json");
    expect(code).toBe(0);
    expect(out).toContain("Clean");
  });

  it("supports --format json", () => {
    const { out } = scan("examples/clean.mcp.json", ["--format", "json"]);
    expect(JSON.parse(out).servers).toEqual(["internal-api", "local-docs"]);
  });

  it("errors with exit 2 on a missing config", () => {
    expect(scan("examples/nope.json").code).toBe(2);
  });

  it("learn emits a deny-by-default policy from an audit log", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpguard-learn-cli-"));
    const auditPath = join(dir, "audit.jsonl");
    writeFileSync(
      auditPath,
      [
        JSON.stringify({ ts: "2026-09-26T09:00:00Z", server: "files", tool: "read_file", decision: "allow", reason: "t" }),
        JSON.stringify({ ts: "2026-09-26T09:00:01Z", server: "files", tool: "delete_file", decision: "deny", reason: "t" }),
      ].join("\n")
    );
    const out = execFileSync("node", [cli, "learn", "--audit", auditPath], {
      encoding: "utf-8",
    });
    const policy = JSON.parse(out);
    expect(policy.defaultAction).toBe("deny");
    expect(policy.servers.files.tools).toEqual({ read_file: "allow", delete_file: "deny" });
  });

  it("learn exits 1 on an unreadable audit log", () => {
    try {
      execFileSync("node", [cli, "learn", "--audit", join(tmpdir(), "nope.jsonl")], {
        encoding: "utf-8",
        stdio: ["ignore", "pipe", "pipe"],
      });
      expect.unreachable("should have exited nonzero");
    } catch (err: any) {
      expect(err.status).toBe(1);
      expect(String(err.stderr ?? "")).toContain("error:");
    }
  });

  it("learn requires --audit", () => {
    try {
      execFileSync("node", [cli, "learn"], { encoding: "utf-8" });
      expect.unreachable("should have exited nonzero");
    } catch (err: any) {
      expect(err.status).toBe(2);
    }
  });
});
