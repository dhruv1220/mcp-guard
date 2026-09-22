import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
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
});
