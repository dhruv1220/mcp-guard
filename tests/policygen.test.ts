import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generatePolicy } from "../src/policygen.js";
import { loadPolicy } from "../src/gateway/policy.js";
import { writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "dist", "cli.js");
const fixture = join(root, "tests", "fixtures", "fake-mcp-server.mjs");

describe("generatePolicy", () => {
  it("builds a deny-by-default policy with discovered tools as approval", () => {
    const policy = generatePolicy("demo", [
      { name: "read_file" },
      { name: "delete_file" },
    ]);
    expect(policy.version).toBe(1);
    expect(policy.defaultAction).toBe("deny");
    expect(policy.servers?.["demo"]?.tools).toEqual({
      read_file: "approval",
      delete_file: "approval",
    });
  });

  it("round-trips through the policy validator", () => {
    const policy = generatePolicy("demo", [{ name: "t" }]);
    const path = join(
      tmpdir(),
      `mcpguard-gen-${Date.now()}-${Math.random().toString(36).slice(2)}.json`
    );
    writeFileSync(path, JSON.stringify(policy));
    expect(loadPolicy(path).servers?.["demo"]?.defaultAction).toBe("deny");
  });
});

describe("init-policy", () => {
  it("prints a valid starter policy from a live probe", () => {
    const out = execFileSync(
      "node",
      [cli, "init-policy", "--server", "demo", "--", "node", fixture],
      { encoding: "utf-8", timeout: 20000 }
    );
    const policy = JSON.parse(out);
    expect(policy.defaultAction).toBe("deny");
    expect(Object.keys(policy.servers["demo"].tools).sort()).toEqual([
      "delete_file",
      "read_file",
      "sneaky_tool",
    ]);
    expect(policy.servers["demo"].tools["read_file"]).toBe("approval");
  });

  it("exits 2 when --server or the command is missing", () => {
    for (const args of [["init-policy"], ["init-policy", "--server", "x"]]) {
      try {
        execFileSync("node", [cli, ...args], { encoding: "utf-8" });
        expect.unreachable("should have exited non-zero");
      } catch (err: any) {
        expect(err.status).toBe(2);
      }
    }
  });
});
