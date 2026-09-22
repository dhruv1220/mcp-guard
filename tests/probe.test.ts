import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "dist", "cli.js");
const fixture = join(root, "tests", "fixtures", "fake-mcp-server.mjs");

function probe(extra: string[] = []): { code: number; out: string } {
  try {
    const out = execFileSync(
      "node",
      [cli, "probe", ...extra, "--", "node", fixture],
      { encoding: "utf-8", timeout: 20000 }
    );
    return { code: 0, out };
  } catch (err: any) {
    return { code: err.status ?? 99, out: String(err.stdout ?? "") + String(err.stderr ?? "") };
  }
}

describe("probe", () => {
  it("enumerates the fake server's tool surface as JSON", () => {
    const { code, out } = probe();
    expect(code).toBe(0);
    const result = JSON.parse(out);
    expect(result.serverInfo.name).toBe("fake-mcp");
    expect(result.protocolVersion).toBe("2024-11-05");
    expect(result.tools.map((t: any) => t.name).sort()).toEqual([
      "delete_file",
      "read_file",
      "sneaky_tool",
    ]);
    expect(result.tools[0].description).toBeTruthy();
    expect(typeof result.durationMs).toBe("number");
  });

  it("exits 2 when the server command is missing", () => {
    expect(probe().code).not.toBe(2); // sanity: the success case above isn't 2
    try {
      execFileSync("node", [cli, "probe"], { encoding: "utf-8" });
      expect.unreachable("should have exited non-zero");
    } catch (err: any) {
      expect(err.status).toBe(2);
    }
  });

  it("fails fast on an unstartable command", () => {
    try {
      execFileSync("node", [cli, "probe", "--", "definitely-not-a-real-binary-xyz"], {
        encoding: "utf-8",
      });
      expect.unreachable("should have exited non-zero");
    } catch (err: any) {
      expect(err.status).toBe(1);
      expect(String(err.stderr)).toContain("failed to start server");
    }
  });
});
