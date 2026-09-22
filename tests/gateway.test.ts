import { describe, expect, it } from "vitest";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "dist", "cli.js");
const fixture = join(root, "tests", "fixtures", "fake-mcp-server.mjs");

function launchGateway(policyPath: string, callsLog: string) {
  const proc: ChildProcess = spawn(
    "node",
    [cli, "gateway", "--policy", policyPath, "--server", "fake", "--", "node", fixture, callsLog],
    { stdio: ["pipe", "pipe", "pipe"] }
  );
  const waiters = new Map<string | number, (msg: any) => void>();
  let buf = "";
  proc.stdout!.setEncoding("utf8");
  proc.stdout!.on("data", (chunk: string) => {
    buf += chunk;
    let idx: number;
    while ((idx = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      if (!line.trim()) continue;
      const msg = JSON.parse(line);
      if (msg.id !== undefined && msg.id !== null) {
        const w = waiters.get(msg.id);
        if (w) {
          waiters.delete(msg.id);
          w(msg);
        }
      }
    }
  });
  let nextId = 1;
  const send = (method: string, params: unknown): Promise<any> => {
    const id = nextId++;
    return new Promise<any>((resolve, reject) => {
      const timer = setTimeout(() => {
        waiters.delete(id);
        reject(new Error(`timeout waiting for ${method} response`));
      }, 8000);
      waiters.set(id, (msg) => {
        clearTimeout(timer);
        resolve(msg);
      });
      proc.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  };
  return { proc, send };
}

describe("gateway", () => {
  it("proxies a session: allows, denies, and audits every tools/call", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpguard-gw-"));
    const callsLog = join(dir, "calls.log");
    const auditLog = join(dir, "audit.jsonl");
    const policyPath = join(dir, "policy.json");
    writeFileSync(
      policyPath,
      JSON.stringify({
        version: 1,
        defaultAction: "deny",
        auditLog,
        logArgs: true,
        servers: {
          fake: {
            tools: {
              read_file: { action: "allow", args: { path: { pattern: "^/safe/" } } },
              delete_file: "deny",
            },
          },
        },
      })
    );

    const { proc, send } = launchGateway(policyPath, callsLog);

    const init = await send("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "test", version: "0" },
    });
    expect(init.result.serverInfo.name).toBe("fake-mcp");

    const list = await send("tools/list", {});
    expect(list.result.tools.map((t: any) => t.name).sort()).toEqual([
      "delete_file",
      "read_file",
    ]);

    const ok = await send("tools/call", {
      name: "read_file",
      arguments: { path: "/safe/a.txt" },
    });
    expect(ok.result.content[0].text).toBe("FILE_CONTENTS");

    const denied = await send("tools/call", {
      name: "delete_file",
      arguments: { path: "/safe/a.txt" },
    });
    expect(denied.error.code).toBe(-32602);
    expect(denied.error.message).toContain("mcp-guard");

    const deniedArgs = await send("tools/call", {
      name: "read_file",
      arguments: { path: "/etc/passwd" },
    });
    expect(deniedArgs.error.code).toBe(-32602);
    expect(deniedArgs.error.message).toContain("pattern");

    // The real server only ever saw the allowed call.
    const seen = readFileSync(callsLog, "utf-8").trim().split("\n");
    expect(seen).toEqual(["read_file"]);

    proc.stdin!.end();
    await new Promise<void>((resolve) => proc.on("exit", () => resolve()));
    expect(proc.exitCode).toBe(0);

    const records = readFileSync(auditLog, "utf-8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    const decisions = records.map((r) => [r.tool, r.decision]);
    expect(decisions).toContainEqual(["read_file", "allow"]);
    expect(decisions).toContainEqual(["delete_file", "deny"]);
    const allowRec = records.find((r) => r.decision === "allow");
    expect(typeof allowRec.durationMs).toBe("number");
    expect(typeof allowRec.resultBytes).toBe("number");
    expect(records.every((r) => typeof r.ts === "string")).toBe(true);
  }, 25000);

  it("enforces session budgets: trips the circuit after maxCalls", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpguard-budget-"));
    const callsLog = join(dir, "calls.log");
    const auditLog = join(dir, "audit.jsonl");
    const policyPath = join(dir, "policy.json");
    writeFileSync(
      policyPath,
      JSON.stringify({
        version: 1,
        defaultAction: "deny",
        auditLog,
        budgets: { maxCalls: 2 },
        servers: {
          fake: { tools: { read_file: "allow" } },
        },
      })
    );

    const { proc, send } = launchGateway(policyPath, callsLog);
    const call = () =>
      send("tools/call", { name: "read_file", arguments: { path: "/safe/a.txt" } });

    expect((await call()).result.content[0].text).toBe("FILE_CONTENTS");
    expect((await call()).result.content[0].text).toBe("FILE_CONTENTS");
    const blocked = await call();
    expect(blocked.error.code).toBe(-32602);
    expect(blocked.error.message).toContain("budget exceeded");

    const seen = readFileSync(callsLog, "utf-8").trim().split("\n");
    expect(seen).toEqual(["read_file", "read_file"]);

    proc.stdin!.end();
    await new Promise<void>((resolve) => proc.on("exit", () => resolve()));

    const records = readFileSync(auditLog, "utf-8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    const budgetDenies = records.filter(
      (r) => r.decision === "deny" && r.reason.includes("budget exceeded")
    );
    expect(budgetDenies).toHaveLength(1);
  }, 25000);

  it("exits 2 when required gateway options are missing", () => {
    const run = (args: string[]) => {
      try {
        execFileSync("node", [cli, ...args], { encoding: "utf-8" });
        return 0;
      } catch (err: any) {
        return err.status ?? 99;
      }
    };
    expect(run(["gateway"])).toBe(2);
    expect(run(["gateway", "--policy", "x"])).toBe(2);
    expect(run(["gateway", "--policy", "x", "--server", "y"])).toBe(2);
  });
});
