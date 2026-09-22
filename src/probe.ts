import { spawn } from "node:child_process";

/**
 * Live server probing: spawn an MCP server over stdio and enumerate
 * its real tool surface (initialize -> tools/list). Useful to see what
 * a server actually exposes before writing a gateway policy for it.
 */

export interface ProbeOptions {
  command: string;
  commandArgs: string[];
  /** Overall timeout in ms. Default 15000. */
  timeoutMs?: number;
}

export interface ProbedTool {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

export interface ProbeResult {
  serverInfo?: { name?: string; version?: string };
  protocolVersion?: string;
  tools: ProbedTool[];
  durationMs: number;
}

export class ProbeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProbeError";
  }
}

type JsonRpcId = string | number;

export async function probeServer(opts: ProbeOptions): Promise<ProbeResult> {
  const timeoutMs = opts.timeoutMs ?? 15000;
  const startedAt = Date.now();

  return new Promise<ProbeResult>((resolve, reject) => {
    const child = spawn(opts.command, opts.commandArgs, {
      stdio: ["pipe", "pipe", "inherit"],
    });
    let settled = false;
    const waiters = new Map<JsonRpcId, (msg: Record<string, unknown>) => void>();
    let buf = "";
    let nextId = 1;

    const done = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        child.kill();
      } catch {
        // Ignore.
      }
      fn();
    };
    const fail = (message: string): void =>
      done(() => reject(new ProbeError(message)));

    const timer = setTimeout(() => {
      fail(`probe timed out after ${timeoutMs}ms`);
    }, timeoutMs);
    timer.unref?.();

    child.on("error", (err) => fail(`failed to start server: ${err.message}`));

    const request = (
      method: string,
      params: unknown,
      onResponse: (msg: Record<string, unknown>) => void
    ): void => {
      const id = nextId++;
      waiters.set(id, onResponse);
      child.stdin?.write(
        JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n"
      );
    };

    child.stdout?.on("data", (chunk: Buffer) => {
      buf += chunk.toString("utf8");
      let idx: number;
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx).replace(/\r$/, "");
        buf = buf.slice(idx + 1);
        if (!line) continue;
        let msg: Record<string, unknown>;
        try {
          msg = JSON.parse(line) as Record<string, unknown>;
        } catch {
          continue;
        }
        const id = msg["id"] as JsonRpcId | undefined;
        if (id === undefined || id === null) continue;
        const w = waiters.get(id);
        if (w) {
          waiters.delete(id);
          w(msg);
        }
      }
    });

    const result: ProbeResult = { tools: [], durationMs: 0 };

    request(
      "initialize",
      {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "mcp-guard-probe", version: "0.1.0" },
      },
      (initMsg) => {
        if (initMsg["error"]) {
          fail(`initialize failed: ${JSON.stringify(initMsg["error"])}`);
          return;
        }
        const initResult = (initMsg["result"] ?? {}) as Record<string, unknown>;
        result.protocolVersion = initResult["protocolVersion"] as string | undefined;
        result.serverInfo = (initResult["serverInfo"] ?? undefined) as
          | { name?: string; version?: string }
          | undefined;
        // Per MCP spec, acknowledge initialization before other requests.
        child.stdin?.write(
          JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n"
        );
        request("tools/list", {}, (listMsg) => {
          if (listMsg["error"]) {
            fail(`tools/list failed: ${JSON.stringify(listMsg["error"])}`);
            return;
          }
          const listResult = (listMsg["result"] ?? {}) as Record<string, unknown>;
          const tools = listResult["tools"];
          result.tools = Array.isArray(tools)
            ? (tools as Record<string, unknown>[]).map((t) => ({
                name: String(t["name"] ?? ""),
                description:
                  typeof t["description"] === "string" ? t["description"] : undefined,
                inputSchema: t["inputSchema"],
              }))
            : [];
          result.durationMs = Date.now() - startedAt;
          done(() => resolve(result));
        });
      }
    );
  });
}
