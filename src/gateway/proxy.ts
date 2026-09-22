import { spawn } from "node:child_process";
import { decide, loadPolicy, type GatewayPolicy } from "./policy.js";
import { createAuditor, redactArgsForLog, type Auditor } from "./audit.js";

/**
 * Transparent enforcement proxy for one MCP server.
 *
 * Sits between an MCP client (our stdin/stdout) and the real server
 * (spawned child). Every `tools/call` request is checked against the
 * policy; denied calls get a JSON-RPC error and never reach the server.
 * Allowed calls are forwarded and timed, and every decision lands in
 * the JSONL audit log.
 *
 * Fail-closed: if the server child can't start, crashes, or the
 * policy file is invalid, no session is proxied.
 */

export interface ProxyOptions {
  policyPath: string;
  serverName: string;
  command: string;
  commandArgs: string[];
}

interface PendingCall {
  tool: string;
  args: Record<string, unknown>;
  reason: string;
  startedAt: number;
}

type JsonRpcId = string | number;

/** Split a byte stream into newline-delimited lines. */
class LineSplitter {
  private buf = "";

  push(chunk: Buffer | string, onLine: (line: string) => void): void {
    this.buf += chunk.toString("utf8");
    let idx: number;
    while ((idx = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, idx).replace(/\r$/, "");
      this.buf = this.buf.slice(idx + 1);
      if (line.length > 0) onLine(line);
    }
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {};
}

/**
 * Start the proxy session. Resolves with the process exit code when
 * the session ends (server child exits, or the client's stdin closes).
 */
export async function runProxy(opts: ProxyOptions): Promise<number> {
  return new Promise<number>((resolve) => {
    const policy: GatewayPolicy = loadPolicy(opts.policyPath);
    const auditor: Auditor = createAuditor(
      policy.auditLog ?? "./mcpguard-audit.jsonl",
      policy.logArgs ?? true
    );
    const logArgs = policy.logArgs ?? true;

    const child = spawn(opts.command, opts.commandArgs, {
      stdio: ["pipe", "pipe", "inherit"],
    });

    const pending = new Map<JsonRpcId, PendingCall>();
    const fromClient = new LineSplitter();
    const fromServer = new LineSplitter();
    let sessionEnded = false;
    /** Grace period for the server to drain in-flight work after our stdin closes. */
    const SHUTDOWN_GRACE_MS = 2000;
    let shutdownTimer: NodeJS.Timeout | undefined;

    const end = (code: number): void => {
      if (sessionEnded) return;
      sessionEnded = true;
      if (shutdownTimer) clearTimeout(shutdownTimer);
      try {
        child.kill();
      } catch {
        // Already gone.
      }
      resolve(code);
    };

    const writeStdout = (line: string): void => {
      try {
        process.stdout.write(line + "\n");
      } catch {
        end(1);
      }
    };

  child.on("error", (err) => {
    process.stderr.write(`mcp-guard: failed to start MCP server: ${err.message}\n`);
    end(1);
  });

  child.on("exit", (code, signal) => {
    if (sessionEnded) return;
    if (shutdownTimer) clearTimeout(shutdownTimer);
    if (signal) {
      process.stderr.write(`mcp-guard: MCP server killed by ${signal} (fail-closed)\n`);
    }
    end(typeof code === "number" ? code : 1);
  });

  // Client -> server: intercept tools/call requests.
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => {
    fromClient.push(chunk, (line) => {
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(line) as Record<string, unknown>;
      } catch {
        child.stdin?.write(line + "\n");
        return;
      }
      const id = msg["id"] as JsonRpcId | undefined;
      if (msg["method"] !== "tools/call" || id === undefined || id === null) {
        child.stdin?.write(line + "\n");
        return;
      }
      const params = asRecord(msg["params"]);
      const tool = String(params["name"] ?? "");
      const args = asRecord(params["arguments"]);
      const decision = decide(policy, opts.serverName, tool, args);
      const loggedArgs = logArgs ? redactArgsForLog(args, decision.redactArgs) : undefined;
      if (decision.action === "deny") {
        auditor.log({
          server: opts.serverName,
          tool,
          decision: "deny",
          reason: decision.reason,
          args: loggedArgs,
        });
        writeStdout(
          JSON.stringify({
            jsonrpc: "2.0",
            id,
            error: { code: -32602, message: `mcp-guard: ${decision.reason}` },
          })
        );
        return;
      }
      pending.set(id, {
        tool,
        args: loggedArgs ?? {},
        reason: decision.reason,
        startedAt: Date.now(),
      });
      child.stdin?.write(line + "\n");
    });
  });
  process.stdin.on("end", () => {
    try {
      child.stdin?.end();
    } catch {
      // Ignore.
    }
    // Let the server drain in-flight responses before we tear down.
    shutdownTimer = setTimeout(() => end(0), SHUTDOWN_GRACE_MS);
    shutdownTimer.unref?.();
  });
  process.stdin.resume();

  // Server -> client: forward everything; audit completed calls.
  child.stdout?.on("data", (chunk: Buffer) => {
    fromServer.push(chunk, (line) => {
      let msg: Record<string, unknown> | undefined;
      try {
        msg = JSON.parse(line) as Record<string, unknown>;
      } catch {
        // Not JSON-RPC — forward untouched.
      }
      if (msg) {
        const id = msg["id"] as JsonRpcId | undefined;
        const call = id !== undefined && id !== null ? pending.get(id) : undefined;
        if (call) {
          pending.delete(id as JsonRpcId);
          auditor.log({
            server: opts.serverName,
            tool: call.tool,
            decision: "allow",
            reason: call.reason,
            args: call.args,
            durationMs: Date.now() - call.startedAt,
            resultBytes: Buffer.byteLength(line, "utf8"),
          });
        }
      }
      writeStdout(line);
    });
  });
  });
}
