import { createInterface } from "node:readline";
import { createReadStream, createWriteStream } from "node:fs";

/**
 * Interactive approval for the mcp-guard gateway.
 *
 * A policy rule with action "approval" pauses the proxied `tools/call`
 * and asks the operator — on the controlling terminal (/dev/tty), never
 * on the proxy's stdin/stdout, so the JSON-RPC stream stays clean —
 * whether this call may proceed.
 *
 * Answers:
 *   y / yes    allow this call only
 *   a / always allow this tool for the rest of the session
 *   n / no     deny this call only
 *   x / never  deny this tool for the rest of the session
 *
 * Anything else (timeout, EOF, no terminal) fails closed: deny.
 */

export type ApprovalAnswer = "once" | "always" | "deny-once" | "never";

/** Parse one line of operator input. Returns null for unrecognized input. */
export function parseApprovalAnswer(input: string): ApprovalAnswer | null {
  switch (input.trim().toLowerCase()) {
    case "y":
    case "yes":
    case "once":
      return "once";
    case "a":
    case "always":
      return "always";
    case "n":
    case "no":
      return "deny-once";
    case "x":
    case "never":
      return "never";
    default:
      return null;
  }
}

export interface ApprovalOutcome {
  allowed: boolean;
  /** Human-readable reason, recorded in the audit log. */
  reason: string;
}

export interface ApproverOptions {
  /** Milliseconds to wait for the operator before denying. Default: 60000. */
  timeoutMs?: number;
  /**
   * Injected prompt for tests. Receives the full prompt text and resolves
   * with one line of operator input, or null on EOF/no terminal.
   */
  prompt?: (text: string) => Promise<string | null>;
}

export interface Approver {
  ask(server: string, tool: string, args: unknown): Promise<ApprovalOutcome>;
}

function summarizeArgs(args: unknown): string {
  try {
    const s = JSON.stringify(args);
    return s.length > 500 ? s.slice(0, 497) + "..." : s;
  } catch {
    return "[unserializable]";
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("approval timed out")), ms);
    timer.unref?.();
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      }
    );
  });
}

/**
 * Default prompt: ask on the controlling terminal. The gateway's stdin is
 * the MCP client's JSON-RPC pipe, so prompting there would corrupt the
 * stream; /dev/tty reaches the operator's terminal instead. Resolves null
 * when there is no terminal (e.g. the gateway was spawned by a client) —
 * the caller fails closed.
 */
function ttyPrompt(text: string): Promise<string | null> {
  return new Promise((resolve) => {
    let ttyIn: ReturnType<typeof createReadStream>;
    let ttyOut: ReturnType<typeof createWriteStream>;
    try {
      ttyIn = createReadStream("/dev/tty");
      ttyOut = createWriteStream("/dev/tty");
    } catch {
      resolve(null);
      return;
    }
    const done = (value: string | null): void => {
      try {
        ttyIn.destroy();
      } catch {
        // Already closed.
      }
      resolve(value);
    };
    ttyOut.write(text);
    const rl = createInterface({ input: ttyIn, output: ttyOut, terminal: true });
    rl.question("", (answer) => {
      rl.close();
      done(answer);
    });
    rl.on("close", () => done(null));
    ttyIn.on("error", () => done(null));
  });
}

export function createApprover(opts: ApproverOptions = {}): Approver {
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const prompt = opts.prompt ?? ttyPrompt;
  /** Session-scoped "always"/"never" decisions, keyed `server/tool`. */
  const remembered = new Map<string, boolean>();

  return {
    async ask(server: string, tool: string, args: unknown): Promise<ApprovalOutcome> {
      const key = `${server}/${tool}`;
      const cached = remembered.get(key);
      if (cached !== undefined) {
        return cached
          ? {
              allowed: true,
              reason: `tool "${tool}" auto-approved (operator chose "always" this session)`,
            }
          : {
              allowed: false,
              reason: `tool "${tool}" auto-denied (operator chose "never" this session)`,
            };
      }

      const question =
        `[mcp-guard] Approve tools/call "${tool}" on server "${server}"?\n` +
        `  args: ${summarizeArgs(args)}\n` +
        `  [y]es once / [a]lways allow this tool / [n]o / ne[x]ver allow this tool ` +
        `(timeout ${Math.round(timeoutMs / 1000)}s, default deny): `;

      let line: string | null;
      try {
        line = await withTimeout(prompt(question), timeoutMs);
      } catch {
        return {
          allowed: false,
          reason: `approval for tool "${tool}" timed out after ${timeoutMs}ms (deny)`,
        };
      }
      if (line === null) {
        return {
          allowed: false,
          reason: `approval for tool "${tool}" unavailable: no terminal (deny)`,
        };
      }

      switch (parseApprovalAnswer(line)) {
        case "once":
          return {
            allowed: true,
            reason: `tool "${tool}" approved by operator (interactive)`,
          };
        case "always":
          remembered.set(key, true);
          return {
            allowed: true,
            reason: `tool "${tool}" approved by operator (interactive; remembered for session)`,
          };
        case "never":
          remembered.set(key, false);
          return {
            allowed: false,
            reason: `tool "${tool}" denied by operator (interactive; remembered for session)`,
          };
        case "deny-once":
        default:
          return {
            allowed: false,
            reason: `tool "${tool}" denied by operator (interactive)`,
          };
      }
    },
  };
}
