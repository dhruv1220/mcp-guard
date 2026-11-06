import { readFileSync } from "node:fs";
import type { AuditRecord } from "./gateway/audit.js";
import type { GatewayPolicy, PolicyAction } from "./gateway/policy.js";

/**
 * Learn a tightened gateway policy from an audit log.
 *
 * The intended workflow: run the gateway with a permissive starter policy
 * (`mcpguard init-policy` emits every tool as "approval"), drive it with
 * `--interactive` so the operator approves/denies each call, then run
 * `mcpguard learn --audit ./mcpguard-audit.jsonl` to emit a policy that
 * encodes what was observed:
 *
 *   - a tool whose most recent decision was "allow" (by the operator
 *     or the old policy) becomes an explicit "allow";
 *   - a tool whose most recent decision was "deny" becomes an explicit "deny";
 *   - tools never observed are omitted — the root defaultAction: deny
 *     still covers them.
 *
 * A tool's most recent genuine decision wins: an approval the operator
 * later reversed (allow, then deny) learns "deny", and a denial later
 * reversed learns "allow". Denials caused by a tripped session budget
 * are not judgments about the tool, so they are ignored — only
 * policy/operator decisions teach the policy.
 *
 * The emitted policy is always deny-by-default. Review it before deploying;
 * learning reflects what happened, not what should happen.
 */

export class LearnError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LearnError";
  }
}

export interface LearnOptions {
  /** Only learn from audit records for this server. */
  server?: string;
}

/**
 * True when the denial was caused by a tripped session budget rather
 * than a judgment about the tool. Budget denials say nothing about
 * whether the tool is safe, so learning must ignore them.
 */
function isBudgetDenial(rec: AuditRecord): boolean {
  return (
    rec.decision === "deny" &&
    typeof rec.reason === "string" &&
    (rec.reason.includes("budget exceeded") || rec.reason.includes("circuit tripped"))
  );
}

function isAuditRecord(value: unknown): value is AuditRecord {
  if (typeof value !== "object" || value === null) return false;
  const rec = value as Record<string, unknown>;
  return (
    typeof rec["server"] === "string" &&
    typeof rec["tool"] === "string" &&
    (rec["decision"] === "allow" || rec["decision"] === "deny")
  );
}

/** Read an audit log and build a deny-by-default policy from observed decisions. */
export function learnPolicy(auditPath: string, opts: LearnOptions = {}): GatewayPolicy {
  let raw: string;
  try {
    raw = readFileSync(auditPath, "utf-8");
  } catch {
    throw new LearnError(`cannot read audit log: ${auditPath}`);
  }

  // Latest genuine decision per tool, keyed server -> tool -> decision.
  // The audit log is chronological, so the last record seen for a tool
  // is the operator's (or old policy's) final word on it.
  const latest = new Map<string, Map<string, "allow" | "deny">>();
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let rec: unknown;
    try {
      rec = JSON.parse(trimmed);
    } catch {
      continue; // tolerate truncated/corrupt lines in a live log
    }
    if (!isAuditRecord(rec)) continue;
    if (opts.server && rec.server !== opts.server) continue;
    if (isBudgetDenial(rec)) continue;
    let tools = latest.get(rec.server);
    if (!tools) {
      tools = new Map();
      latest.set(rec.server, tools);
    }
    tools.set(rec.tool, rec.decision);
  }

  if (latest.size === 0) {
    throw new LearnError(`no usable audit records in ${auditPath}`);
  }

  const servers: GatewayPolicy["servers"] = {};
  for (const server of [...latest.keys()].sort()) {
    const tools = latest.get(server)!;
    const entries: Record<string, PolicyAction> = {};
    for (const tool of [...tools.keys()].sort()) {
      entries[tool] = tools.get(tool)!;
    }
    servers[server] = { tools: entries };
  }
  return { version: 1, defaultAction: "deny", servers };
}
