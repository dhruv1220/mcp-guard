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
 *   - a tool allowed at least once (by the operator or the old policy)
 *     becomes an explicit "allow";
 *   - a tool only ever denied becomes an explicit "deny";
 *   - tools never observed are omitted — the root defaultAction: deny
 *     still covers them.
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

interface ToolTally {
  allow: number;
  deny: number;
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

  const tallies = new Map<string, Map<string, ToolTally>>();
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
    let tools = tallies.get(rec.server);
    if (!tools) {
      tools = new Map();
      tallies.set(rec.server, tools);
    }
    let tally = tools.get(rec.tool);
    if (!tally) {
      tally = { allow: 0, deny: 0 };
      tools.set(rec.tool, tally);
    }
    if (rec.decision === "allow") tally.allow += 1;
    else tally.deny += 1;
  }

  if (tallies.size === 0) {
    throw new LearnError(`no usable audit records in ${auditPath}`);
  }

  const servers: GatewayPolicy["servers"] = {};
  for (const server of [...tallies.keys()].sort()) {
    const tools = tallies.get(server)!;
    const entries: Record<string, PolicyAction> = {};
    for (const tool of [...tools.keys()].sort()) {
      const tally = tools.get(tool)!;
      entries[tool] = tally.allow > 0 ? "allow" : "deny";
    }
    servers[server] = { tools: entries };
  }
  return { version: 1, defaultAction: "deny", servers };
}
