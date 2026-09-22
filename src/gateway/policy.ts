import { readFileSync } from "node:fs";
import type { BudgetLimits } from "./budgets.js";

/**
 * Policy engine for the mcp-guard gateway.
 *
 * A policy decides, per MCP server and tool, whether a `tools/call`
 * is allowed — and constrains the arguments it may carry.
 *
 * Policy file (JSON):
 * {
 *   "version": 1,
 *   "defaultAction": "deny",
 *   "auditLog": "./mcpguard-audit.jsonl",
 *   "logArgs": true,
 *   "servers": {
 *     "files": {
 *       "defaultAction": "deny",
 *       "tools": {
 *         "read_file": {
 *           "action": "allow",
 *           "args": { "path": { "pattern": "^/safe/" } },
 *           "redactArgs": ["token"]
 *         },
 *         "delete_file": "deny",
 *         "*": "deny"
 *       }
 *     }
 *   }
 * }
 */

export type PolicyAction = "allow" | "deny" | "approval";

export interface ArgConstraint {
  /** Regex the stringified value must match. */
  pattern?: string;
  /** Allowed values. */
  enum?: Array<string | number | boolean>;
  /** Max length of the stringified value. */
  maxLength?: number;
  /** Fail when the argument is missing. */
  required?: boolean;
}

export interface ToolRule {
  action: PolicyAction;
  args?: Record<string, ArgConstraint>;
  /** Argument names to redact in the audit log. */
  redactArgs?: string[];
}

export type ToolPolicyEntry = ToolRule | PolicyAction;

export interface ServerPolicy {
  /** Fallback for tools not listed; defaults to the root defaultAction. */
  defaultAction?: PolicyAction;
  tools?: Record<string, ToolPolicyEntry>;
}

export interface GatewayPolicy {
  version: 1;
  defaultAction: PolicyAction;
  /** Where the JSONL audit log goes. Default: ./mcpguard-audit.jsonl */
  auditLog?: string;
  /** Include (redacted) arguments in the audit log. Default: true. */
  logArgs?: boolean;
  /** Session budgets: maxCalls, maxResultBytes, maxSessionMs. */
  budgets?: BudgetLimits;
  servers?: Record<string, ServerPolicy>;
}

export interface Decision {
  action: "allow" | "deny";
  reason: string;
  redactArgs: string[];
}

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

const ACTIONS: PolicyAction[] = ["allow", "deny", "approval"];

function assertAction(value: unknown, where: string): asserts value is PolicyAction {
  if (typeof value !== "string" || !ACTIONS.includes(value as PolicyAction)) {
    throw new PolicyError(`${where}: action must be one of ${ACTIONS.join(", ")}`);
  }
}

/** Load and minimally validate a policy file. Throws PolicyError. */
export function loadPolicy(path: string): GatewayPolicy {
  let raw: string;
  try {
    raw = readFileSync(path, "utf-8");
  } catch {
    throw new PolicyError(`cannot read policy file: ${path}`);
  }
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new PolicyError(`policy file is not valid JSON: ${path}`);
  }
  if (typeof data !== "object" || data === null) {
    throw new PolicyError(`policy file must contain a JSON object: ${path}`);
  }
  const p = data as Record<string, unknown>;
  if (p["version"] !== 1) throw new PolicyError(`unsupported policy version (want 1): ${path}`);
  assertAction(p["defaultAction"], "defaultAction");
  if (p["budgets"] !== undefined) {
    const b = p["budgets"];
    if (typeof b !== "object" || b === null) {
      throw new PolicyError(`budgets must be an object: ${path}`);
    }
    for (const [key, value] of Object.entries(b as Record<string, unknown>)) {
      if (!["maxCalls", "maxResultBytes", "maxSessionMs"].includes(key)) {
        throw new PolicyError(`budgets: unknown budget "${key}": ${path}`);
      }
      if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
        throw new PolicyError(`budgets: "${key}" must be a positive number: ${path}`);
      }
    }
  }
  if (p["servers"] !== undefined && (typeof p["servers"] !== "object" || p["servers"] === null)) {
    throw new PolicyError(`servers must be an object: ${path}`);
  }
  return data as GatewayPolicy;
}

function normalizeEntry(entry: ToolPolicyEntry | undefined): ToolRule | undefined {
  if (entry === undefined) return undefined;
  if (typeof entry === "string") {
    assertAction(entry, "tool entry");
    return { action: entry };
  }
  assertAction(entry.action, "tool entry");
  return entry;
}

function checkArgs(
  rule: ToolRule,
  args: Record<string, unknown>
): { ok: true } | { ok: false; reason: string } {
  if (!rule.args) return { ok: true };
  for (const [name, c] of Object.entries(rule.args)) {
    const value = args[name];
    if (value === undefined || value === null) {
      if (c.required) return { ok: false, reason: `argument "${name}" is required` };
      continue;
    }
    const str = typeof value === "string" ? value : JSON.stringify(value);
    if (c.pattern !== undefined) {
      let re: RegExp;
      try {
        re = new RegExp(c.pattern);
      } catch {
        return { ok: false, reason: `invalid pattern for argument "${name}"` };
      }
      if (!re.test(str)) {
        return { ok: false, reason: `argument "${name}" violates allowed pattern` };
      }
    }
    if (c.enum !== undefined && !c.enum.some((v) => v === value)) {
      return { ok: false, reason: `argument "${name}" is not an allowed value` };
    }
    if (c.maxLength !== undefined && str.length > c.maxLength) {
      return {
        ok: false,
        reason: `argument "${name}" exceeds max length ${c.maxLength}`,
      };
    }
  }
  return { ok: true };
}

/**
 * Decide whether `tool` may be called on `server` with `args`.
 * Deny always wins; unknown tools fall back to defaultAction.
 */
export function decide(
  policy: GatewayPolicy,
  server: string,
  tool: string,
  args: unknown
): Decision {
  const serverPolicy = policy.servers?.[server];
  const entry = serverPolicy?.tools?.[tool] ?? serverPolicy?.tools?.["*"];
  const rule = normalizeEntry(entry);
  const action: PolicyAction =
    rule?.action ?? serverPolicy?.defaultAction ?? policy.defaultAction;

  if (action === "deny") {
    return {
      action: "deny",
      reason: `tool "${tool}" is denied by policy`,
      redactArgs: rule?.redactArgs ?? [],
    };
  }
  if (action === "approval") {
    return {
      action: "deny",
      reason: `tool "${tool}" requires approval (non-interactive gateway denies)`,
      redactArgs: rule?.redactArgs ?? [],
    };
  }
  const argMap =
    typeof args === "object" && args !== null ? (args as Record<string, unknown>) : {};
  const checked = rule ? checkArgs(rule, argMap) : { ok: true as const };
  if (!checked.ok) {
    return { action: "deny", reason: checked.reason, redactArgs: rule?.redactArgs ?? [] };
  }
  return { action: "allow", reason: "allowed by policy", redactArgs: rule?.redactArgs ?? [] };
}
