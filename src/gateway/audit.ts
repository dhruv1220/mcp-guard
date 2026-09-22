import { appendFileSync } from "node:fs";

/**
 * Append-only JSONL audit log for the gateway.
 * Every `tools/call` the proxy sees is recorded with its policy
 * decision; argument values are redacted (explicit redactArgs plus
 * anything that looks like a secret).
 */

export interface AuditRecord {
  ts: string;
  server: string;
  tool: string;
  decision: "allow" | "deny";
  reason: string;
  /** Redacted arguments (omitted when logArgs is false). */
  args?: Record<string, unknown>;
  /** Round-trip time in ms for allowed calls. */
  durationMs?: number;
  /** Byte size of the tool result for allowed calls. */
  resultBytes?: number;
}

const SECRET_VALUE = new RegExp(
  [
    "sk-(live|test)-[A-Za-z0-9]{16,}",
    "xox[bap]-[A-Za-z0-9-]{8,}",
    "ghp_[A-Za-z0-9]{16,}",
    "gho_[A-Za-z0-9]{16,}",
    "AKIA[0-9A-Z]{16}",
    "AIza[0-9A-Za-z_-]{16,}",
    "-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "(api[_-]?key|secret|token|password)\\s*[:=]\\s*\\S{8,}",
  ].join("|"),
  // Case-insensitive: the key-name heuristic ("api_key", "SECRET", ...) needs it.
  "i"
);

/** Argument names that almost always hold secrets, regardless of value. */
const SENSITIVE_KEY = /(api[_-]?key|secret|token|passwd|password|pwd|credential|auth)/i;

function looksSecret(value: string): boolean {
  return SECRET_VALUE.test(value);
}

/** Redact sensitive argument values; never throws. */
export function redactArgsForLog(
  args: Record<string, unknown>,
  redactKeys: string[]
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    if (redactKeys.includes(k) || SENSITIVE_KEY.test(k)) {
      out[k] = "[redacted]";
    } else if (typeof v === "string" && looksSecret(v)) {
      out[k] = "[redacted]";
    } else if (v !== null && typeof v === "object") {
      try {
        out[k] = redactArgsForLog(v as Record<string, unknown>, redactKeys);
      } catch {
        out[k] = "[unserializable]";
      }
    } else {
      out[k] = v;
    }
  }
  return out;
}

export interface Auditor {
  log(record: Omit<AuditRecord, "ts">): void;
}

export function createAuditor(logPath: string, logArgs: boolean): Auditor {
  return {
    log(record) {
      const full: AuditRecord = { ts: new Date().toISOString(), ...record };
      if (!logArgs) delete full.args;
      try {
        appendFileSync(logPath, JSON.stringify(full) + "\n");
      } catch {
        // Audit logging must never break the proxied session.
      }
    },
  };
}
