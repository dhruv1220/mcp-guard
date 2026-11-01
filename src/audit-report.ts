import { readFileSync } from "node:fs";
import type { AuditRecord } from "./gateway/audit.js";

/**
 * Summarize a gateway audit log (JSONL) for a human operator.
 *
 * The audit log's other consumer, `learn`, turns observations into a
 * policy. This answers the questions that come before that: what got
 * blocked, why, which tools draw the most denials, and whether any tool
 * output tripped the injection screen. Parsing is deliberately tolerant —
 * a live log can end mid-line — corrupt lines are counted and skipped,
 * never fatal.
 */

export class AuditError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuditError";
  }
}

export interface AuditOptions {
  /** Only summarize audit records for this server. */
  server?: string;
}

export interface Counted {
  reason: string;
  count: number;
}

export interface FlagCounted {
  flag: string;
  count: number;
}

export interface ToolSummary {
  server: string;
  tool: string;
  calls: number;
  allowed: number;
  denied: number;
  /** Up to 3 most common deny reasons for this tool. */
  topDenyReasons: Counted[];
}

export interface AuditSummary {
  /** Totals across all summarized records. */
  totals: {
    calls: number;
    allowed: number;
    denied: number;
    /** Sum of resultBytes over allowed calls that reported one. */
    resultBytes: number;
    /** Allowed calls whose result tripped the injection screen. */
    injectionFlagged: number;
    /** Mean durationMs over allowed calls that reported one, else null. */
    avgDurationMs: number | null;
    /** Max durationMs over allowed calls that reported one, else null. */
    maxDurationMs: number | null;
  };
  /** ISO timestamps of the first/last summarized records, else null. */
  firstTs: string | null;
  lastTs: string | null;
  /** Lines skipped because they were not parseable audit records. */
  skippedLines: number;
  /** Deny reasons across all tools, most common first. */
  denyReasons: Counted[];
  /** Injection flags across all tools, most common first. */
  injectionFlags: FlagCounted[];
  /** Per-tool breakdown, most-denied first. */
  tools: ToolSummary[];
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

function sortCounted<T extends { count: number }>(
  entries: Iterable<[string, number]>,
  toEntry: (key: string, count: number) => T,
  keyOf: (entry: T) => string
): T[] {
  return [...entries]
    .map(([key, count]) => toEntry(key, count))
    .sort((a, b) => b.count - a.count || (keyOf(a) < keyOf(b) ? -1 : 1));
}

interface ToolTally {
  calls: number;
  allowed: number;
  denied: number;
  denyReasons: Map<string, number>;
}

/** Read an audit log and summarize what the gateway did. */
export function summarizeAudit(auditPath: string, opts: AuditOptions = {}): AuditSummary {
  let raw: string;
  try {
    raw = readFileSync(auditPath, "utf-8");
  } catch {
    throw new AuditError(`cannot read audit log: ${auditPath}`);
  }

  const tools = new Map<string, ToolTally>();
  const denyReasons = new Map<string, number>();
  const injectionFlags = new Map<string, number>();
  let calls = 0;
  let allowed = 0;
  let denied = 0;
  let resultBytes = 0;
  let injectionFlagged = 0;
  let durationSum = 0;
  let durationCount = 0;
  let maxDurationMs: number | null = null;
  let firstTs: string | null = null;
  let lastTs: string | null = null;
  let skippedLines = 0;

  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let rec: unknown;
    try {
      rec = JSON.parse(trimmed);
    } catch {
      skippedLines += 1;
      continue;
    }
    if (!isAuditRecord(rec)) {
      skippedLines += 1;
      continue;
    }
    if (opts.server && rec.server !== opts.server) continue;
    calls += 1;
    if (typeof rec.ts === "string") {
      if (firstTs === null) firstTs = rec.ts;
      lastTs = rec.ts;
    }
    const key = `${rec.server}\0${rec.tool}`;
    let tally = tools.get(key);
    if (!tally) {
      tally = { calls: 0, allowed: 0, denied: 0, denyReasons: new Map() };
      tools.set(key, tally);
    }
    tally.calls += 1;
    if (rec.decision === "allow") {
      allowed += 1;
      tally.allowed += 1;
      if (typeof rec.resultBytes === "number") resultBytes += rec.resultBytes;
      if (typeof rec.durationMs === "number") {
        durationSum += rec.durationMs;
        durationCount += 1;
        if (maxDurationMs === null || rec.durationMs > maxDurationMs) {
          maxDurationMs = rec.durationMs;
        }
      }
      if (Array.isArray(rec.injectionFlags) && rec.injectionFlags.length > 0) {
        injectionFlagged += 1;
        for (const flag of rec.injectionFlags) {
          if (typeof flag !== "string") continue;
          injectionFlags.set(flag, (injectionFlags.get(flag) ?? 0) + 1);
        }
      }
    } else {
      denied += 1;
      tally.denied += 1;
      denyReasons.set(rec.reason, (denyReasons.get(rec.reason) ?? 0) + 1);
      tally.denyReasons.set(
        rec.reason,
        (tally.denyReasons.get(rec.reason) ?? 0) + 1
      );
    }
  }

  if (calls === 0) {
    throw new AuditError(`no usable audit records in ${auditPath}`);
  }

  const toolSummaries: ToolSummary[] = [...tools.entries()]
    .map(([key, tally]) => {
      const [server, tool] = key.split("\0") as [string, string];
      return {
        server,
        tool,
        calls: tally.calls,
        allowed: tally.allowed,
        denied: tally.denied,
        topDenyReasons: sortCounted(
          tally.denyReasons.entries(),
          (reason, count) => ({ reason, count }),
          (e) => e.reason
        ).slice(0, 3),
      };
    })
    .sort(
      (a, b) =>
        b.denied - a.denied ||
        b.calls - a.calls ||
        (a.server === b.server
          ? a.tool < b.tool
            ? -1
            : 1
          : a.server < b.server
            ? -1
            : 1)
    );

  return {
    totals: {
      calls,
      allowed,
      denied,
      resultBytes,
      injectionFlagged,
      avgDurationMs:
        durationCount > 0 ? Math.round((durationSum / durationCount) * 10) / 10 : null,
      maxDurationMs,
    },
    firstTs,
    lastTs,
    skippedLines,
    denyReasons: sortCounted(
      denyReasons.entries(),
      (reason, count) => ({ reason, count }),
      (e) => e.reason
    ),
    injectionFlags: sortCounted(
      injectionFlags.entries(),
      (flag, count) => ({ flag, count }),
      (e) => e.flag
    ),
    tools: toolSummaries,
  };
}

/** Human-readable table output for an audit summary. */
export function formatAuditTable(summary: AuditSummary): string {
  const lines: string[] = [];
  const t = summary.totals;
  lines.push(
    `mcp-guard audit — ${t.calls} call(s), ${t.allowed} allowed, ${t.denied} denied`
  );
  if (summary.firstTs && summary.lastTs) {
    lines.push(`Range: ${summary.firstTs} → ${summary.lastTs}`);
  }
  lines.push(
    `Result bytes: ${t.resultBytes} · injection-flagged calls: ${t.injectionFlagged}` +
      (t.avgDurationMs !== null
        ? ` · avg duration: ${t.avgDurationMs}ms (max ${t.maxDurationMs}ms)`
        : "")
  );
  if (summary.skippedLines > 0) {
    lines.push(`(skipped ${summary.skippedLines} unparseable line(s))`);
  }
  lines.push("");

  if (summary.denyReasons.length > 0) {
    lines.push("Denied by reason:");
    for (const r of summary.denyReasons) {
      lines.push(`  ${r.count} × ${r.reason}`);
    }
    lines.push("");
  }

  lines.push("Per tool (most-denied first):");
  for (const tool of summary.tools) {
    lines.push(
      `  ${tool.server}/${tool.tool} — ${tool.calls} call(s), ${tool.allowed} allowed, ${tool.denied} denied`
    );
    for (const r of tool.topDenyReasons) {
      lines.push(`    ${r.count} × ${r.reason}`);
    }
  }

  if (summary.injectionFlags.length > 0) {
    lines.push("");
    lines.push("Injection flags:");
    for (const f of summary.injectionFlags) {
      lines.push(`  ${f.count} × ${f.flag}`);
    }
  }

  return lines.join("\n").trimEnd();
}
