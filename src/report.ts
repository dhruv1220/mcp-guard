import type { Finding, ScanReport, Severity } from "./scanner/types.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const BADGE: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

/** Human-readable table output. Secrets are already redacted in findings. */
export function formatTable(report: ScanReport): string {
  const lines: string[] = [];
  const total = report.findings.length;
  const parts = SEVERITY_ORDER.filter((s) => report.summary[s] > 0).map(
    (s) => `${report.summary[s]} ${s}`
  );
  lines.push(
    `mcp-guard scan — ${report.servers.length} server(s), ${total} finding(s)${
      parts.length > 0 ? ` (${parts.join(", ")})` : ""
    }`
  );
  if (report.skippedNetworkChecks) {
    lines.push(`(network checks skipped: --no-network)`);
  }
  lines.push("");

  if (total === 0) {
    lines.push("Clean — no findings.");
    return lines.join("\n");
  }

  for (const sev of SEVERITY_ORDER) {
    const group = report.findings.filter((f) => f.severity === sev);
    for (const f of group) {
      lines.push(...formatFinding(f));
      lines.push("");
    }
  }
  return lines.join("\n").trimEnd();
}

function formatFinding(f: Finding): string[] {
  return [
    `[${BADGE[f.severity]}] ${f.checkId} · ${f.server}`,
    `  ${f.message}`,
    `  Evidence: ${f.evidence}`,
    `  Fix: ${f.remediation}`,
  ];
}

/** Machine-readable output for CI and tooling. */
export function formatJson(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}
