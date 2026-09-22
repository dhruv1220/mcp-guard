import { ALL_CHECKS } from "./checks.js";
import type {
  CheckContext,
  Finding,
  McpServerDef,
  ScanReport,
  Severity,
} from "./types.js";

export { ALL_CHECKS };

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function compareFindings(a: Finding, b: Finding): number {
  return (
    SEVERITY_WEIGHT[a.severity] - SEVERITY_WEIGHT[b.severity] ||
    a.checkId.localeCompare(b.checkId) ||
    a.server.localeCompare(b.server)
  );
}

/**
 * Run every check against every server. Async (network) checks are skipped
 * when `ctx.offline` is true and reported via `skippedNetworkChecks`.
 */
export async function runChecks(
  servers: McpServerDef[],
  ctx: CheckContext = { offline: false }
): Promise<ScanReport> {
  const findings: Finding[] = [];
  let skippedNetworkChecks = false;

  for (const check of ALL_CHECKS) {
    if (check.async && ctx.offline) {
      skippedNetworkChecks = true;
      continue;
    }
    for (const server of servers) {
      findings.push(...(await check.run(server, ctx)));
    }
  }

  findings.sort(compareFindings);

  const summary: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) summary[f.severity] += 1;

  return {
    scannedAt: new Date().toISOString(),
    servers: servers.map((s) => s.name),
    findings,
    summary,
    skippedNetworkChecks,
  };
}

/** True when the report has findings at or above `threshold`. */
export function breachesThreshold(report: ScanReport, threshold: Severity): boolean {
  const weight = SEVERITY_WEIGHT[threshold];
  return report.findings.some((f) => SEVERITY_WEIGHT[f.severity] <= weight);
}
