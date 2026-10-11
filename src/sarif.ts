/**
 * SARIF 2.1.0 output for `mcpguard scan --format sarif`.
 *
 * Lets CI pipelines upload findings to GitHub code scanning (or any SARIF
 * consumer) with `github/codeql-action/upload-sarif`. Findings are
 * config-level, so each result points at the scanned config file.
 */
import { ALL_CHECKS } from "./scanner/engine.js";
import type { Finding, ScanReport, Severity } from "./scanner/types.js";

const SARIF_VERSION = "2.1.0";
const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

const LEVEL: Record<Severity, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "none",
};

export interface SarifOptions {
  /** Path of the scanned config, used as the result artifact URI. */
  configPath?: string;
  /** Reported as the tool driver version. */
  toolVersion?: string;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: string };
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: Array<{
    physicalLocation: { artifactLocation: { uri: string } };
  }>;
}

function toRule(check: { id: string; title: string }): SarifRule {
  return {
    id: check.id,
    name: check.title,
    shortDescription: { text: check.title },
    defaultConfiguration: { level: "warning" },
  };
}

function toResult(f: Finding, configPath: string): SarifResult {
  const parts = [f.message];
  if (f.evidence) parts.push(`Evidence: ${f.evidence}`);
  if (f.remediation) parts.push(`Remediation: ${f.remediation}`);
  return {
    ruleId: f.checkId,
    level: LEVEL[f.severity],
    message: { text: parts.join("\n") },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: configPath || f.server },
        },
      },
    ],
  };
}

/** Render a scan report as a SARIF 2.1.0 log. Secrets stay redacted: findings carry redacted evidence by contract. */
export function formatSarif(report: ScanReport, opts: SarifOptions = {}): string {
  const configPath = opts.configPath ?? "";
  const log = {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-guard",
            version: opts.toolVersion ?? "0.0.0",
            informationUri: "https://github.com/dhruv1220/mcp-guard",
            rules: ALL_CHECKS.map(toRule),
          },
        },
        artifacts: configPath
          ? [{ location: { uri: configPath } }]
          : [],
        results: report.findings.map((f) => toResult(f, configPath)),
      },
    ],
  };
  return JSON.stringify(log, null, 2);
}
