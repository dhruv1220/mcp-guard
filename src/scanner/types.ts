/** Core types for the mcp-guard static scanner. */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Transport = "stdio" | "http" | "sse" | "streamable";

/** A single MCP server entry, normalized from a client config file. */
export interface McpServerDef {
  name: string;
  transport: Transport;
  /** stdio only */
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  /** http/sse/streamable only */
  url?: string;
  headers?: Record<string, string>;
}

/** One scanner finding. `evidence` must be redacted — never raw secrets. */
export interface Finding {
  checkId: string;
  title: string;
  severity: Severity;
  server: string;
  message: string;
  evidence: string;
  remediation: string;
}

export interface CheckContext {
  /** When true, async (network) checks are skipped. */
  offline: boolean;
}

export interface Check {
  id: string;
  title: string;
  /** Async checks need network and are skipped with --no-network. */
  async: boolean;
  run(server: McpServerDef, ctx: CheckContext): Finding[] | Promise<Finding[]>;
}

export interface ScanReport {
  scannedAt: string;
  servers: string[];
  findings: Finding[];
  summary: Record<Severity, number>;
  skippedNetworkChecks: boolean;
}
