// mcp-guard public API. Scanner ships in v0.1; gateway lands next.
export type {
  Check,
  CheckResult,
  Finding,
  McpServerDef,
  ScanReport,
  Severity,
  Transport,
} from "./scanner/types.js";
export { loadConfig } from "./config.js";
export { ALL_CHECKS, runChecks } from "./scanner/engine.js";
export { formatJson, formatTable } from "./report.js";
