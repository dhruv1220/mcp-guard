// mcp-guard public API. Scanner ships in v0.1; gateway lands next.
export type {
  Check,
  CheckContext,
  Finding,
  McpServerDef,
  ScanReport,
  Severity,
  Transport,
} from "./scanner/types.js";
export { loadConfig, ConfigError } from "./config.js";
export { ALL_CHECKS, breachesThreshold, runChecks } from "./scanner/engine.js";
export { formatJson, formatTable } from "./report.js";
