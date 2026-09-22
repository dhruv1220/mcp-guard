// mcp-guard public API (scanner). CLI/report ship next.
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
