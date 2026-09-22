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
export {
  decide,
  loadPolicy,
  PolicyError,
} from "./gateway/policy.js";
export type {
  ArgConstraint,
  Decision,
  GatewayPolicy,
  PolicyAction,
  ServerPolicy,
  ToolPolicyEntry,
  ToolRule,
} from "./gateway/policy.js";
export { createAuditor, redactArgsForLog } from "./gateway/audit.js";
export type { AuditRecord, Auditor } from "./gateway/audit.js";
export { createBudgetTracker } from "./gateway/budgets.js";
export type { BudgetLimits, BudgetTracker } from "./gateway/budgets.js";
export { probeServer, ProbeError } from "./probe.js";
export type { ProbeOptions, ProbeResult, ProbedTool } from "./probe.js";
export { extractResultTexts, screenText } from "./gateway/screen.js";
export type { InjectionPattern } from "./gateway/screen.js";
export { generatePolicy } from "./policygen.js";
export { runProxy } from "./gateway/proxy.js";
export type { ProxyOptions } from "./gateway/proxy.js";
