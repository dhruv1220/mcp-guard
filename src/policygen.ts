import type { GatewayPolicy } from "./gateway/policy.js";
import type { ProbedTool } from "./probe.js";

/**
 * Generate a starter gateway policy from a probed tool surface.
 *
 * Deny-by-default: every discovered tool starts as "approval" (denied
 * non-interactively) so nothing runs until the operator explicitly
 * allowlists it. The policy documents the full surface.
 */
export function generatePolicy(
  serverName: string,
  tools: ProbedTool[],
  defaultAction: "allow" | "deny" = "deny"
): GatewayPolicy {
  const toolEntries: Record<string, "allow" | "deny" | "approval"> = {};
  for (const t of tools) {
    toolEntries[t.name] = "approval";
  }
  return {
    version: 1,
    defaultAction,
    auditLog: "./mcpguard-audit.jsonl",
    logArgs: true,
    screenOutput: true,
    servers: {
      [serverName]: {
        defaultAction,
        tools: toolEntries,
      },
    },
  };
}
