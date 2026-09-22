#!/usr/bin/env node
/**
 * mcpguard CLI — scan MCP client configs for security issues,
 * or proxy a server through the enforcement gateway.
 *
 *   mcpguard scan --config ./mcp.json [--format table|json] [--fail-on medium] [--no-network]
 *   mcpguard gateway --policy ./policy.json --server <name> -- <command> [args...]
 */
import { readFileSync } from "node:fs";
import { ConfigError, loadConfig } from "./config.js";
import { breachesThreshold, runChecks } from "./scanner/engine.js";
import { formatJson, formatTable } from "./report.js";
import { runProxy } from "./gateway/proxy.js";
import type { Severity } from "./scanner/types.js";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function version(): string {
  try {
    const pkg = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf-8")
    ) as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

function usage(): string {
  return [
    `mcpguard v${version()} — security and cost control for MCP servers`,
    "",
    "Usage:",
    "  mcpguard scan --config <path> [--format table|json] [--fail-on <severity>] [--no-network]",
    "  mcpguard gateway --policy <path> --server <name> -- <command> [args...]",
    "",
    "Commands:",
    "  scan                 statically audit an MCP client config",
    "  gateway              transparent policy-enforcing proxy for one MCP server",
    "",
    "Options:",
    "  --config <path>      MCP client config JSON (with an \"mcpServers\" block)",
    "  --format <fmt>       table (default) or json",
    "  --fail-on <sev>      exit 1 if findings at/above this severity (default: medium)",
    "  --no-network         skip checks that need network access",
    "  --policy <path>      gateway policy JSON (required for gateway)",
    "  --server <name>      server name as listed in the policy (required for gateway)",
    "  --help               show this help",
    "  --version            show version",
  ].join("\n");
}

interface Args {
  command?: string;
  config?: string;
  format: "table" | "json";
  failOn: Severity;
  noNetwork: boolean;
  policy?: string;
  server?: string;
  commandArgs: string[];
}

function parseArgs(argv: string[]): Args {
  const args: Args = { format: "table", failOn: "medium", noNetwork: false, commandArgs: [] };
  const rest = [...argv];
  args.command = rest.shift();
  while (rest.length > 0) {
    const a = rest.shift()!;
    if (a === "--") {
      // Everything after -- is the server command to spawn.
      args.commandArgs = rest.splice(0);
      break;
    } else if (a === "--config") args.config = rest.shift();
    else if (a === "--policy") args.policy = rest.shift();
    else if (a === "--server") args.server = rest.shift();
    else if (a === "--format") {
      const f = rest.shift();
      if (f !== "table" && f !== "json") throw new ConfigError(`--format must be table or json`);
      args.format = f;
    } else if (a === "--fail-on") {
      const s = rest.shift() as Severity;
      if (!SEVERITIES.includes(s))
        throw new ConfigError(`--fail-on must be one of: ${SEVERITIES.join(", ")}`);
      args.failOn = s;
    } else if (a === "--no-network") args.noNetwork = true;
    else if (a === "--help" || a === "-h") args.command = "help";
    else if (a === "--version" || a === "-v") args.command = "version";
    else throw new ConfigError(`unknown argument: ${a}`);
  }
  return args;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (args.command === "version") {
    console.log(version());
    return;
  }
  if (!args.command || args.command === "help") {
    console.log(usage());
    process.exit(args.command === "help" ? 0 : 2);
  }
  if (args.command === "gateway") {
    if (!args.policy) {
      console.error("missing required option: --policy <path>\n");
      console.error(usage());
      process.exit(2);
    }
    if (!args.server) {
      console.error("missing required option: --server <name>\n");
      console.error(usage());
      process.exit(2);
    }
    if (args.commandArgs.length === 0) {
      console.error("missing server command after --\n");
      console.error(usage());
      process.exit(2);
    }
    try {
      const code = await runProxy({
        policyPath: args.policy,
        serverName: args.server,
        command: args.commandArgs[0]!,
        commandArgs: args.commandArgs.slice(1),
      });
      process.exit(code);
    } catch (err) {
      console.error(`error: ${(err as Error).message}`);
      process.exit(2);
    }
  }
  if (args.command !== "scan") {
    console.error(`unknown command: ${args.command}\n\n${usage()}`);
    process.exit(2);
  }
  if (!args.config) {
    console.error("missing required option: --config <path>\n");
    console.error(usage());
    process.exit(2);
  }

  let servers;
  try {
    servers = loadConfig(args.config);
  } catch (err) {
    console.error(`error: ${(err as Error).message}`);
    process.exit(2);
  }

  const report = await runChecks(servers, { offline: args.noNetwork });
  console.log(args.format === "json" ? formatJson(report) : formatTable(report));
  process.exit(breachesThreshold(report, args.failOn) ? 1 : 0);
}

main().catch((err) => {
  console.error(`error: ${(err as Error).message}`);
  process.exit(2);
});
