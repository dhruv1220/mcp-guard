#!/usr/bin/env node
/**
 * mcpguard CLI — scan MCP client configs for security issues,
 * or proxy a server through the enforcement gateway.
 *
 *   mcpguard scan --config ./mcp.json [--format table|json] [--fail-on medium] [--no-network]
 *   mcpguard gateway --policy ./policy.json --server <name> [--interactive] -- <command> [args...]
 *   mcpguard learn --audit ./mcpguard-audit.jsonl [--server <name>] [--out ./policy.json]
 */
import { readFileSync, writeFileSync } from "node:fs";
import { ConfigError, loadConfig } from "./config.js";
import { breachesThreshold, runChecks } from "./scanner/engine.js";
import { formatJson, formatTable } from "./report.js";
import { runProxy } from "./gateway/proxy.js";
import { probeServer, ProbeError } from "./probe.js";
import { generatePolicy } from "./policygen.js";
import { learnPolicy, LearnError } from "./learn.js";
import { loadPolicy } from "./gateway/policy.js";
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
    "  mcpguard gateway --policy <path> --server <name> [--interactive] [--approval-timeout <ms>] -- <command> [args...]",
    "  mcpguard probe [--timeout <ms>] -- <command> [args...]",
    "  mcpguard init-policy --server <name> [--default allow|deny] [--timeout <ms>] -- <command> [args...]",
    "  mcpguard learn --audit <path> [--server <name>] [--out <path>]",
    "",
    "Commands:",
    "  scan                 statically audit an MCP client config",
    "  gateway              transparent policy-enforcing proxy for one MCP server",
    "  probe                enumerate a server's real tool surface (initialize + tools/list)",
    "  init-policy          print a starter deny-by-default policy from a live probe",
    "  learn                build a tightened policy from a gateway audit log",
    "",
    "Options:",
    "  --config <path>      MCP client config JSON (with an \"mcpServers\" block)",
    "  --format <fmt>       table (default) or json",
    "  --fail-on <sev>      exit 1 if findings at/above this severity (default: medium)",
    "  --no-network         skip checks that need network access",
    "  --policy <path>      gateway policy JSON (required for gateway)",
    "  --server <name>      server name as listed in the policy (required for gateway)",
    "  --timeout <ms>       probe timeout in milliseconds (default: 15000)",
    "  --interactive        prompt the operator on the terminal for \"approval\" tools",
    "  --approval-timeout <ms>  operator prompt timeout in ms (default: 60000)",
    "  --audit <path>       gateway audit log (JSONL) to learn from (required for learn)",
    "  --out <path>         write output to a file instead of stdout",
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
  timeoutMs?: number;
  defaultAction?: "allow" | "deny";
  interactive: boolean;
  approvalTimeoutMs?: number;
  audit?: string;
  out?: string;
  commandArgs: string[];
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    format: "table",
    failOn: "medium",
    noNetwork: false,
    interactive: false,
    commandArgs: [],
  };
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
    else if (a === "--timeout") {
      const t = Number(rest.shift());
      if (!Number.isFinite(t) || t <= 0) throw new ConfigError("--timeout must be a positive number");
      args.timeoutMs = t;
    } else if (a === "--approval-timeout") {
      const t = Number(rest.shift());
      if (!Number.isFinite(t) || t <= 0)
        throw new ConfigError("--approval-timeout must be a positive number");
      args.approvalTimeoutMs = t;
    } else if (a === "--interactive") args.interactive = true;
    else if (a === "--audit") args.audit = rest.shift();
    else if (a === "--out") args.out = rest.shift();
    else if (a === "--default") {
      const d = rest.shift();
      if (d !== "allow" && d !== "deny") throw new ConfigError("--default must be allow or deny");
      args.defaultAction = d;
    } else if (a === "--format") {
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
  if (args.command === "init-policy") {
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
      const probed = await probeServer({
        command: args.commandArgs[0]!,
        commandArgs: args.commandArgs.slice(1),
        timeoutMs: args.timeoutMs,
      });
      const policy = generatePolicy(
        args.server,
        probed.tools,
        args.defaultAction ?? "deny"
      );
      console.log(JSON.stringify(policy, null, 2));
    } catch (err) {
      if (err instanceof ProbeError) {
        console.error(`error: ${err.message}`);
        process.exit(1);
      }
      throw err;
    }
    return;
  }
  if (args.command === "probe") {
    if (args.commandArgs.length === 0) {
      console.error("missing server command after --\n");
      console.error(usage());
      process.exit(2);
    }
    try {
      const result = await probeServer({
        command: args.commandArgs[0]!,
        commandArgs: args.commandArgs.slice(1),
        timeoutMs: args.timeoutMs,
      });
      console.log(JSON.stringify(result, null, 2));
    } catch (err) {
      if (err instanceof ProbeError) {
        console.error(`error: ${err.message}`);
        process.exit(1);
      }
      throw err;
    }
    return;
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
        interactive: args.interactive,
        approvalTimeoutMs: args.approvalTimeoutMs,
      });
      process.exit(code);
    } catch (err) {
      console.error(`error: ${(err as Error).message}`);
      process.exit(2);
    }
  }
  if (args.command === "learn") {
    if (!args.audit) {
      console.error("missing required option: --audit <path>\n");
      console.error(usage());
      process.exit(2);
    }
    try {
      const policy = learnPolicy(args.audit, { server: args.server });
      const out = JSON.stringify(policy, null, 2);
      if (args.out) writeFileSync(args.out, out + "\n");
      else console.log(out);
    } catch (err) {
      if (err instanceof LearnError) {
        console.error(`error: ${err.message}`);
        process.exit(1);
      }
      throw err;
    }
    return;
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
