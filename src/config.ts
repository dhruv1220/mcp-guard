import { readFileSync } from "node:fs";
import type { McpServerDef, Transport } from "./scanner/types.js";

export class ConfigError extends Error {}

/**
 * Load an MCP client config file and normalize every server entry.
 *
 * Supports the common `mcpServers` shapes (Claude Desktop, Cursor,
 * Claude Code JSON export):
 *
 *   { "mcpServers": { "name": { "command": ..., "args": [...], "env": {...} } } }
 *   { "mcpServers": { "name": { "url": "https://...", "headers": {...} } } }
 *
 * A bare `{ "name": {...} }` map is also accepted.
 */
export function loadConfig(path: string): McpServerDef[] {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf-8"));
  } catch (err) {
    throw new ConfigError(
      `could not read config at ${path}: ${(err as Error).message}`
    );
  }
  if (typeof raw !== "object" || raw === null) {
    throw new ConfigError(`config at ${path} is not a JSON object`);
  }
  const obj = raw as Record<string, unknown>;
  const serversBlock =
    obj["mcpServers"] && typeof obj["mcpServers"] === "object"
      ? (obj["mcpServers"] as Record<string, unknown>)
      : obj;

  const servers: McpServerDef[] = [];
  for (const [name, def] of Object.entries(serversBlock)) {
    if (typeof def !== "object" || def === null) continue;
    servers.push(normalizeServer(name, def as Record<string, unknown>));
  }
  if (servers.length === 0) {
    throw new ConfigError(`no MCP server entries found in ${path}`);
  }
  return servers;
}

function normalizeServer(name: string, raw: Record<string, unknown>): McpServerDef {
  const explicit = typeof raw["type"] === "string" ? raw["type"] : undefined;

  if (typeof raw["url"] === "string" || explicit === "http" || explicit === "sse" || explicit === "streamable") {
    const url = typeof raw["url"] === "string" ? raw["url"] : "";
    let transport: Transport = "http";
    if (explicit === "sse" || explicit === "http" || explicit === "streamable") {
      transport = explicit;
    } else if (/\/sse(\?|$)/i.test(url)) {
      transport = "sse";
    } else if (/\/mcp(\?|$)/i.test(url)) {
      transport = "streamable";
    }
    const headers: Record<string, string> = {};
    if (raw["headers"] && typeof raw["headers"] === "object") {
      for (const [k, v] of Object.entries(raw["headers"] as Record<string, unknown>)) {
        headers[k] = String(v);
      }
    }
    return { name, transport, url, headers };
  }

  const env: Record<string, string> = {};
  if (raw["env"] && typeof raw["env"] === "object") {
    for (const [k, v] of Object.entries(raw["env"] as Record<string, unknown>)) {
      env[k] = String(v);
    }
  }
  return {
    name,
    transport: "stdio",
    command: typeof raw["command"] === "string" ? raw["command"] : "",
    args: Array.isArray(raw["args"]) ? raw["args"].map(String) : [],
    env,
  };
}
