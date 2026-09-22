import { describe, expect, it } from "vitest";
import { ConfigError, loadConfig } from "../src/config.js";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function writeConfig(obj: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), "mcpguard-"));
  const path = join(dir, "mcp.json");
  writeFileSync(path, typeof obj === "string" ? obj : JSON.stringify(obj));
  return path;
}

describe("loadConfig", () => {
  it("parses Claude-style mcpServers with stdio entries", () => {
    const path = writeConfig({
      mcpServers: {
        gh: {
          command: "npx",
          args: ["-y", "@modelcontextprotocol/server-github"],
          env: { GITHUB_TOKEN: "${GITHUB_TOKEN}" },
        },
      },
    });
    const servers = loadConfig(path);
    expect(servers).toHaveLength(1);
    expect(servers[0]).toMatchObject({
      name: "gh",
      transport: "stdio",
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-github"],
      env: { GITHUB_TOKEN: "${GITHUB_TOKEN}" },
    });
  });

  it("detects remote transports from the URL", () => {
    const path = writeConfig({
      mcpServers: {
        a: { url: "https://api.example.com/mcp", headers: { Authorization: "Bearer x" } },
        b: { url: "https://api.example.com/sse" },
        c: { url: "https://api.example.com/rpc" },
        d: { url: "https://api.example.com/mcp", type: "sse" },
      },
    });
    const transports = Object.fromEntries(
      loadConfig(path).map((s) => [s.name, s.transport])
    );
    expect(transports).toEqual({ a: "streamable", b: "sse", c: "http", d: "sse" });
  });

  it("accepts a bare map without the mcpServers wrapper", () => {
    const path = writeConfig({ my: { command: "uvx", args: ["pkg"] } });
    expect(loadConfig(path)).toHaveLength(1);
  });

  it("throws ConfigError on invalid JSON", () => {
    expect(() => loadConfig(writeConfig("{nope"))).toThrow(ConfigError);
  });

  it("throws ConfigError when no servers are found", () => {
    expect(() => loadConfig(writeConfig({ mcpServers: {} }))).toThrow(ConfigError);
  });

  it("throws ConfigError for a missing file", () => {
    expect(() => loadConfig("/does/not/exist.json")).toThrow(ConfigError);
  });
});
