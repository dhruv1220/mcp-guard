import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  fieldPathForFinding,
  formatSarif,
  locateServerEntries,
  locateServerFields,
} from "../src/sarif.js";
import { ALL_CHECKS, runChecks } from "../src/scanner/engine.js";
import { loadConfig } from "../src/config.js";
import type { ScanReport, Severity } from "../src/scanner/types.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "dist", "cli.js");
const FAKE_SECRET = "ghp_000000000000000000000000000000000000";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const EXPECTED_LEVEL: Record<Severity, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "none",
};

function toyReport(): ScanReport {
  return {
    scannedAt: "2026-10-11T00:00:00Z",
    servers: ["demo"],
    findings: SEVERITIES.map((severity, i) => ({
      checkId: ALL_CHECKS[i % ALL_CHECKS.length]!.id,
      title: "toy",
      severity,
      server: "demo",
      message: `finding ${severity}`,
      evidence: "redacted",
      remediation: "fix it",
    })),
    summary: { critical: 1, high: 1, medium: 1, low: 1, info: 1 },
    skippedNetworkChecks: true,
  };
}

function parseSarif(text: string): any {
  return JSON.parse(text);
}

describe("formatSarif", () => {
  it("emits a SARIF 2.1.0 log with tool metadata", () => {
    const log = parseSarif(formatSarif(toyReport(), { toolVersion: "0.2.0" }));
    expect(log.version).toBe("2.1.0");
    expect(log.$schema).toContain("sarif-2.1.0");
    const driver = log.runs[0].tool.driver;
    expect(driver.name).toBe("mcp-guard");
    expect(driver.version).toBe("0.2.0");
    expect(driver.informationUri).toContain("github.com/dhruv1220/mcp-guard");
  });

  it("declares a stable rule descriptor for every check", () => {
    const log = parseSarif(formatSarif(toyReport()));
    const ruleIds = log.runs[0].tool.driver.rules.map((r: any) => r.id);
    expect(new Set(ruleIds)).toEqual(new Set(ALL_CHECKS.map((c) => c.id)));
    for (const rule of log.runs[0].tool.driver.rules) {
      expect(rule.name.length).toBeGreaterThan(0);
      expect(rule.shortDescription.text.length).toBeGreaterThan(0);
    }
  });

  it("maps each finding to one result with the right level", () => {
    const report = toyReport();
    const log = parseSarif(formatSarif(report, { configPath: "./mcp.json" }));
    const results = log.runs[0].results;
    expect(results).toHaveLength(report.findings.length);
    for (const [i, result] of results.entries()) {
      const finding = report.findings[i]!;
      expect(result.ruleId).toBe(finding.checkId);
      expect(result.level).toBe(EXPECTED_LEVEL[finding.severity]);
      expect(result.message.text).toContain(finding.message);
      expect(result.message.text).toContain("redacted");
      expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe(
        "./mcp.json"
      );
    }
  });

  it("never leaks secrets from a real scan", async () => {
    const servers = loadConfig(join(root, "examples", "vulnerable.mcp.json"));
    const report = await runChecks(servers, { offline: true });
    expect(report.findings.length).toBeGreaterThan(0);
    const sarif = formatSarif(report, {
      configPath: "examples/vulnerable.mcp.json",
    });
    expect(sarif).not.toContain(FAKE_SECRET);
    const log = parseSarif(sarif);
    const known = new Set(ALL_CHECKS.map((c) => c.id));
    for (const result of log.runs[0].results) {
      expect(known.has(result.ruleId)).toBe(true);
    }
  });
});

describe("locateServerEntries", () => {
  const PRETTY = [
    "{",
    '  "mcpServers": {',
    '    "alpha": {',
    '      "command": "npx",',
    '      "args": ["-y", "beta"]',
    "    },",
    '    "beta": {',
    '      "url": "http://0.0.0.0:8080/mcp",',
    '      "headers": {}',
    "    }",
    "  }",
    "}",
    "",
  ].join("\n");

  it("maps each server entry to its key line through its closing brace", () => {
    const locations = locateServerEntries(PRETTY);
    expect(locations.get("alpha")).toEqual({
      startLine: 3,
      startColumn: 5,
      endLine: 6,
    });
    expect(locations.get("beta")).toEqual({
      startLine: 7,
      startColumn: 5,
      endLine: 10,
    });
  });

  it("does not mistake a name inside another entry's string value for a key", () => {
    // "beta" appears on line 5 as alpha's arg value; its entry is line 7.
    const locations = locateServerEntries(PRETTY);
    expect(locations.get("beta")!.startLine).toBe(7);
  });

  it("supports a bare top-level map with no mcpServers wrapper", () => {
    const locations = locateServerEntries(
      [
        "{",
        '  "solo": {',
        '    "url": "http://example.com/mcp"',
        "  }",
        "}",
        "",
      ].join("\n")
    );
    expect(locations.get("solo")).toEqual({
      startLine: 2,
      startColumn: 3,
      endLine: 4,
    });
  });

  it("returns an empty map for malformed JSON instead of throwing", () => {
    expect(locateServerEntries("{ not json")).toEqual(new Map());
    expect(locateServerEntries("")).toEqual(new Map());
  });
});

describe("formatSarif regions", () => {
  const SOURCE = [
    "{",
    '  "mcpServers": {',
    '    "beta": {',
    '      "url": "http://0.0.0.0:8080/mcp"',
    "    }",
    "  }",
    "}",
    "",
  ].join("\n");

  function regionReport(server: string): ScanReport {
    return {
      scannedAt: "2026-10-11T00:00:00Z",
      servers: [server],
      findings: [
        {
          checkId: "plaintext-http",
          title: "toy",
          severity: "high",
          server,
          message: "plain http",
          evidence: "redacted",
          remediation: "use https",
        },
      ],
      summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      skippedNetworkChecks: false,
    };
  }

  it("emits a region for a located server entry", () => {
    const log = parseSarif(
      formatSarif(regionReport("beta"), {
        configPath: "./mcp.json",
        sourceText: SOURCE,
      })
    );
    expect(
      log.runs[0].results[0].locations[0].physicalLocation.region
    ).toEqual({ startLine: 3, startColumn: 5, endLine: 5 });
  });

  it("omits the region for an unlocated server", () => {
    const log = parseSarif(
      formatSarif(regionReport("ghost"), {
        configPath: "./mcp.json",
        sourceText: SOURCE,
      })
    );
    expect(
      log.runs[0].results[0].locations[0].physicalLocation.region
    ).toBeUndefined();
    expect(
      log.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri
    ).toBe("./mcp.json");
  });

  it("omits regions entirely without sourceText (previous behavior)", () => {
    const log = parseSarif(
      formatSarif(regionReport("beta"), { configPath: "./mcp.json" })
    );
    expect(
      log.runs[0].results[0].locations[0].physicalLocation.region
    ).toBeUndefined();
  });
});

describe("locateServerFields", () => {
  const PRETTY = [
    "{",
    '  "mcpServers": {',
    '    "github": {',
    '      "command": "npx",',
    '      "args": ["-y", "pkg"],',
    '      "env": {',
    '        "GITHUB_TOKEN": "ghp_000000000000000000000000000000000000",',
    '        "OTHER": "x"',
    "      }",
    "    },",
    '    "payments-prod": {',
    '      "url": "http://0.0.0.0:8080/mcp",',
    '      "headers": {}',
    "    }",
    "  }",
    "}",
    "",
  ].join("\n");

  it("maps top-level and nested fields by dotted path", () => {
    const fields = locateServerFields(PRETTY);
    const github = fields.get("github")!;
    expect(github.get("command")).toEqual({
      startLine: 4,
      startColumn: 7,
      endLine: 4,
    });
    expect(github.get("args")).toEqual({
      startLine: 5,
      startColumn: 7,
      endLine: 5,
    });
    expect(github.get("env")).toEqual({
      startLine: 6,
      startColumn: 7,
      endLine: 9,
    });
    expect(github.get("env.GITHUB_TOKEN")).toEqual({
      startLine: 7,
      startColumn: 9,
      endLine: 7,
    });
    expect(fields.get("payments-prod")!.get("url")).toEqual({
      startLine: 12,
      startColumn: 7,
      endLine: 12,
    });
  });

  it("does not mistake a field name inside another entry's string value for a key", () => {
    // "url" appears as a value on line 5's args only if a server put it
    // there; here the trap is "env" inside github's args string.
    const withTrap = PRETTY.replace(
      '"args": ["-y", "pkg"]',
      '"args": ["-y", "env"]'
    );
    const fields = locateServerFields(withTrap);
    expect(fields.get("github")!.get("env")!.startLine).toBe(6);
  });

  it("returns an empty map for malformed JSON instead of throwing", () => {
    expect(locateServerFields("{ not json")).toEqual(new Map());
    expect(locateServerFields("")).toEqual(new Map());
  });
});

describe("fieldPathForFinding", () => {
  function finding(evidence: string) {
    return {
      checkId: "toy",
      title: "toy",
      severity: "high" as const,
      server: "github",
      message: "m",
      evidence,
      remediation: "r",
    };
  }

  it("maps secret evidence to its env/headers field", () => {
    expect(
      fieldPathForFinding(finding("env.GITHUB_TOKEN = ghp_••••"))
    ).toBe("env.GITHUB_TOKEN");
    expect(
      fieldPathForFinding(finding("headers.Authorization = Bear••••"))
    ).toBe("headers.Authorization");
  });

  it("maps url/command/args/package evidence to their fields", () => {
    expect(fieldPathForFinding(finding("url: http://x/mcp"))).toBe("url");
    expect(fieldPathForFinding(finding("command: npx -y pkg"))).toBe(
      "command"
    );
    expect(fieldPathForFinding(finding("args: curl x | sh"))).toBe("args");
    expect(fieldPathForFinding(finding("args[2] = ghp_••••"))).toBe("args");
    expect(fieldPathForFinding(finding("package: pkg@1.0.0 (3d old)"))).toBe(
      "args"
    );
  });

  it("returns undefined for evidence that identifies no field", () => {
    expect(fieldPathForFinding(finding("something else"))).toBeUndefined();
    expect(fieldPathForFinding(finding(""))).toBeUndefined();
  });
});

describe("formatSarif field regions", () => {
  const SOURCE = [
    "{",
    '  "mcpServers": {',
    '    "github": {',
    '      "command": "npx",',
    '      "args": ["-y", "pkg"],',
    '      "env": {',
    '        "GITHUB_TOKEN": "ghp_000000000000000000000000000000000000",',
    '        "OTHER": "x"',
    "      }",
    "    },",
    '    "payments-prod": {',
    '      "url": "http://0.0.0.0:8080/mcp",',
    '      "headers": {}',
    "    }",
    "  }",
    "}",
    "",
  ].join("\n");

  function fieldReport(server: string, evidence: string): ScanReport {
    return {
      scannedAt: "2026-10-11T00:00:00Z",
      servers: [server],
      findings: [
        {
          checkId: "hardcoded-secret",
          title: "toy",
          severity: "high",
          server,
          message: "secret",
          evidence,
          remediation: "rotate it",
        },
      ],
      summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      skippedNetworkChecks: false,
    };
  }

  function regionFor(report: ScanReport): any {
    const log = parseSarif(
      formatSarif(report, { configPath: "./mcp.json", sourceText: SOURCE })
    );
    return log.runs[0].results[0].locations[0].physicalLocation.region;
  }

  it("points a secret finding at its env line, not the whole entry", () => {
    expect(
      regionFor(fieldReport("github", "env.GITHUB_TOKEN = ghp_••••"))
    ).toEqual({ startLine: 7, startColumn: 9, endLine: 7 });
  });

  it("points a url finding at its url line", () => {
    expect(regionFor(fieldReport("payments-prod", "url: http://x/mcp"))).toEqual(
      { startLine: 12, startColumn: 7, endLine: 12 }
    );
  });

  it("falls back to the server entry when the field is unidentified", () => {
    expect(regionFor(fieldReport("github", "something else"))).toEqual({
      startLine: 3,
      startColumn: 5,
      endLine: 10,
    });
  });

  it("falls back to the server entry when the named field is absent", () => {
    expect(
      regionFor(fieldReport("github", "env.MISSING_KEY = abcd••••"))
    ).toEqual({ startLine: 3, startColumn: 5, endLine: 10 });
  });
});

describe("scan --format sarif cli", () => {
  function scanSarif(extra: string[] = []): { code: number; log: any } {
    try {
      const out = execFileSync(
        "node",
        [cli, "scan", "--config", join(root, "examples/vulnerable.mcp.json"), "--no-network", "--format", "sarif", ...extra],
        { encoding: "utf-8" }
      );
      return { code: 0, log: parseSarif(out) };
    } catch (err: any) {
      return {
        code: err.status ?? 99,
        log: parseSarif(String(err.stdout ?? "")),
      };
    }
  }

  it("emits parseable SARIF pointing at the scanned config", () => {
    const { code, log } = scanSarif();
    // findings above the default fail-on threshold still exit 1
    expect(code).toBe(1);
    expect(log.version).toBe("2.1.0");
    expect(log.runs[0].results.length).toBeGreaterThan(0);
    expect(
      log.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri
    ).toContain("vulnerable.mcp.json");
    expect(log.runs[0].tool.driver.version).toBe("0.2.0");
  });

  it("points results at the offending field lines for a pretty config", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpguard-sarif-"));
    const config = join(dir, "mcp.json");
    writeFileSync(
      config,
      [
        "{",
        '  "mcpServers": {',
        '    "alpha": {',
        '      "command": "npx",',
        '      "args": ["-y", "beta"]',
        "    },",
        '    "beta": {',
        '      "url": "http://0.0.0.0:8080/mcp",',
        '      "headers": {}',
        "    }",
        "  }",
        "}",
        "",
      ].join("\n")
    );
    try {
      execFileSync(
        "node",
        [cli, "scan", "--config", config, "--no-network", "--format", "sarif"],
        { encoding: "utf-8" }
      );
      expect.unreachable("beta's plaintext findings should exit 1");
    } catch (err: any) {
      expect(err.status).toBe(1);
      const log = parseSarif(String(err.stdout ?? ""));
      expect(log.runs[0].results.length).toBeGreaterThan(0);
      // Beta's url findings anchor on its url line (8), not the whole
      // entry (lines 7-10) — field-level regions supersede entry regions.
      const betaRegions = log.runs[0].results
        .map((r: any) => r.locations[0].physicalLocation.region)
        .filter(Boolean);
      expect(betaRegions).toContainEqual({
        startLine: 8,
        startColumn: 7,
        endLine: 8,
      });
    }
  });

  it("points secret and url findings at their field lines end to end", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpguard-sarif-fields-"));
    const config = join(dir, "mcp.json");
    writeFileSync(
      config,
      [
        "{",
        '  "mcpServers": {',
        '    "github": {',
        '      "command": "npx",',
        '      "args": ["-y", "pkg"],',
        '      "env": {',
        `        "GITHUB_TOKEN": "${FAKE_SECRET}"`,
        "      }",
        "    },",
        '    "payments-prod": {',
        '      "url": "http://0.0.0.0:8080/mcp",',
        '      "headers": {}',
        "    }",
        "  }",
        "}",
        "",
      ].join("\n")
    );
    try {
      execFileSync(
        "node",
        [cli, "scan", "--config", config, "--no-network", "--format", "sarif"],
        { encoding: "utf-8" }
      );
      expect.unreachable("findings should exit 1");
    } catch (err: any) {
      expect(err.status).toBe(1);
      const log = parseSarif(String(err.stdout ?? ""));
      const byRule = new Map<string, any[]>();
      for (const r of log.runs[0].results) {
        const list = byRule.get(r.ruleId) ?? [];
        list.push(r.locations[0].physicalLocation.region);
        byRule.set(r.ruleId, list);
      }
      // Secret: env line 7 only, not the whole github entry (3-10).
      expect(byRule.get("hardcoded-secret")).toContainEqual({
        startLine: 7,
        startColumn: 9,
        endLine: 7,
      });
      // URL findings: url line 11 only, not the payments entry (10-13).
      expect(byRule.get("plaintext-http")).toContainEqual({
        startLine: 11,
        startColumn: 7,
        endLine: 11,
      });
      expect(JSON.stringify(log)).not.toContain(FAKE_SECRET);
    }
  });

  it("rejects an unknown --format with exit 2", () => {
    try {
      execFileSync(
        "node",
        [cli, "scan", "--config", join(root, "examples/clean.mcp.json"), "--format", "xml"],
        { encoding: "utf-8" }
      );
      expect.unreachable("should have exited nonzero");
    } catch (err: any) {
      expect(err.status).toBe(2);
      expect(String(err.stderr ?? "")).toContain("--format must be");
    }
  });
});
