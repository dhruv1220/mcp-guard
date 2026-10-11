import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { formatSarif } from "../src/sarif.js";
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
