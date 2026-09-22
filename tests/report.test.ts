import { describe, expect, it } from "vitest";
import { formatJson, formatTable } from "../src/report.js";
import type { ScanReport } from "../src/scanner/types.js";

function reportWith(secret: string): ScanReport {
  return {
    scannedAt: "2026-09-22T00:00:00.000Z",
    servers: ["gh"],
    findings: [
      {
        checkId: "hardcoded-secret",
        title: "Hardcoded secret in config",
        severity: "high",
        server: "gh",
        message: "msg",
        evidence: `env.GITHUB_TOKEN = ghp_…••••••••`,
        remediation: "fix",
      },
    ],
    summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    skippedNetworkChecks: false,
  };
}

describe("formatTable", () => {
  it("renders findings grouped by severity", () => {
    const out = formatTable(reportWith("x"));
    expect(out).toContain("1 server(s), 1 finding(s) (1 high)");
    expect(out).toContain("[HIGH] hardcoded-secret · gh");
    expect(out).toContain("Evidence:");
    expect(out).toContain("Fix:");
  });

  it("renders a clean report", () => {
    const clean: ScanReport = {
      scannedAt: "x",
      servers: ["a"],
      findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      skippedNetworkChecks: false,
    };
    expect(formatTable(clean)).toContain("Clean — no findings.");
  });

  it("notes skipped network checks", () => {
    const r = reportWith("x");
    r.skippedNetworkChecks = true;
    expect(formatTable(r)).toContain("--no-network");
  });
});

describe("formatJson", () => {
  it("round-trips as JSON", () => {
    const r = reportWith("x");
    expect(JSON.parse(formatJson(r))).toEqual(r);
  });
});
