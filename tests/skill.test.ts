import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  findSkillSource,
  installSkill,
  readSkillFrontmatter,
  resolveSkillDir,
  SKILL_NAME,
  skillStatus,
} from "../src/skill.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "dist", "cli.js");
const KNOWN_COMMANDS = new Set([
  "scan",
  "gateway",
  "probe",
  "init-policy",
  "learn",
  "install-skill",
]);

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "mcpguard-skill-"));
}

describe("resolveSkillDir", () => {
  it("resolves user-level installs under ~/.claude/skills", () => {
    expect(resolveSkillDir({ home: "/tmp/fakehome" })).toBe(
      join("/tmp/fakehome", ".claude", "skills", SKILL_NAME)
    );
  });

  it("resolves project-level installs under <cwd>/.claude/skills", () => {
    expect(resolveSkillDir({ scope: "project", cwd: "/tmp/proj" })).toBe(
      join("/tmp/proj", ".claude", "skills", SKILL_NAME)
    );
  });

  it("an explicit dir wins over scope resolution", () => {
    expect(resolveSkillDir({ scope: "project", dir: "/tmp/explicit", cwd: "/tmp/proj" })).toBe(
      "/tmp/explicit"
    );
  });
});

describe("installSkill", () => {
  it("installs SKILL.md with valid frontmatter", () => {
    const dir = join(tmp(), "skills");
    const result = installSkill({ dir });
    expect(result.installed).toBe(true);
    expect(result.dir).toBe(dir);
    const { name, description } = readSkillFrontmatter();
    expect(name).toBe(SKILL_NAME);
    expect(description.length).toBeGreaterThan(20);
    const installed = readFileSync(join(dir, "SKILL.md"), "utf-8");
    expect(installed).toContain(`name: ${SKILL_NAME}`);
  });

  it("refuses to overwrite an existing install without --force", () => {
    const dir = join(tmp(), "skills");
    expect(installSkill({ dir }).installed).toBe(true);
    writeFileSync(join(dir, "SKILL.md"), "user-edited");
    const second = installSkill({ dir });
    expect(second.installed).toBe(false);
    expect(readFileSync(join(dir, "SKILL.md"), "utf-8")).toBe("user-edited");
  });

  it("overwrites with --force", () => {
    const dir = join(tmp(), "skills");
    installSkill({ dir });
    writeFileSync(join(dir, "SKILL.md"), "user-edited");
    const forced = installSkill({ dir, force: true });
    expect(forced.installed).toBe(true);
    expect(readFileSync(join(dir, "SKILL.md"), "utf-8")).toContain(
      `name: ${SKILL_NAME}`
    );
  });

  it("every mcpguard command referenced in SKILL.md exists in the CLI", () => {
    const skill = readFileSync(join(findSkillSource(), "SKILL.md"), "utf-8");
    const mentioned = new Set(
      [...skill.matchAll(/mcpguard\s+([a-z-]+)/g)].map((m) => m[1]!)
    );
    expect(mentioned.size).toBeGreaterThan(0);
    for (const cmd of mentioned) {
      expect(KNOWN_COMMANDS.has(cmd), `SKILL.md references unknown command: ${cmd}`).toBe(true);
    }
  });
});

describe("skillStatus", () => {
  it("reports installed state per scope", () => {
    const home = tmp();
    const cwd = tmp();
    const before = skillStatus({ home, cwd });
    expect(before.find((s) => s.scope === "user")!.installed).toBe(false);
    installSkill({ scope: "project", home, cwd });
    const after = skillStatus({ home, cwd });
    expect(after.find((s) => s.scope === "user")!.installed).toBe(false);
    expect(after.find((s) => s.scope === "project")!.installed).toBe(true);
  });
});

describe("install-skill cli", () => {
  it("installs to --dir and prints the path", () => {
    const dir = join(tmp(), "out");
    const out = execFileSync("node", [cli, "install-skill", "--dir", dir], {
      encoding: "utf-8",
    });
    expect(out).toContain(`installed mcp-guard skill to ${dir}`);
    expect(readFileSync(join(dir, "SKILL.md"), "utf-8")).toContain("mcp-guard");
  });

  it("is idempotent without --force and exits 0", () => {
    const dir = join(tmp(), "out");
    execFileSync("node", [cli, "install-skill", "--dir", dir], { encoding: "utf-8" });
    const out = execFileSync("node", [cli, "install-skill", "--dir", dir], {
      encoding: "utf-8",
    });
    expect(out).toContain("already installed");
  });

  it("appears in --help", () => {
    const out = execFileSync("node", [cli, "--help"], { encoding: "utf-8" });
    expect(out).toContain("install-skill");
  });
});
