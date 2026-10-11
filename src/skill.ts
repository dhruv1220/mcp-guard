/**
 * Claude Code skill installation.
 *
 * The distributable skill lives at <package>/skills/mcp-guard/SKILL.md.
 * `installSkill` copies it into Claude Code's skill directory — either the
 * user-level `~/.claude/skills/mcp-guard` (default) or the project-level
 * `<cwd>/.claude/skills/mcp-guard` (with `--project`).
 */
import { cpSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";

export const SKILL_NAME = "mcp-guard";

export class SkillError extends Error {}

export interface SkillPaths {
  /** Directory containing the bundled SKILL.md shipped with this package. */
  sourceDir: string;
}

function candidateSourceDirs(): string[] {
  const here = dirname(fileURLToPath(import.meta.url));
  // Compiled layout: dist/skill.js -> <pkg>/skills/mcp-guard
  // Source layout (tests): src/skill.ts -> <repo>/skills/mcp-guard
  return [join(here, "..", "skills", SKILL_NAME), join(here, "..", "..", "skills", SKILL_NAME)];
}

/** Locate the bundled skill directory, whatever layout we're running from. */
export function findSkillSource(): string {
  for (const dir of candidateSourceDirs()) {
    if (existsSync(join(dir, "SKILL.md"))) return dir;
  }
  throw new SkillError(
    `bundled skill not found (looked in ${candidateSourceDirs().join(", ")})`
  );
}

export type SkillScope = "user" | "project";

export interface ResolveOptions {
  scope?: SkillScope;
  /** Explicit target directory (overrides scope resolution; used by tests). */
  dir?: string;
  /** Overrides for path resolution (tests). */
  home?: string;
  cwd?: string;
}

/** Resolve where the skill should be installed. */
export function resolveSkillDir(opts: ResolveOptions = {}): string {
  if (opts.dir) return opts.dir;
  const scope = opts.scope ?? "user";
  if (scope === "project") {
    return join(opts.cwd ?? process.cwd(), ".claude", "skills", SKILL_NAME);
  }
  return join(opts.home ?? homedir(), ".claude", "skills", SKILL_NAME);
}

export interface InstallOptions extends ResolveOptions {
  /** Overwrite an existing installation instead of refusing. */
  force?: boolean;
}

export interface InstallResult {
  dir: string;
  scope: SkillScope | "custom";
  /** True when files were written; false when an existing install was kept. */
  installed: boolean;
}

/**
 * Install the mcp-guard skill for Claude Code.
 * Refuses to overwrite an existing install unless `force` is set.
 */
export function installSkill(opts: InstallOptions = {}): InstallResult {
  const sourceDir = findSkillSource();
  const dir = resolveSkillDir(opts);
  const scope: InstallResult["scope"] = opts.dir
    ? "custom"
    : (opts.scope ?? "user");

  if (existsSync(join(dir, "SKILL.md")) && !opts.force) {
    return { dir, scope, installed: false };
  }
  try {
    mkdirSync(dir, { recursive: true });
    cpSync(sourceDir, dir, { recursive: true });
  } catch (err) {
    throw new SkillError(`failed to install skill to ${dir}: ${(err as Error).message}`);
  }
  return { dir, scope, installed: true };
}

export interface SkillStatus {
  scope: SkillScope;
  dir: string;
  installed: boolean;
}

/** Report whether the skill is installed at user and project level. */
export function skillStatus(opts: ResolveOptions = {}): SkillStatus[] {
  return (["user", "project"] as const).map((scope) => {
    const dir = resolveSkillDir({ ...opts, scope, dir: undefined });
    return { scope, dir, installed: existsSync(join(dir, "SKILL.md")) };
  });
}

/** Read the bundled SKILL.md frontmatter (name/description) for validation. */
export function readSkillFrontmatter(): { name: string; description: string } {
  const raw = readFileSync(join(findSkillSource(), "SKILL.md"), "utf-8");
  const match = raw.match(/^---\n([\s\S]*?)\n---\n/);
  if (!match) throw new SkillError("SKILL.md has no YAML frontmatter block");
  const name = match[1]!.match(/^name:\s*(.+)$/m)?.[1]?.trim();
  const description = match[1]!.match(/^description:\s*(.+)$/m)?.[1]?.trim();
  if (!name || !description) {
    throw new SkillError("SKILL.md frontmatter must define name and description");
  }
  return { name, description };
}
