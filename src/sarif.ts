/**
 * SARIF 2.1.0 output for `mcpguard scan --format sarif`.
 *
 * Lets CI pipelines upload findings to GitHub code scanning (or any SARIF
 * consumer) with `github/codeql-action/upload-sarif`. Each result points
 * at the offending field inside its server's entry when the finding's
 * evidence identifies one (see `locateServerFields` and
 * `fieldPathForFinding`); otherwise it points at the server's entry (see
 * `locateServerEntries`); when the source text is unavailable or an entry
 * cannot be located, the result falls back to pointing at the file with
 * no region.
 */
import { ALL_CHECKS } from "./scanner/engine.js";
import type { Finding, ScanReport, Severity } from "./scanner/types.js";

const SARIF_VERSION = "2.1.0";
const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

const LEVEL: Record<Severity, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "none",
};

export interface SarifOptions {
  /** Path of the scanned config, used as the result artifact URI. */
  configPath?: string;
  /** Reported as the tool driver version. */
  toolVersion?: string;
  /**
   * Raw text of the scanned config. When supplied, each result gains a
   * region covering its offending field, or its server's entry when no
   * field is identified (see `locateServerFields`).
   * Only server/field names and line/column numbers are derived from it —
   * no values, and therefore no secrets, ever reach the output.
   */
  sourceText?: string;
}

/** Line range of one server entry in the source config (1-based). */
export interface ServerLocation {
  startLine: number;
  startColumn: number;
  endLine: number;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: string };
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number; startColumn: number; endLine: number };
    };
  }>;
}

function toRule(check: { id: string; title: string }): SarifRule {
  return {
    id: check.id,
    name: check.title,
    shortDescription: { text: check.title },
    defaultConfiguration: { level: "warning" },
  };
}

/**
 * The config field a finding's evidence points at, as a dotted path
 * inside the server entry (e.g. `env.GITHUB_TOKEN`, `url`, `args`).
 * Derived only from the evidence prefix, which the checks already emit
 * in redacted form — no secret value is ever read, only the field name
 * (which the SARIF message already contains via the evidence text).
 * Returns undefined when the evidence identifies no single field; the
 * caller then falls back to the whole server entry.
 */
export function fieldPathForFinding(f: Finding): string | undefined {
  const secret = /^(env|headers)\.(.+?) = /.exec(f.evidence);
  if (secret) return `${secret[1]}.${secret[2]}`;
  if (/^args\[\d+\] = /.test(f.evidence)) return "args";
  if (f.evidence.startsWith("url: ")) return "url";
  if (f.evidence.startsWith("command: ")) return "command";
  if (f.evidence.startsWith("args: ")) return "args";
  if (f.evidence.startsWith("package: ")) return "args";
  return undefined;
}

function toResult(
  f: Finding,
  configPath: string,
  locations: Map<string, ServerLocation>,
  fieldLocations: Map<string, Map<string, ServerLocation>> = new Map()
): SarifResult {
  const parts = [f.message];
  if (f.evidence) parts.push(`Evidence: ${f.evidence}`);
  if (f.remediation) parts.push(`Remediation: ${f.remediation}`);
  const fieldPath = fieldPathForFinding(f);
  const location =
    (fieldPath ? fieldLocations.get(f.server)?.get(fieldPath) : undefined) ??
    locations.get(f.server);
  return {
    ruleId: f.checkId,
    level: LEVEL[f.severity],
    message: { text: parts.join("\n") },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: configPath || f.server },
          ...(location
            ? {
                region: {
                  startLine: location.startLine,
                  startColumn: location.startColumn,
                  endLine: location.endLine,
                },
              }
            : {}),
        },
      },
    ],
  };
}

/**
 * Map each server name to the line range of its entry in a config file's
 * raw text: the key's line/column through the closing line of its value.
 *
 * This is a position-aware JSON parse, not a text search: a server name
 * that appears inside another entry's string value is never mistaken for
 * that entry's key, because only strings in key position inside the
 * `mcpServers` object (or the bare top-level map, when there is no
 * `mcpServers` wrapper — mirroring `loadConfig`) are recorded. Duplicate
 * keys resolve last-wins, matching `JSON.parse`. Malformed JSON yields
 * an empty map, so callers fall back to file-only locations.
 */
/** One server entry plus every nested field inside it, by dotted path. */
interface ServerFields {
  name: string;
  location: ServerLocation;
  fields: Map<string, ServerLocation>;
}

/** Collect every nested key inside an object, as dotted paths. */
function collectFields(
  obj: ParsedObject,
  prefix: string,
  out: Map<string, ServerLocation>
): void {
  for (const entry of obj.entries) {
    const path = prefix ? `${prefix}.${entry.key}` : entry.key;
    out.set(path, {
      startLine: entry.keyLine,
      startColumn: entry.keyColumn,
      endLine: entry.value.endLine,
    });
    if (entry.value.object) collectFields(entry.value.object, path, out);
  }
}

/**
 * Parse the server entries out of a config's raw text (the `mcpServers`
 * wrapper, or the bare top-level map when there is no wrapper — mirroring
 * `loadConfig`). Returns null for malformed JSON or a non-object top
 * level; callers treat that as "nothing locatable".
 */
function parseServers(source: string): ServerFields[] | null {
  try {
    const top = new JsonParser(source).parseTop();
    if (!top.object) return null;
    let serverEntries = top.object.entries;
    const serversEntry = top.object.entries.find(
      (e) => e.key === "mcpServers"
    );
    if (serversEntry?.value.object)
      serverEntries = serversEntry.value.object.entries;
    return serverEntries.map((entry) => {
      const fields = new Map<string, ServerLocation>();
      if (entry.value.object) collectFields(entry.value.object, "", fields);
      return {
        name: entry.key,
        location: {
          startLine: entry.keyLine,
          startColumn: entry.keyColumn,
          endLine: entry.value.endLine,
        },
        fields,
      };
    });
  } catch {
    return null;
  }
}

export function locateServerEntries(
  source: string
): Map<string, ServerLocation> {
  const servers = parseServers(source);
  if (!servers) return new Map();
  const locations = new Map<string, ServerLocation>();
  for (const server of servers) locations.set(server.name, server.location);
  return locations;
}

/**
 * Map each server name to its nested fields, by dotted path inside the
 * server entry: top-level fields (`url`, `command`, `args`) and nested
 * ones (`env.GITHUB_TOKEN`, `headers.Authorization`). A field's region
 * runs from its key line through its value's end line, so a scalar field
 * is one line and an object field spans its braces. Only key names and
 * line/column numbers are recorded — never values, so no secret can
 * leak through regions. Malformed JSON yields an empty map.
 */
export function locateServerFields(
  source: string
): Map<string, Map<string, ServerLocation>> {
  const servers = parseServers(source);
  if (!servers) return new Map();
  const fields = new Map<string, Map<string, ServerLocation>>();
  for (const server of servers) fields.set(server.name, server.fields);
  return fields;
}

interface ParsedEntry {
  key: string;
  keyLine: number;
  keyColumn: number;
  value: ParsedValue;
}

interface ParsedObject {
  entries: ParsedEntry[];
  endLine: number;
}

interface ParsedValue {
  endLine: number;
  object?: ParsedObject;
}

/** Minimal JSON parser that retains object structure and value end lines. */
class JsonParser {
  private pos = 0;
  private line = 1;
  private col = 1;

  constructor(private readonly text: string) {}

  private peek(): string {
    return this.text[this.pos] ?? "";
  }

  private next(): string {
    const ch = this.text[this.pos] ?? "";
    this.pos += 1;
    if (ch === "\n") {
      this.line += 1;
      this.col = 1;
    } else {
      this.col += 1;
    }
    return ch;
  }

  private skipWhitespace(): void {
    while (this.pos < this.text.length && " \t\r\n".includes(this.peek())) {
      this.next();
    }
  }

  private expect(ch: string): void {
    if (this.peek() !== ch) {
      throw new Error(`expected ${ch} at ${this.line}:${this.col}`);
    }
    this.next();
  }

  parseTop(): ParsedValue {
    const value = this.parseValue();
    this.skipWhitespace();
    if (this.pos < this.text.length) throw new Error("trailing data");
    return value;
  }

  private parseValue(): ParsedValue {
    this.skipWhitespace();
    const ch = this.peek();
    if (ch === "{") return this.parseObject();
    if (ch === "[") return this.parseArray();
    if (ch === '"') {
      this.parseString();
      return { endLine: this.line };
    }
    // true / false / null / number: consume until a structural delimiter.
    const start = this.pos;
    while (this.pos < this.text.length && !",}] \t\r\n".includes(this.peek())) {
      this.next();
    }
    if (this.pos === start) {
      throw new Error(`unexpected input at ${this.line}:${this.col}`);
    }
    return { endLine: this.line };
  }

  private parseObject(): ParsedValue {
    this.expect("{");
    const entries: ParsedEntry[] = [];
    this.skipWhitespace();
    if (this.peek() === "}") {
      this.next();
      return { endLine: this.line, object: { entries, endLine: this.line } };
    }
    for (;;) {
      this.skipWhitespace();
      if (this.peek() !== '"') {
        throw new Error(`expected object key at ${this.line}:${this.col}`);
      }
      const keyLine = this.line;
      const keyColumn = this.col;
      const key = this.parseString();
      this.skipWhitespace();
      this.expect(":");
      const value = this.parseValue();
      entries.push({ key, keyLine, keyColumn, value });
      this.skipWhitespace();
      const ch = this.peek();
      if (ch === ",") {
        this.next();
        continue;
      }
      if (ch === "}") {
        this.next();
        break;
      }
      throw new Error(`expected , or } at ${this.line}:${this.col}`);
    }
    return { endLine: this.line, object: { entries, endLine: this.line } };
  }

  private parseArray(): ParsedValue {
    this.expect("[");
    this.skipWhitespace();
    if (this.peek() === "]") {
      this.next();
      return { endLine: this.line };
    }
    for (;;) {
      this.parseValue();
      this.skipWhitespace();
      const ch = this.peek();
      if (ch === ",") {
        this.next();
        continue;
      }
      if (ch === "]") {
        this.next();
        break;
      }
      throw new Error(`expected , or ] at ${this.line}:${this.col}`);
    }
    return { endLine: this.line };
  }

  /** Parse a JSON string; returns its decoded value. Advances past the closing quote. */
  private parseString(): string {
    this.expect('"');
    let out = "";
    for (;;) {
      if (this.pos >= this.text.length) throw new Error("unterminated string");
      const ch = this.next();
      if (ch === '"') break;
      if (ch === "\\") {
        const esc = this.next();
        if (esc === "u") {
          let hex = "";
          for (let i = 0; i < 4; i += 1) hex += this.next();
          out += String.fromCharCode(Number.parseInt(hex, 16));
        } else {
          out += { n: "\n", t: "\t", r: "\r", b: "\b", f: "\f" }[esc] ?? esc;
        }
      } else {
        out += ch;
      }
    }
    return out;
  }
}

/** Render a scan report as a SARIF 2.1.0 log. Secrets stay redacted: findings carry redacted evidence by contract. */
export function formatSarif(report: ScanReport, opts: SarifOptions = {}): string {
  const configPath = opts.configPath ?? "";
  const locations =
    opts.sourceText !== undefined
      ? locateServerEntries(opts.sourceText)
      : new Map<string, ServerLocation>();
  const fieldLocations =
    opts.sourceText !== undefined
      ? locateServerFields(opts.sourceText)
      : new Map<string, Map<string, ServerLocation>>();
  const log = {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-guard",
            version: opts.toolVersion ?? "0.0.0",
            informationUri: "https://github.com/dhruv1220/mcp-guard",
            rules: ALL_CHECKS.map(toRule),
          },
        },
        artifacts: configPath
          ? [{ location: { uri: configPath } }]
          : [],
        results: report.findings.map((f) =>
          toResult(f, configPath, locations, fieldLocations)
        ),
      },
    ],
  };
  return JSON.stringify(log, null, 2);
}
