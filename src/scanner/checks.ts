import type {
  Check,
  CheckContext,
  Finding,
  McpServerDef,
  Severity,
} from "./types.js";

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

/** Redact a secret for display: keep a short prefix, hide the rest. */
export function redactSecret(value: string): string {
  const v = value.trim().replace(/["']/g, "");
  if (v.length <= 8) return "••••••••";
  return `${v.slice(0, 4)}…${"•".repeat(Math.min(v.length - 4, 8))}`;
}

/** Values that are clearly placeholders, not real secrets. */
const PLACEHOLDER_RE =
  /(\$\{[^}]+\}|%[A-Z_]+%|<[^>]*>|\b(x{3,}|changeme|replace-?me|your[-_ ]?(api[-_ ]?)?key|test|example|dummy|none|null|undefined)\b)/i;

export function looksLikePlaceholder(value: string): boolean {
  return value.trim() === "" || PLACEHOLDER_RE.test(value);
}

interface SecretPattern {
  label: string;
  re: RegExp;
}

const SECRET_PATTERNS: SecretPattern[] = [
  { label: "OpenAI-style API key", re: /\bsk-(?:ant|proj)-[A-Za-z0-9-_]{16,}/ },
  { label: "GitHub token", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}/ },
  { label: "GitHub fine-grained PAT", re: /\bgithub_pat_[A-Za-z0-9_]{20,}/ },
  { label: "AWS access key ID", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { label: "Slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/ },
  { label: "private key material", re: /-----BEGIN (?:RSA )?PRIVATE KEY-----/ },
  { label: "Bearer token", re: /\bBearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}/ },
];

const SENSITIVE_KEY_RE = /token|secret|passwd|password|api[_-]?key|auth|private/i;

function findSecret(value: string): string | null {
  if (looksLikePlaceholder(value)) return null;
  for (const p of SECRET_PATTERNS) {
    if (p.re.test(value)) return p.label;
  }
  return null;
}

function finding(
  checkId: string,
  title: string,
  severity: Severity,
  server: string,
  message: string,
  evidence: string,
  remediation: string
): Finding {
  return { checkId, title, severity, server, message, evidence, remediation };
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

/**
 * True when a URL carries credentials in its userinfo
 * (`https://user:pass@host` or a bare token as username,
 * `https://token@host`). Either form is a credential: it must be
 * flagged, never printed.
 */
export function urlHasCredentials(url: string): boolean {
  try {
    const u = new URL(url);
    return u.username !== "" || u.password !== "";
  } catch {
    return false;
  }
}

/**
 * Query-string parameter names that carry credentials. A token in the
 * query string is auth of the worst kind: URLs land in access logs,
 * proxies, error reports, and shell history, and the value is visible
 * to every hop — unlike a header, which stays out of the URL.
 */
const CREDENTIAL_QUERY_PARAMS = new Set([
  "access_token",
  "api_key",
  "apikey",
  "token",
  "secret",
]);

/**
 * The credential-bearing query parameters present in a URL
 * (lowercased names, deduplicated). Malformed URLs have none.
 */
export function urlQueryCredentials(url: string): string[] {
  try {
    const u = new URL(url);
    const found = new Set<string>();
    for (const k of u.searchParams.keys()) {
      if (CREDENTIAL_QUERY_PARAMS.has(k.toLowerCase())) found.add(k.toLowerCase());
    }
    return [...found];
  } catch {
    return [];
  }
}

/**
 * Replace a URL's userinfo with a placeholder, keeping the rest
 * (scheme, host, port, path, query, fragment) intact so evidence
 * still shows which server the finding is about. Credential-bearing
 * query parameters have their values replaced the same way — a
 * `?api_key=` value is a secret and must never reach scan output —
 * while benign parameters are left byte-identical. Malformed URLs
 * pass through unchanged — callers already skip those.
 */
export function redactUrlCredentials(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return url;
  }
  const hasUserinfo = parsed.username !== "" || parsed.password !== "";
  const queryCreds = urlQueryCredentials(url);
  if (!hasUserinfo && queryCreds.length === 0) return url;
  // Redact by string surgery on the raw query, not via URLSearchParams:
  // re-serializing would percent-encode the placeholder and mangle
  // benign parameters. The leading "?" stays attached to the first part.
  const search = parsed.search
    .split("&")
    .map((part) => {
      const eq = part.indexOf("=");
      if (eq === -1) return part;
      // The leading "?" rides along on the first part; strip it for
      // the key comparison but keep it in the rebuilt output.
      const rawKey = part.slice(0, eq);
      const key = rawKey.startsWith("?") ? rawKey.slice(1) : rawKey;
      let decoded = key;
      try {
        decoded = decodeURIComponent(key);
      } catch {
        /* keep the raw key on undecodable input */
      }
      if (CREDENTIAL_QUERY_PARAMS.has(decoded.toLowerCase())) {
        return `${part.slice(0, eq + 1)}•••`;
      }
      return part;
    })
    .join("&");
  return `${parsed.protocol}//${hasUserinfo ? "•••@" : ""}${parsed.host}${parsed.pathname}${search}${parsed.hash}`;
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1"]);

/* ------------------------------------------------------------------ */
/* transport checks                                                    */
/* ------------------------------------------------------------------ */

const noAuthCheck: Check = {
  id: "no-auth",
  title: "Remote server without authentication",
  async: false,
  run(server) {
    if (server.transport === "stdio" || !server.url) return [];
    const headers = server.headers ?? {};
    const hasAuthHeader = Object.keys(headers).some(
      (k) => k.toLowerCase() === "authorization"
    );
    // A credential in the query string is auth, of a bad kind —
    // url-query-credentials flags it, so no-auth stays silent instead
    // of double-flagging. (urlQueryCredentials is safe on malformed
    // URLs: it returns [] rather than throwing.)
    const hasUrlToken = urlQueryCredentials(server.url).length > 0;
    // Userinfo credentials are auth, of a bad kind — url-credentials
    // flags them, so no-auth stays silent instead of double-flagging.
    if (hasAuthHeader || hasUrlToken || urlHasCredentials(server.url)) return [];
    return [
      finding(
        "no-auth",
        "Remote server without authentication",
        "high",
        server.name,
        `Remote MCP server has no Authorization header or URL token — anyone who can reach it can invoke its tools.`,
        `url: ${redactUrlCredentials(server.url)}`,
        "Put the server behind OAuth 2.0/OIDC or add an Authorization header. Never commit bearer tokens in the URL — reference them from the environment."
      ),
    ];
  },
};

const plaintextHttpCheck: Check = {
  id: "plaintext-http",
  title: "Plaintext HTTP transport",
  async: false,
  run(server) {
    if (server.transport === "stdio" || !server.url) return [];
    let proto = "";
    try {
      proto = new URL(server.url).protocol;
    } catch {
      return [];
    }
    if (proto !== "http:") return [];
    const host = hostOf(server.url);
    if (LOOPBACK.has(host)) {
      return [
        finding(
          "plaintext-http",
          "Plaintext HTTP transport",
          "info",
          server.name,
          "Server uses plaintext HTTP, but only on loopback — low risk on a trusted machine.",
          `url: ${redactUrlCredentials(server.url)}`,
          "Prefer https:// or a Unix socket even for local servers when the machine is shared."
        ),
      ];
    }
    return [
      finding(
        "plaintext-http",
        "Plaintext HTTP transport",
        "high",
        server.name,
        "Server URL uses http:// — tool calls, results, and any credentials travel unencrypted.",
        `url: ${redactUrlCredentials(server.url)}`,
        "Serve the MCP endpoint over https:// (or tunnel it). Rotate any credential that already traversed plaintext."
      ),
    ];
  },
};

const wildcardBindCheck: Check = {
  id: "wildcard-bind",
  title: "Server bound to 0.0.0.0",
  async: false,
  run(server) {
    if (server.transport === "stdio" || !server.url) return [];
    if (hostOf(server.url) !== "0.0.0.0") return [];
    return [
      finding(
        "wildcard-bind",
        "Server bound to 0.0.0.0",
        "medium",
        server.name,
        "Server URL binds 0.0.0.0 — the MCP endpoint is exposed to the whole local network, not just this machine (the 'NeighborJack' pattern).",
        `url: ${redactUrlCredentials(server.url)}`,
        "Bind to 127.0.0.1 unless remote access is intentional, and require authentication either way."
      ),
    ];
  },
};

const urlCredentialsCheck: Check = {
  id: "url-credentials",
  title: "Credentials embedded in server URL",
  async: false,
  run(server) {
    if (server.transport === "stdio" || !server.url) return [];
    if (!urlHasCredentials(server.url)) return [];
    return [
      finding(
        "url-credentials",
        "Credentials embedded in server URL",
        "high",
        server.name,
        "Server URL embeds credentials in its userinfo — URLs land in logs, shell history, screen shares, and error reports, so the credential leaks far beyond this config file.",
        `url: ${redactUrlCredentials(server.url)}`,
        "Move the credential to an Authorization header (referenced from the environment, never committed) and rotate the exposed credential."
      ),
    ];
  },
};

const urlQueryCredentialsCheck: Check = {
  id: "url-query-credentials",
  title: "Credentials in server URL query string",
  async: false,
  run(server) {
    if (server.transport === "stdio" || !server.url) return [];
    const params = urlQueryCredentials(server.url);
    if (params.length === 0) return [];
    return [
      finding(
        "url-query-credentials",
        "Credentials in server URL query string",
        "high",
        server.name,
        `Server URL carries a credential in its query string (?${params.join(", ?")}=…) — query strings are logged by servers, proxies, and error reporters, so the credential leaks to every hop. Treat it as exposed and rotate it.`,
        `url: ${redactUrlCredentials(server.url)}`,
        "Move the credential to an Authorization header (referenced from the environment, never committed) and rotate the exposed credential."
      ),
    ];
  },
};

/* ------------------------------------------------------------------ */
/* secret checks                                                       */
/* ------------------------------------------------------------------ */

const hardcodedSecretCheck: Check = {
  id: "hardcoded-secret",
  title: "Hardcoded secret in config",
  async: false,
  run(server) {
    const out: Finding[] = [];
    const sources: [string, Record<string, string>][] = [];
    if (server.env && Object.keys(server.env).length > 0) sources.push(["env", server.env]);
    if (server.headers && Object.keys(server.headers).length > 0)
      sources.push(["headers", server.headers]);

    for (const [source, entries] of sources) {
      for (const [key, rawValue] of Object.entries(entries)) {
        const value = String(rawValue);
        if (looksLikePlaceholder(value)) continue;
        const label = findSecret(value);
        const sensitiveName = SENSITIVE_KEY_RE.test(key);
        if (label) {
          out.push(
            finding(
              "hardcoded-secret",
              "Hardcoded secret in config",
              "high",
              server.name,
              `${label} committed in ${source}.${key} — anyone with read access to this config (dotfiles repos, backups, screen shares) gets the credential.`,
              `${source}.${key} = ${redactSecret(value)}`,
              "Move the value to an environment variable (${VAR} is left alone by this check) or a secret manager, and rotate the exposed credential."
            )
          );
        } else if (sensitiveName && value.length >= 20) {
          out.push(
            finding(
              "hardcoded-secret",
              "Hardcoded secret in config",
              "high",
              server.name,
              `Suspiciously secret-shaped value in ${source}.${key} (long, high-entropy, sensitive name).`,
              `${source}.${key} = ${redactSecret(value)}`,
              "If this is a real credential, move it to the environment and rotate it. If not, rename the key to avoid the tripwire."
            )
          );
        }
      }
    }
    // stdio arguments: argv is a third credential channel, after env
    // and headers. A token passed as `--api-key <value>` or
    // `--token=<value>` shows up in process listings (`ps`), shell
    // history, and process managers — and in this config file itself.
    // The whole argument is redacted in evidence, never just the
    // matched substring, so `--flag=<secret>` forms leak nothing.
    if (server.args && server.args.length > 0) {
      server.args.forEach((raw, i) => {
        const value = String(raw);
        if (looksLikePlaceholder(value)) return;
        const label = findSecret(value);
        if (label) {
          out.push(
            finding(
              "hardcoded-secret",
              "Hardcoded secret in config",
              "high",
              server.name,
              `${label} passed as a stdio argument — anyone who can list processes or read this config gets the credential.`,
              `args[${i}] = ${redactSecret(value)}`,
              "Move the value to an environment variable (${VAR} is left alone by this check) or a secret manager, and rotate the exposed credential."
            )
          );
          return;
        }
        // Long value handed to a sensitive flag (`--api-key <value>`):
        // no known pattern, but a 20+ character opaque value after a
        // credential-named flag is secret-shaped. Skip values that are
        // themselves flags.
        if (i > 0 && !value.startsWith("-") && value.length >= 20) {
          const prev = String(server.args![i - 1]).replace(/^-+/, "");
          if (SENSITIVE_KEY_RE.test(prev)) {
            out.push(
              finding(
                "hardcoded-secret",
                "Hardcoded secret in config",
                "high",
                server.name,
                `Suspiciously secret-shaped value passed to --${prev} (long, high-entropy, sensitive flag name).`,
                `args[${i}] = ${redactSecret(value)}`,
                "If this is a real credential, move it to the environment and rotate it. If not, rename the flag to avoid the tripwire."
              )
            );
          }
        }
      });
    }
    return out;
  },
};

/* ------------------------------------------------------------------ */
/* stdio command checks                                                */
/* ------------------------------------------------------------------ */

const PIPE_TO_SHELL_RE = /\b(curl|wget)\b[^|]*\|\s*(sh|bash|zsh)\b/;
const ENCODED_PWSH_RE = /\bpowershell\b.*-(e|ec|en|enc|encodedcommand)\b/i;

function parsePackageRunner(
  server: McpServerDef
): { runner: string; pkg: string; pinned: boolean; autoInstall: boolean } | null {
  const cmd = (server.command ?? "").trim();
  const args = server.args ?? [];
  const m = /^(npx|pnpx|pnpm|bunx|uvx|uv)$/.exec(cmd.split(/[\\/]/).pop() ?? "");
  if (!m) return null;
  const runner = m[1] ?? "";
  if (!runner) return null;
  // pnpm dlx / bunx need the subcommand skipped; uv tool run too
  let rest = args;
  if ((runner === "pnpm" || runner === "uv") && rest[0] === "dlx") rest = rest.slice(1);
  if (runner === "uv" && rest[0] === "tool" && rest[1] === "run") rest = rest.slice(2);
  const noYes = rest.includes("-y") || rest.includes("--yes");
  const pkg = rest.find((a) => !a.startsWith("-")) ?? "";
  if (!pkg) return null;
  // Pinned only when an explicit version is present; anything else
  // auto-resolves to latest on every agent start.
  const pinned = stripVersion(pkg) !== pkg;
  return { runner, pkg, pinned, autoInstall: noYes };
}

const riskyStdioCommandCheck: Check = {
  id: "risky-stdio-command",
  title: "Risky stdio command",
  async: false,
  run(server) {
    if (server.transport !== "stdio") return [];
    const out: Finding[] = [];
    const cmdline = [server.command ?? "", ...(server.args ?? [])].join(" ");

    if (PIPE_TO_SHELL_RE.test(cmdline)) {
      out.push(
        finding(
          "risky-stdio-command",
          "Risky stdio command",
          "critical",
          server.name,
          "stdio args pipe a network download straight into a shell (curl|sh) — arbitrary remote code execution every time the agent starts.",
          `args: ${cmdline.slice(0, 160)}`,
          "Vendor the script or pin it by content hash; never pipe-to-shell in a tool the agent auto-starts."
        )
      );
    }
    if (/\bsudo\b/.test(cmdline)) {
      out.push(
        finding(
          "risky-stdio-command",
          "Risky stdio command",
          "high",
          server.name,
          "MCP server runs via sudo — a compromised or malicious server gets root.",
          `command: ${cmdline.slice(0, 160)}`,
          "Run as an unprivileged user; grant only the specific capabilities the server needs."
        )
      );
    }
    if (ENCODED_PWSH_RE.test(cmdline)) {
      out.push(
        finding(
          "risky-stdio-command",
          "Risky stdio command",
          "medium",
          server.name,
          "Encoded PowerShell invocation hides what the server actually runs.",
          `command: ${cmdline.slice(0, 160)}`,
          "Replace with a readable script checked into version control."
        )
      );
    }
    const pkg = parsePackageRunner(server);
    if (pkg && !pkg.pinned) {
      out.push(
        finding(
          "risky-stdio-command",
          "Risky stdio command",
          "medium",
          server.name,
          `Unpinned auto-install: \`${server.command} -y ${pkg.pkg}\` fetches the latest package on every start — a supply-chain compromise or breaking release hits you silently.`,
          `command: ${server.command} -y ${pkg.pkg}`,
          `Pin a version (${pkg.pkg}@x.y.z) and verify the publisher before first use.`
        )
      );
    }
    return out;
  },
};

/* ------------------------------------------------------------------ */
/* npm supply-chain check (async)                                      */
/* ------------------------------------------------------------------ */

const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;

/** Strip a `@version` suffix from an npm spec, keeping scopes intact. */
export function stripVersion(spec: string): string {
  const at = spec.lastIndexOf("@");
  if (at > 0) return spec.slice(0, at);
  return spec;
}

async function npmPackageAge(pkg: string): Promise<
  | { ok: true; daysOld: number; version: string; deprecated?: string }
  | { ok: false; reason: "not-found" | "network" }
> {
  try {
    const name = stripVersion(pkg);
    const res = await fetch(
      `https://registry.npmjs.org/${encodeURIComponent(name).replace("%40", "@")}`
    );
    if (res.status === 404) return { ok: false, reason: "not-found" };
    if (!res.ok) return { ok: false, reason: "network" };
    const meta = (await res.json()) as {
      "dist-tags": { latest: string };
      time: Record<string, string>;
      versions?: Record<string, { deprecated?: string }>;
    };
    const created = meta.time?.created;
    if (!created) return { ok: false, reason: "network" };
    const daysOld = (Date.now() - new Date(created).getTime()) / (24 * 60 * 60 * 1000);
    const version = meta["dist-tags"]?.latest ?? "unknown";
    // Deprecation lives on the latest version's entry; a deprecated
    // old version does not flag a package whose latest is clean.
    const deprecated = meta.versions?.[version]?.deprecated;
    return { ok: true, daysOld, version, deprecated };
  } catch {
    return { ok: false, reason: "network" };
  }
}

const npmSupplyChainCheck: Check = {
  id: "npm-supply-chain",
  title: "npm supply-chain risk",
  async: true,
  async run(server, ctx) {
    if (ctx.offline || server.transport !== "stdio") return [];
    const pkg = parsePackageRunner(server);
    if (!pkg || !["npx", "pnpm", "bunx", "uvx"].includes(pkg.runner)) return [];
    const name = stripVersion(pkg.pkg);
    const info = await npmPackageAge(name);
    if (!info.ok) {
      if (info.reason === "not-found") {
        return [
          finding(
            "npm-supply-chain",
            "npm supply-chain risk",
            "medium",
            server.name,
            `Package \`${name}\` is not on the npm registry — possible typo, rename, or private package. A typosquatted name here would execute on every agent start.`,
            `package: ${name}`,
            "Verify the exact package name and publisher; prefer scoped/official packages."
          ),
        ];
      }
      return []; // offline or registry hiccup — degrade silently
    }
    // Deprecation is the stronger signal and subsumes the age check:
    // a dead, unmaintained package auto-installed on every agent start
    // is the risk, whatever its age. The registry reason is display
    // text, not a secret, but it is truncated to keep evidence sane.
    if (info.deprecated) {
      const reason =
        info.deprecated.length > 120
          ? `${info.deprecated.slice(0, 117)}...`
          : info.deprecated;
      return [
        finding(
          "npm-supply-chain",
          "npm supply-chain risk",
          "medium",
          server.name,
          `Package \`${name}\`'s latest version (${info.version}) is deprecated — ${reason}`,
          `package: ${name}@${info.version} (deprecated)`,
          "Find a maintained alternative; pin a non-deprecated version only as a stopgap and verify the publisher before first use."
        ),
      ];
    }
    if (info.daysOld * 24 * 60 * 60 * 1000 < NINETY_DAYS_MS) {
      return [
        finding(
          "npm-supply-chain",
          "npm supply-chain risk",
          "medium",
          server.name,
          `Package \`${name}\` was first published ${Math.floor(info.daysOld)} days ago — newly-published packages are the most common supply-chain attack vector.`,
          `package: ${name}@${info.version} (${Math.floor(info.daysOld)}d old)`,
          "Check the publisher, repo link, and download counts before trusting it; pin the version."
        ),
      ];
    }
    return [];
  },
};

/* ------------------------------------------------------------------ */

export const ALL_CHECKS: Check[] = [
  noAuthCheck,
  plaintextHttpCheck,
  wildcardBindCheck,
  urlCredentialsCheck,
  urlQueryCredentialsCheck,
  hardcodedSecretCheck,
  riskyStdioCommandCheck,
  npmSupplyChainCheck,
];
