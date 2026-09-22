# mcp-guard

**The open-source security and cost control plane for MCP servers.**

AI agents now consume dozens of MCP servers, skills, and plugins — most of them installed with a copy-pasted config and never reviewed. Industry scans keep finding the same story: a large share of public MCP servers ship with no authentication, plaintext transport, hardcoded secrets, and auto-executed packages straight from the registry. mcp-guard exists to make that visible and fixable.

## What it does

- **`mcpguard scan`** — statically audit an MCP client config (`mcpServers` JSON) for authentication gaps, insecure transport, hardcoded secrets, risky commands, and npm supply-chain risk. Findings are severity-ranked, secrets are redacted in output, and `--fail-on` gates CI.
- **`mcpguard gateway`** — a transparent enforcement proxy for one MCP server: every `tools/call` is checked against a JSON policy (per-tool allow/deny/approval, argument patterns, enums, max lengths) before it reaches the server. Denied calls get a JSON-RPC error and are never forwarded; every decision lands in a JSONL audit log with redacted arguments, latency, and result size. Session budgets (`maxCalls`, `maxResultBytes`, `maxSessionMs`) trip a circuit breaker against runaway agents, and tool output is screened for prompt-injection tells (flagged on the audit record). Fail-closed: a crashed server ends the session.
- **`mcpguard probe`** — enumerate a server's real tool surface: spawns it, runs `initialize` + `tools/list`, and prints the tools (names, descriptions, input schemas) as JSON. Know what you're about to write a policy for.
- **Roadmap** — prompt-injection screening of tool output and a Claude Code skill. See [issues](https://github.com/dhruv1220/mcp-guard/issues).

## Quickstart

```bash
npm install -g mcp-guard
mcpguard scan --config ~/.claude.json
# or point at any config file with an "mcpServers" block
mcpguard scan --config ./mcp.json --format json --fail-on high
```

## Gateway (v0.2)

Wrap any stdio MCP server with a policy:

```bash
mcpguard gateway --policy ./policy.json --server filesystem -- npx -y @modelcontextprotocol/server-filesystem /safe
```

`examples/policy.json`:

```json
{
  "version": 1,
  "defaultAction": "deny",
  "auditLog": "./mcpguard-audit.jsonl",
  "logArgs": true,
  "servers": {
    "filesystem": {
      "tools": {
        "read_file": { "action": "allow", "args": { "path": { "pattern": "^/safe/" } } },
        "delete_file": "deny"
      }
    }
  }
}
```

Rules: a tool entry is `"allow" | "deny" | "approval"` or `{ action, args, redactArgs }`.
`args` constrains each named argument (`pattern`, `enum`, `maxLength`, `required`).
Deny always wins; unknown tools fall back to the server's `defaultAction`, then the
root `defaultAction`. `"approval"` denies in non-interactive use. Secret-looking
argument values are redacted in the audit log automatically.

### Session budgets

Add a `budgets` block to cap what one session may consume. When a cap trips, the
circuit breaks and every further `tools/call` is denied:

```json
{ "budgets": { "maxCalls": 200, "maxResultBytes": 1048576, "maxSessionMs": 3600000 } }
```

Budgets measure what the proxy can observe honestly — forwarded call count, total
tool-result bytes, wall time. Token/cost estimation is out of scope for v1.

### Output screening

Tool results are scanned for prompt-injection tells (`ignore previous
instructions`, `reveal the system prompt`, `you are now …`, etc.). Screening is
flag-only — matches are recorded as `injectionFlags` on the audit record, never
used to block, since detection is heuristic. Disable with
`"screenOutput": false` in the policy.

## Probing a server's tool surface

```bash
mcpguard probe -- node my-server.mjs
```

Spawns the server, runs `initialize` + `tools/list`, and prints the real tool
surface as JSON — know what you're about to write a policy for. Fails fast on
spawn errors; `--timeout <ms>` bounds the whole probe (default 15000).

Turn a probe straight into a starter policy (deny-by-default, every discovered
tool set to `approval` so nothing runs until you allowlist it):

```bash
mcpguard init-policy --server filesystem -- npx -y @modelcontextprotocol/server-filesystem /safe > policy.json
```

## Checks (v0.1)

| Check ID | Severity | What it flags |
|---|---|---|
| `no-auth` | high | Remote (HTTP/SSE) server with no `Authorization` header or token |
| `plaintext-http` | high | Remote URL over `http://` instead of `https://` |
| `wildcard-bind` | medium | Server URL bound to `0.0.0.0` (exposed to the local network) |
| `hardcoded-secret` | high | API keys / tokens committed in `env` or headers (redacted in output) |
| `risky-stdio-command` | critical–medium | `curl … \| sh`, `sudo`, encoded PowerShell, unpinned `npx -y` auto-install |
| `npm-supply-chain` | medium | `npx`/`uvx` package missing from npm or published < 90 days ago |

## Development

```bash
npm install
npm run typecheck && npm run build && npm test
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Zero runtime dependencies by design.

## License

MIT — see [LICENSE](LICENSE).
