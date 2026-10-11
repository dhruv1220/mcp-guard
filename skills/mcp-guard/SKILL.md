---
name: mcp-guard
description: Audit and harden MCP servers with mcp-guard. Use when the user adds, reviews, or asks about MCP server security — scan configs for auth/transport/secret risks, probe a server's real tool surface, generate a deny-by-default policy, wrap the server in the enforcement gateway, and tighten the policy from the audit log.
---

# mcp-guard — security and cost control for MCP servers

mcp-guard is installed as the `mcpguard` CLI. It answers three questions about
any MCP server: **is the config safe?** (`scan`), **what can this server actually
do?** (`probe`), and **how do I keep it inside a sandbox?** (`gateway` + `learn`).

Zero runtime dependencies. Secrets are redacted in all output.

## 1. Audit the config before trusting a server

Run this whenever the user adds a new MCP server, pastes an `mcpServers` block,
or asks "is my setup safe":

```bash
mcpguard scan --config ~/.claude.json
# or: mcpguard scan --config ./mcp.json --format json --fail-on high
```

Read the findings table, highest severity first, and explain each in plain
language: what is exposed, and what an attacker (or a compromised server) could
do with it. Priorities:

- `risky-stdio-command` (critical–medium) — `curl | sh`, `sudo`, encoded
  PowerShell, unpinned `npx -y` auto-installs. This is the most common real
  infection vector: the command in the config IS the payload.
- `hardcoded-secret` (high) — tokens committed in `env`/headers. Tell the user
  to rotate the secret and move it to an env var or secret manager; never echo
  the value back.
- `no-auth` / `plaintext-http` (high) — remote servers with no auth or over
  plain HTTP. Anyone on the network path can read and inject tool traffic.
- `npm-supply-chain` (medium) — `npx`/`uvx` packages that don't exist on npm or
  were published < 90 days ago (possible typosquat / fresh account).

Offer to fix: rewrite the config entry (pin the package version, add the
`Authorization` header via env var, switch to `https://`). Re-run `scan` to
confirm the finding clears. Use `--fail-on` in CI to gate merges.

## 2. Learn what the server can really do

Config entries lie by omission. Before writing a policy, enumerate the live
tool surface:

```bash
mcpguard probe -- node my-server.mjs
```

This spawns the server, runs `initialize` + `tools/list`, and prints every
tool with its description and input schema. Summarize for the user: which tools
read, which write, which touch the network or shell — that summary is the
threat model the policy must cover.

Turn the probe straight into a starter policy (deny-by-default, every
discovered tool set to `approval` so nothing runs unattended):

```bash
mcpguard init-policy --server myserver -- node my-server.mjs > policy.json
```

## 3. Enforce the policy with the gateway

Wrap the server so every `tools/call` is checked before it reaches the server:

```bash
mcpguard gateway --policy ./policy.json --server myserver -- node my-server.mjs
```

How to explain it: per-tool `allow`/`deny`/`approval`, argument constraints
(`pattern`, `enum`, `maxLength`, `required`), secret redaction in the audit
log, session budgets (`maxCalls`, `maxResultBytes`, `maxSessionMs`) that trip
a circuit breaker against runaway agents, and flag-only prompt-injection
screening of tool output (`injectionFlags` on the audit record — heuristic,
never blocking). Denied calls get a JSON-RPC error and are never forwarded;
a crashed server fails closed.

For interactive tightening, run with `--interactive`: the operator approves
each risky call on the controlling terminal (`y` once, `a` always, `n` deny,
`x` never). Then freeze what was observed into a tight policy:

```bash
mcpguard learn --audit ./mcpguard-audit.jsonl --server myserver > tight-policy.json
```

**Always tell the user to review the learned policy before deploying it** —
it reflects what happened during the session, not what should happen.

## 4. The standard hardening flow

When the user says "harden this server" or "lock down my MCP setup", run the
full loop and report each step:

1. `mcpguard scan --config <their config>` — baseline findings.
2. `mcpguard probe -- <server command>` — real tool surface.
3. `mcpguard init-policy --server <name> -- <server command> > policy.json` —
   starter deny-by-default policy.
4. Edit the policy with the user: `allow` the tools they need with argument
   constraints, keep everything else `deny` or `approval`.
5. `mcpguard gateway --policy ./policy.json --server <name> -- <server command>`
   — run behind the gateway.
6. `mcpguard learn --audit ./mcpguard-audit.jsonl --server <name>` — tighten.

## Rules

- Never print or repeat secret values from configs, env, or audit logs. If a
  finding involves a secret, say which field holds it and how to rotate it.
- Never weaken a policy on your own authority (no flipping `deny` to `allow`,
  no widening `pattern`s) — propose the change and let the user approve.
- `approval` tools deny in non-interactive use; say so when a call is blocked.
- Token/cost estimation is out of scope: budgets measure forwarded calls,
  result bytes, and wall time — say exactly that if asked.
