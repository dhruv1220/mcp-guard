# Contributing to mcp-guard

## Ground rules

- Every check ships with unit tests, including adversarial cases (placeholders must not flag, real secrets must).
- Scanner output **never prints raw secret values** — findings carry redacted evidence only. Tests enforce this.
- Zero runtime dependencies. Dev dependencies are fine.
- One check per pull request, with docs updated in the same PR.

## Workflow

```bash
npm install
npm run typecheck   # strict TS, must pass
npm run build       # emits dist/
npm test            # vitest
```

New checks live in `src/scanner/checks.ts` and follow the `Check` interface in
`src/scanner/types.ts`: an `id`, a human `title`, and a `run(server)` function
returning findings. Async checks (network) go in the async section and must
degrade gracefully offline (`--no-network` skips them).
