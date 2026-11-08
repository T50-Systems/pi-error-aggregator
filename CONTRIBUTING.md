# Contributing

1. Create a focused branch.
2. Keep diagnostics stateless and post-redaction unless an ADR explicitly changes that decision.
3. Do not add fixtures containing real session content, paths, credentials, or tokens.
4. Run:

```bash
pnpm install --frozen-lockfile
pnpm run verify
npm pack --dry-run
```

Changes affecting persistence, new session roots, raw context, telemetry, network calls, or automated remediation require architecture review before implementation.
