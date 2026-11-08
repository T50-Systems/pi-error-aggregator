# pi-error-aggregator

Public Pi extension that scans persisted session JSONL files on demand and reports recurring errors without creating another error database.

## Install

```bash
pi install git:github.com/T50-Systems/pi-error-aggregator@v0.1.0
```

Run `/reload` when installing into an active Pi session.

## Interfaces

- `/errors` — grouped summary across all sessions (backward compatible)
- `/errors current list 50` — newest 50 errors from the current session
- `/errors new 20` — fingerprints present in the current session but absent from history
- `/errors show <fingerprint> [all|current] 20` — redacted occurrence drill-down
- `/errors compare 20` — current-only, recurring, and historical-only groups
- `session_errors` — equivalent LLM-callable tool with `action`, `scope`, `mode`, `limit`, and filters

## Filters

Filters are additive and operate only on redacted in-memory errors:

```text
/errors current summary 20 --kind tool --source bash --since 24h
/errors new --project pi --exclude model,rate-limit
/errors compare --since 7d
```

Supported filters: `--kind`, `--source`, `--project`, `--since`, and repeatable `--exclude`. `since` accepts ISO timestamps or bounded relative values such as `30m`, `24h`, `7d`, or `2w`. Exclusions are per invocation and are never persisted.

Known recurring patterns receive deterministic local recovery hints (rate limits, missing paths/modules, WorkGuard output bounds, FFF roots, and non-zero command exits). No model call or automatic remediation is performed.

## Detected errors

- tool results with `isError: true`
- assistant messages with `stopReason: "error"`
- user bash executions with a non-zero exit code
- failed/error custom entries, including `subagents:record`
- custom messages whose `details.error` is a string unless explicitly marked successful

Only errors persisted in session JSONL are detectable. Startup crashes and extension errors that Pi only writes to stderr are outside this tool's data source.
Aborted/cancelled operations are not classified as failures.

## Privacy and limits

- read-only, on-demand scanning; no index or aggregate log is written
- raw user/assistant prompts are ignored
- absolute/home filesystem paths, common credentials, tokens, URL credentials, and long opaque blobs are redacted before storage in memory or output
- output uses sanitized source labels, project basenames, and shortened session IDs, never session-file paths
- scan caps: 10,000 files, 10,000 errors, 512 MiB total input, and 4 MiB per JSONL line
- report caps: 100 rows per view, 240 lines, and 48 KiB output
- malformed, oversized, and unreadable input is counted and skipped; active stream reads honor cancellation

## Development

```bash
pnpm install --frozen-lockfile
pnpm run verify
```
