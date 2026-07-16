# Architecture

## Decision

Use stateless, on-demand aggregation over `SessionManager.listAll()` results. Do not persist a derived error index.

## Flow

1. The command/tool obtains session file paths from Pi's `SessionManager`.
2. `scanner.ts` streams JSONL through a bounded line splitter under global file/error/byte and per-line budgets.
3. Exact session error markers are extracted; ordinary prompts and successful results are ignored.
4. Error text and source/session/project labels are redacted, control-sanitized, and length-bounded before entering the in-memory result array.
5. A normalized SHA-256 fingerprint groups volatile variants without exposing raw text.
6. `query.ts` applies bounded filters, per-request exclusions, deterministic hints, fingerprint drill-down, and current/history set comparisons using only `SessionError` values.
7. `format.ts` renders report/new/show/compare views using project basenames and short session IDs.
8. The extension applies a final output line/byte cap.

## Guardrails

- no writes, watchers, background indexing, network calls, or raw-message output
- unreadable, malformed, or oversized input fails per file/line rather than aborting the whole scan
- limits cannot be disabled through the public tool or command
- tool `details` contains counts only, never raw errors
- current/history comparison is stateless and excludes the current session ID from the historical partition
- exclusions are invocation-local; no ignore or baseline file is written
- recovery hints are deterministic rules and never execute remediation
- active stream reads honor `AbortSignal`; Pi's metadata-only `SessionManager.listAll()` phase is not cancellable
- installing the extension changes global Pi configuration and must be mirrored to private `my-pi-cli`
