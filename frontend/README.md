# SentinelFlow frontend

The local investigation and detection-engineering interface. All displayed operational
data comes from the backend API; the application has no fixture fallback. The only
mocked data lives in `tests/`.

## Development

Use Node **20.19.2** (also recorded in `.nvmrc`).

```sh
cd frontend
npm ci
npm run dev
```

Vite binds to `127.0.0.1:5173`. Requests to `/api/*` are proxied to
`127.0.0.1:8765`, with `/api` removed on the proxy request. Override ports without
changing source:

```sh
SENTINEL_FRONTEND_PORT=5174 SENTINEL_BACKEND_PORT=8766 npm run dev
```

The production build retains same-origin `/api` URLs. The backend must serve
`frontend/dist`, support `/api` routes, and return the SPA entry point for frontend
routes. `npm run preview` is only a static build preview, not a replacement API server.

## Verification

```sh
npm run typecheck
npm run lint
npm run format:check
npm test
npm run test:report
npm run build
```

`npm run format` applies Prettier. `test:report` writes the actual Vitest JSON report
to `frontend/test-results/vitest.json`; this generated directory is ignored by Git.
`build` runs TypeScript checking before generating `dist/`.

All direct dependencies are exactly pinned, with a committed npm lockfile.
Playwright and `ffmpeg-static` are included for repository-level browser verification
and recording; neither is required at application runtime. Unit tests do not replace
the parent project’s real API/browser validation.

## Workbenches

| Route                 | Purpose                                                                                             |
| --------------------- | --------------------------------------------------------------------------------------------------- |
| `/`                   | Five live statistics, activity intervals, recent alerts, source/rule/ATT&CK activity                |
| `/events`             | Exact-field and substring search, UTC filters, pagination, file or pasted ingestion                 |
| `/events/:storage_id` | Complete normalized event and safely escaped original input                                         |
| `/alerts`             | Filtered investigation queue                                                                        |
| `/alerts/:id`         | Status updates, exact trigger evidence, attribution, independently accessible pinned rule           |
| `/rules`              | Global catalog, client-side search, persisted enable/disable                                        |
| `/rules/:id`          | Current definition, YAML, criteria, provenance, isolated definition tests                           |
| `/testing`            | Bundled/current validation with exact expected-versus-observed results                              |
| `/replay`             | Real job polling, arrival feed, cancellation, retained run history                                  |
| `/sigma`              | Pinned samples, backend compilation/import/testing, attribution and subset limitations              |
| `/evidence`           | Read-only validation log, generated reports, measured benchmark, repository inventory and documents |

`run_id` in the URL controls event and alert scope. Navigation preserves it; imports
and new replays focus their returned run. Replay URLs additionally use `replay_id`
to reopen a job. Rule enable state is global and applies to **new** runs. Existing
alerts display the pinned definition, even if the current catalog no longer has it.

## Trust and execution boundaries

- Telemetry files and pasted logs are limited to 5 MiB before submission. Sigma YAML
  files and pasted source have a separate 64 KiB UTF-8 byte limit. Input format is
  explicit; real EVTX is unsupported. Optional syslog years are limited to 1970–2100.
- Raw input, rule source, compiler errors, and project documents render through React
  text nodes. No raw HTML, dynamic code execution, or log-derived shell commands are used.
- External provenance links allow only HTTP(S) and use `noopener noreferrer`.
- Connection settings save an optional operator-provided Bearer token in this tab’s
  `sessionStorage`. Tokens must be at most 256 printable ASCII characters with no
  whitespace; invalid values are rejected, not trimmed. There is no bundled token or
  persistent local-storage credential.
- Validation is isolated from operational runs. Unknown expectations stay **OBSERVED**,
  never PASS. Downloaded JSON is the complete returned report.
- Isolated validation alerts expose their actual metadata and inline triggering
  evidence, with expandable raw input. They deliberately do not link to operational
  alert or event URLs: those isolated IDs are not persisted there. Count-only
  expectations label evidence counts **Not asserted**, not zero.
- Replay progress comes from backend counters. Polling is sequential, approximately
  every 500 ms while active; terminal jobs stop polling. Cancellation must be confirmed
  by the backend.
- Project evidence polls the real artifact endpoint every 1.5 seconds so external
  `make validate` execution appears without a fabricated progress sequence. This page
  cannot execute commands. A missing artifact is explicitly not yet validated. Recorded
  suite counts, overlapping test categories, executed commands, coverage, and benchmark
  metrics remain distinct. Stale source fingerprints receive an explicit warning rather
  than a current-validation claim; partially failed runs do not fabricate missing counts.

## UI implementation

`src/components/ui.tsx` supplies semantic reusable controls, panels, statuses, table
regions, loading/error/empty states, and inert code blocks. Feature components reuse
those primitives. All timestamps are labeled UTC, including input boundaries; precise
UTC fractional timestamps are preserved in evidence views.
Process basenames remain separate from preserved full executable paths; Sigma `Image`
and `ParentImage` use `process.executable` and `process.parent.executable`. Compiled
and pinned definitions without YAML are shown as the exact returned canonical JSON.

The sidebar collapses to keyboard-operable inline navigation on small screens. Dense
tables scroll within their own labeled regions instead of widening the page. The UI
uses system fonts, local monospace fallbacks, visible focus, native form controls and
dialogs, and reduced-motion overrides. See `DESIGN.md` for the implemented visual rules.
