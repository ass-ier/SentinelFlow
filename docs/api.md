# REST API

Base URL: `http://127.0.0.1:8765`. All operational routes are also available
under `/api` for the frontend proxy / single-server build. OpenAPI JSON is at
`/openapi.json`; `/docs` uses locally installed Swagger assets.

If `SENTINEL_API_TOKEN` is set, pass `Authorization: Bearer ...`. Otherwise only
loopback operational access is permitted. Health remains public. Errors use
`{"error":{"code":"...","message":"..."},"request_id":"..."}`; request-schema
errors also contain safe field details.

The above authentication behavior is the default **private/local mode**.
With `SENTINEL_PUBLIC_DEMO=true`, visitors need no credentials for the restricted
synthetic workflows. Both route prefixes enforce the same public restrictions.
Uploads, rule mutation/import, alert status/notes, arbitrary Sigma sources and
developer project endpoints return `public_demo_restricted`. Only an optional
backend owner token permits public reset, and `seed:true` is mandatory there.

Private `/health` retains its original three fields. Public health additionally
returns `public_demo:true` and `public_demo_run_limit:20`, while
`auth_required:false` describes visitor access. No secret or database content is
included. Public datasets/scenarios contain 49 synthetic cases; full local
validation retains all 50. Public validation/compilation and replay return 429
when their process-local capacity is occupied.

| Method / path | Behavior |
|---|---|
| GET `/health` | Readiness/version and whether a token is required |
| GET `/dashboard` | Real scoped metrics, event-time bins, top sources/rules/MITRE |
| POST `/events` | `{format,content,name?,run_id?,syslog_year?}`; atomic parse/ingest/detect |
| POST `/events/upload` | Multipart UTF-8 file and explicit format |
| GET `/events`, `/events/search` | Paginated event search |
| GET `/events/{storage_id}` | Normalized observation and raw evidence |
| GET `/rules`, `/rules/{id}` | Definitions, YAML, provenance and enabled state |
| POST `/rules` | Import a validated internal YAML rule; duplicate IDs rejected |
| PATCH `/rules/{id}` | `{enabled}`; applies to new runs |
| POST `/rules/{id}/test` | `{dataset_id,expected_alerts?}`; isolated definition test |
| GET `/alerts`, `/alerts/{id}` | Queue or exact evidence/rule snapshot |
| PATCH `/alerts/{id}/status` | `{status,note?}` with audit entry |
| GET `/datasets` | Actual included manifest, checksum, source/license and expectation |
| GET `/runs` | Recent persisted run state |
| GET `/runs/{id}/feed` | Latest observed events and actual alerts |
| POST `/detections/replay` | `{dataset_id,speed}`; starts an isolated job, returns 202 |
| GET `/detections/replay/{id}` | Real processed/total/duplicate/alert counters and terminal state |
| POST `/detections/replay/{id}/cancel` | Cooperative cancellation |
| GET `/detections/scenarios` | Authored scenario specifications |
| POST `/detections/validate` | `{dataset_id?,rule_id?,scope?}`; `bundled` or `current` |
| GET `/sigma/samples` | Two unchanged, licensed examples with provenance/fixtures |
| POST `/sigma/compile` | `{yaml,source_url?,license?,license_url?}`; no persistence |
| POST `/sigma/import` | Same plus `enabled?`; defaults to disabled |
| POST `/sigma/test` | Same plus `dataset_id,expected_alerts`; isolated output |
| GET `/project/evidence` | Actual validation log, receipt freshness, benchmark and file inventory |
| GET `/project/document` | Whitelisted repository documentation only |
| POST `/admin/demo-reset` | `{confirmation:"RESET DEMO",seed?}`; named demo DB only |

Event filters: `source_ip`, `user_name`, `category`, `action`, `outcome`,
`host_name`, `process_name`, `severity`, `event_type`, `event_source`, `run_id`,
timezone-aware `timestamp_from` and `timestamp_to`, and `q` (literal substring
over indexed display fields). Pagination uses `offset` and `limit` (1-100).
`event_source` is the log provider; it is not `source_ip`.

Alert filters: `run_id`, `severity`, `status`, `rule_id`, and literal substring
`q` over rule ID/name, source addresses, affected hosts, and users.
List responses contain `items`, `total`, `offset`, `limit` as applicable.

## Optional private integration APIs

All routes below have the same `/api` alias and structured error convention.
Administration requires the existing private analyst/local-owner policy.
Scoped integration tokens cannot administer configuration or analyst state.
Public synthetic mode denies mutations regardless of owner token and keeps
external integration tables empty.

| Method / path | Behavior |
|---|---|
| GET `/integrations` | Connector/profile catalog, counters and worker state |
| GET/POST `/integrations/connectors` | List/create bounded connector configuration |
| PATCH `/integrations/connectors/{id}` | Edit configuration; source identity immutable after ingestion |
| POST `/integrations/connectors/{id}/enabled` | `{enabled}`; live enable flags still required |
| POST `/integrations/connectors/{id}/test` | Real query/authentication check, no ingestion |
| POST `/integrations/connectors/{id}/poll` | Process bounded pages and persist checkpoints |
| POST `/integrations/demo` | `{source}`; deterministic local HTTP demonstration |
| POST `/ingest/windows` | `{connector_id,events}`; 202 exact stored/duplicate counts; bound `windows:ingest` token required |
| GET/POST `/notifications/destinations` | List/create Power Automate or webhook configuration |
| PATCH/DELETE `/notifications/destinations/{id}` | Edit/soft-delete while retaining delivery history |
| POST `/notifications/destinations/{id}/enabled` | `{enabled}`; disable suppresses unsent work |
| GET/POST `/notifications/policies` | List/create independent notification routing |
| PATCH/DELETE `/notifications/policies/{id}` | Modify/remove a routing policy |
| POST `/alerts/{id}/notify` | `{destination_ids}`; queue idempotently, 202; owner or `alerts:notify` |
| POST `/notifications/test` | `{destination_id}`; explicit test message, 202; owner or `notifications:test` |
| GET `/notifications/deliveries` | `alert_id?`, `offset`, `limit` (1-100); actual persisted states |
| GET `/notifications/deliveries/{id}` | Payload and safe attempt history, no secret/response bodies |
| GET/POST `/integrations/credentials` | Manage environment references and explicit scopes |
| PATCH `/integrations/credentials/{id}` | Update/revoke a scoped credential reference |

New alert detail fields are `telemetry_sources` and `notifications`; detection
rule `provenance` retains its existing meaning. Event provider/connector/table/
channel/ingestion time lives in `metadata`, with raw evidence preserved.
`wazuh` is now an explicit import format for the documented EventChannel and
authentication-full-log subset. System/Application Windows events have their
own categories. See [integration setup and payload contract](integrations.md).

```sh
curl -sS http://127.0.0.1:8765/health
curl -sS 'http://127.0.0.1:8765/events/search?category=authentication'
curl -sS -H 'Content-Type: application/json' \
  -d '{"dataset_id":"auth-brute-force","speed":"instant"}' \
  http://127.0.0.1:8765/detections/replay
curl -sS -H 'Content-Type: application/json' \
  -d '{"dataset_id":"auth-normal-failures","scope":"bundled"}' \
  http://127.0.0.1:8765/detections/validate
```

In browser development, Vite proxies `/api` to the loopback backend. In the
single-server build, HTML navigation receives the SPA and `/api` remains
unambiguously JSON. No page or API simulates operational success locally.

In the split deployment, `VITE_API_BASE_URL` selects the backend origin and all
frontend requests use its `/api` routes. Public mode is API-only; it does not
serve the local `frontend/dist` directory. The Vercel frontend supplies SPA
routing independently. Configure exact CORS origins and backend hostnames as
described in [deployment.md](deployment.md). `/docs` remains available with
local assets; `/redoc` is intentionally not enabled.
