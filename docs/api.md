# Local REST API

Base URL: `http://127.0.0.1:8765`. All operational routes are also available
under `/api` for the frontend proxy / single-server build. OpenAPI JSON is at
`/openapi.json`; `/docs` uses locally installed Swagger assets.

If `SENTINEL_API_TOKEN` is set, pass `Authorization: Bearer ...`. Otherwise only
loopback operational access is permitted. Health remains public. Errors use
`{"error":{"code":"...","message":"..."},"request_id":"..."}`; request-schema
errors also contain safe field details.

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
