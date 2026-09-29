# Architecture

SentinelFlow is a single FastAPI application and a separately built React SPA.
The default local development supervisor runs Vite and Uvicorn on loopback.
The built SPA and vendored Swagger assets can also be served by FastAPI alone.
There are no required runtime cloud dependencies. Optional private connectors
and notifications make background calls only when explicitly configured;
their disabled/offline behavior and local mocks remain credential-free.

```mermaid
flowchart TB
    Sources["Included files / analyst uploads"] --> Parsing["parsers: bounded format parsing"]
    Parsing --> Normalization["schemas: UTC events, stable IDs, raw values, DNS features"]
    Normalization --> Ingest["services.Platform: atomic ingest"]
    Rules["rules/*.yml"] --> RuleStore["SQLAlchemy rule store"]
    Sigma["Untrusted Sigma YAML"] --> Compiler["Restricted compiler + preserved provenance"]
    Compiler --> RuleStore
    RuleStore --> Snapshot["Immutable per-run rule snapshot"]
    Ingest --> Engine["detection.engine: chronological evaluation"]
    Snapshot --> Engine
    Engine --> Alerts["Correlated episodes and exact evidence IDs"]
    Ingest --> DB[("SQLite: runs, events, alerts, evidence, audit")]
    Alerts --> DB
    DB --> API["Typed request boundaries / parameterized search / analytics"]
    API --> UI["Dashboard / explorer / alert detail / rules / testing / replay / Sigma"]
    Expectations["Saved independently authored expected results"] --> Validator["Isolated validation"]
    Validator --> Engine
    Validator --> Reports["Actual JSON + text reports / fingerprints"]
```

## Boundaries

| Module | Responsibility |
|---|---|
| `core` | Configuration, input limits, safe decoding, access checks, receipt fingerprints |
| `schemas` | Strict normalized domain objects and API request types |
| `parsers` | JSON/JSONL/CSV, syslog authentication, explicit Windows-provider JSON |
| `detection` | Generic predicates, time windows/correlation, restricted Sigma translation |
| `services` | Ingest transactions, replay jobs, rule/status operations, isolated validation |
| `storage` | SQLAlchemy models and session/engine ownership |
| `api` | REST routes, request validation, local evidence/document endpoints |
| `integrations` | OAuth providers, normalization adapters, durable checkpoints/outbox, safe HTTP, collector and optional worker |
| `frontend` | Accessible analyst workflows; no hardcoded operational metrics |
| `scripts` | Install/dev/validation/replay/reset/benchmark/source reproduction |

## Persistence and run isolation

An operational run owns a snapshot of the currently enabled rule definitions.
An observation is unique on `(run_id, event.id)`, and its storage ID incorporates
the run ID. Replaying the same file creates a fresh, separately identified run.
Duplicates inside a run must have identical normalized content, including raw
evidence; conflicting IDs reject the whole batch.

Manual/replay batches are sorted and compared against the committed `(timestamp, ID)`
watermark. Late manual appends fail before a database mutation is committed. Evaluation
reconstructs the run in event-time order and deterministically upserts alerts,
preserving analyst status and exact evidence foreign keys. This is deliberately
simpler and slower than a production streaming engine.

Connector-only runs add a durable source dedup ledger and deliberately allow
late data with chronological re-evaluation. Events, checkpoint, detections,
evidence and notification outbox commit atomically; HTTP delivery happens after
that transaction. Stable overlapping alert identity prevents duplicate
notifications and preserves investigation status. See
[integration architecture and limits](integrations.md).

Validation does not share operational correlation state or persist its alerts.
It reads checksum-verified fixtures and immutable bundled definitions, unless
the analyst explicitly selects current rule state. Expected outcomes are saved
independently of engine output.

Replay uses a small in-process worker pool. Progress and terminal states are
persisted; cancellation is cooperative. On restart, interrupted replay records
become explicit failures rather than hanging or reporting completion.

## Database portability

SQLAlchemy entities and JSON fields isolate storage from detection. SQLite
foreign keys, WAL, and busy timeouts are configured only on SQLite connections.
No detection relies on vendor-specific SQL or interpolated SQL text. PostgreSQL
would require a driver/configuration and migration/deployment work, not a new
detection engine. The additive migration runner adopts the original schema as
revision 1 and adds optional integration tables as revision 2, without rewriting
core rows. It refuses unknown future versions before changing tables. SQLite
leases and insertion conflict handling are used by the integration worker;
PostgreSQL would also require adapting those helpers. This is not a full
Alembic upgrade/downgrade framework.
