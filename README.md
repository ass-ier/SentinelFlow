# SentinelFlow

**Local detection engineering, with an evidence trail.**

SentinelFlow is a security analytics portfolio application built around a real
event pipeline, configurable YAML detections, and reproducible validation.
It runs on your workstation without a cloud account, paid API, or external
security platform. It is **not a production SIEM**.

![SentinelFlow dashboard](screenshots/dashboard.png)

## Run locally

Release baseline: **Python 3.13.15**, **Node 24.21.0 LTS**, and **npm 11.19.0**.
Use `.python-version` and `.nvmrc`. Development and validation
were exercised on macOS; the commands also target Linux. Dependencies are pinned
in `requirements.lock` (development and runtime), `requirements-runtime.lock`
(production only), and `frontend/package-lock.json`.

```sh
make install
make validate
.venv/bin/python scripts/demo_reset.py --offline --seed
make dev
```

Open **http://127.0.0.1:5173**. The API is at
**http://127.0.0.1:8765**, with offline OpenAPI documentation at **/docs**.
`make dev` checks both ports and never terminates an existing process. To use
different ports, set `SENTINEL_BACKEND_PORT` and `SENTINEL_FRONTEND_PORT` before
starting it. See `.env.example`; secrets belong only in an untracked `.env`.

```sh
SENTINEL_BACKEND_PORT=8766 SENTINEL_FRONTEND_PORT=5174 make dev
```

Without an explicit `SENTINEL_ALLOWED_ORIGINS`, the allowed development origins
follow `SENTINEL_FRONTEND_PORT`. If you copied `.env.example`, update or remove
its explicit 5173 origin override when changing ports. CLI commands accept
`--api http://127.0.0.1:8766`; browser scripts use `SENTINEL_API_URL` and
`SENTINEL_UI_URL`. Do not accidentally reset another running instance.

Without Make:

```sh
python3 scripts/manage.py install
python3 scripts/manage.py validate
.venv/bin/python scripts/demo_reset.py --offline --seed
python3 scripts/manage.py dev
```

`manage.py` also accepts `test`, `lint`, `format`, `security-tools`, and `security`.
`SENTINELFLOW_PYTHON` can select an existing isolated environment without replacing
one used by another running process. After installation, the
core app, tests, datasets, replay, validation, and OpenAPI assets work offline.
Only the optional public-source reproduction scripts and initial dependency /
browser installation and the separate security/advisory gate require the network.
Explicitly enabled private Microsoft
and notification integrations also contact the owner's configured services;
their offline mock mode requires no credentials.

For a single production-build preview process:

```sh
npm --prefix frontend run build
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

Open http://127.0.0.1:8765 with a browser. JSON API clients can use `/api/events`,
`/api/alerts`, etc.; the documented unprefixed API routes also accept JSON
requests. HTML navigation serves the SPA without colliding with `/api`.

## Live Demo Deployment

The split deployment is **Vercel for the React/Vite frontend** and **Render for
the FastAPI backend**, using a dedicated SQLite database. It is a shared,
synthetic-data-only portfolio/security-engineering demonstration, **not a
production SIEM**. Nothing has been pushed or deployed to either provider.

Set `VITE_API_BASE_URL` in Vercel to the actual Render HTTPS origin. Set
`SENTINEL_PUBLIC_DEMO=true`, `SENTINEL_DATABASE_URL`, and the exact Vercel
`SENTINEL_ALLOWED_ORIGINS` in Render. The backend reads `PORT`, binds to
`0.0.0.0`, and serves `/health` and offline `/docs`. The public frontend uses
real cross-origin API requests, not a development proxy.

First startup loads 56 synthetic events and seven alerts. Public visitors can
investigate evidence, replay included data, validate detections, and compile/test
the licensed Sigma samples without credentials. Uploads, rule changes, status
notes, arbitrary Sigma input, developer endpoints, and visitor reset are
unavailable; private local functionality is preserved. An optional server-only
owner token permits reset to the fixed seed. Free Render storage is ephemeral;
persistent SQLite requires an explicitly chosen paid disk.

Use the [step-by-step deployment runbook](docs/deployment.md),
[readiness report](docs/deployment-readiness.md),
[checklist](docs/deployment-checklist.md), and
[public environment example](.env.public-demo.example). They distinguish actual
local/container/clone evidence from the hosted checks you must still perform.

```sh
make validate
.venv/bin/python scripts/verify_deployment.py \
  --label my-native-check --backend-port 18865 --frontend-port 18875
.venv/bin/python scripts/verify_deployment.py \
  --label my-docker-check --docker --backend-port 18866 --frontend-port 18876
```

Each label must be new. The verifier uses separate databases and production-build
outputs, runs real desktop/mobile browser workflows and restart/reset checks,
and leaves the original live instance and final media alone. It never publishes
an image or contacts a deployment service. See the runbook for manual equivalents.

| Owner-supplied link | Placeholder |
|---|---|
| Public demo | `LIVE_DEMO_URL` |
| Your GitHub repository | `GITHUB_URL` |
| Published demonstration video | `DEMO_VIDEO_URL` |

## What it does

The complete feature list below describes private/local mode. Public-demo
restrictions are deliberate boundaries, not simulated implementations.

- Normalize JSON, JSONL, CSV, authentication syslog, and Windows-style JSON into
  one nested event model. Preserve original field values and linked raw evidence.
- Evaluate nine predicate operators, nested AND/OR/NOT, inclusive event-time
  windows, thresholds, groups, and deterministic suppression using YAML rules.
- Investigate an alert through its pinned rule definition, exact contributing
  events, source/affected entities, event-time bounds, and raw records.
- Search event fields and time ranges; manage alert statuses and rule enablement.
- Replay included telemetry instantly, at real time, or at 10x, with real progress,
  cancellation, detections, and persisted evidence.
- Compare expected and observed rule IDs, severity, branch, and evidence counts
  in isolated positive, controlled-benign, mixed, boundary, and regression scenarios.
- Compile, import, and test a documented Sigma subset, including two unchanged,
  licensed upstream rules with author attribution on resulting alerts.
- Inspect actual dashboard metrics, measured benchmark output, validation receipts,
  dataset provenance, and the included repository content.
- Optionally receive Azure Monitor/Sentinel, Graph/Entra and authenticated
  Windows/WEF telemetry; investigate its source attribution without replacing
  the detection engine.
- Route alerts through a durable outbox to Power Automate or independent
  webhooks, with scoped credentials, retries, idempotency and attempt history.
  All external activity is disabled by default; public demo mode forbids it.

## Microsoft and notification integrations

Open **Integrations** in a private installation and run the offline demonstration.
The included Sentinel/Graph datasets each produce 13 events and two alerts;
the Windows dataset produces 36 events and seven alerts. Notifications are sent
to an actual local mock HTTP receiver, with persisted delivery evidence.
No live tenant, domain, Power Automate flow, Teams channel or external webhook
has been tested or created.

Use the [integration setup and architecture guide](docs/integrations.md),
[Windows collector runbook](collector/windows/README.md),
[fixture manifest](test-data/integrations/README.md), and
[detailed implementation/validation report](docs/integrations-implementation-report.md).

```sh
.venv/bin/python scripts/validate_integrations.py
```

This isolated check is also part of `make validate`. Secret values belong only
in the backend environment; administration forms accept reference names.
Existing screenshots and the six-minute recording document the original phase,
not these new integrations or a live Microsoft connection.

## Security release assessment

The [security assessment](docs/security-assessment.md) records the scanned
dependency set, confirmed fixes, exact regression results, source/image identities,
SBOMs and limitations. Historical screenshots/video are preserved, not represented
as a recording of the security changes.

The final local gate passed on **2026-09-28**: **801 backend tests, 145 frontend
tests and 127 browser checks**, with zero reported dependency findings in the
specified scanned set. Raw findings, technical classifications and before/after
evidence are saved in [the evidence index](docs/results/security/README.md).
This does not certify the preserved older running processes, live integrations,
hosted deployment or unscanned host/optional native tooling.

```sh
# Public advisory/tool downloads; no live integration credentials required.
make security-tools
frontend/node_modules/.bin/playwright install chromium
make security
```

The full gate executes `make validate`'s equivalent, Python/npm/OSV/Retire.js,
Gitleaks current-tree/history, Bandit/Semgrep, filesystem and both production-image
scans, SBOM generation, real browser workflows, collector outage/restart, and
native/Docker rehearsals. Missing tools, stale evidence, incomplete coverage,
unreviewed findings or failed phases result in **BLOCKED** and a nonzero exit.
Use `python3 scripts/manage.py security` without Make. Each execution creates a
new directory under `artifacts/security/`; do not publish that directory wholesale.

`make validate` remains offline after installation. It is not a substitute for
current vulnerability databases. The public-mode API schema omits private
administration, integration, ingestion and developer operations. Scoped credentials
support optional timezone-aware expiry; blank/legacy expiry remains explicitly
non-expiring. Original owner tokens are static configuration, not user sessions.

The GitHub Actions workflow adds a daily and pull-request gate, but configuring
it does not mean hosted CI or a deployment has run. No live Microsoft, Graph,
Windows domain, Power Automate, Teams or external webhook is verified.

## Architecture

```mermaid
flowchart LR
    UI["React / TypeScript analyst UI"] --> API["FastAPI / OpenAPI"]
    CLI["Replay, validate, reset CLI"] --> API
    API --> Parse["JSON / JSONL / CSV / syslog / Windows parsers"]
    Parse --> Model["Pydantic normalized events + raw evidence"]
    Model --> Store[("SQLAlchemy / SQLite")]
    API --> Rules["YAML rules / restricted Sigma compiler"]
    Rules --> Engine["Event-time predicate + correlation engine"]
    Model --> Engine
    Engine --> Alerts["Alerts / statuses / evidence links"]
    Alerts --> Store
    Fixtures["Saved deterministic datasets + authored expectations"] --> Validation["Isolated validation"]
    Validation --> Engine
```

A modular monolith, not microservices. SQLAlchemy separates persistence from
the engine; SQLite is the zero-configuration default. See
[architecture](docs/architecture.md) and [data model](docs/data-model.md).

## Included detections

| ID | Detection / default policy | Severity | ATT&CK mapping |
|---|---|---|---|
| AUTH-001 | 10 failed logins per source in 300 seconds, including multiple users | High | T1110 |
| AUTH-002 | 3 account lockouts per host in 300 seconds | Medium | T1110 |
| PROC-001 | PowerShell encoding, download, or dynamic-execution indicators | High | T1059.001 |
| IAM-001 | Privileged membership / identity changes outside narrow maintenance policy | High | T1098 |
| PROC-002 | Office-to-interpreter relationships and configurable command patterns | High | T1059.003, T1204.002 |
| DNS-001 | Long labels, repeated entropy heuristics, or 20 queries/source/minute | Medium | T1071.004 |
| NET-001 | 3 connections in 120 seconds to configured unusual destination ports | Medium | T1048 |

These are **indicators for investigation**, not proof of compromise, tunneling,
exfiltration, or technique coverage. Legitimate installers can match PowerShell
rules. DNS bursts and service-discovery names can match DNS rules. Policy and
controlled-benign exceptions are explained in
[detection-engine.md](docs/detection-engine.md).

## Evidence and validation

```sh
make test
make lint
make validate
.venv/bin/python scripts/validate_detections.py
.venv/bin/python scripts/validate_sigma.py
.venv/bin/python scripts/benchmark_detection.py
```

`make validate` runs environment/dependency checks, Ruff, strict MyPy, frontend
lint/format/types/build, byte-for-byte fixture reproduction, the full backend
and frontend tests, exact detection scenarios, licensed Sigma compatibility,
and the measured benchmark. **Any failed phase makes the command fail.**
Parser/replay/negative/security categories must have executed tests; empty or
skipped suites cannot produce a validated receipt.

The original delivery evidence (`b987e6d`) records **268 backend tests and 93 frontend
tests passed**, **50 exact detection scenarios**, **14/14 controlled benign
scenarios**, **4 Sigma compatibility cases**, and **33 live browser checks**.
The latter groups are reported separately, not added to the 361 unique unit /
integration test cases. Every measured benchmark iteration processed 5,600
events, evaluated 39,200 event-rule pairs, and produced exactly 700 alerts.
See [executed results](docs/results/README.md) for measured timings, coverage,
environment, raw receipts, and their limitations.

Deployment preparation adds access, configuration, public-mode and cross-platform
lock regressions. Its current counts and separate production-browser,
container and clone receipts are recorded in the
[deployment readiness report](docs/deployment-readiness.md). Historical screenshots
and the final recording have not been regenerated to imply a hosted deployment.

A clean installation exposed npm advisories in the original dependency pins.
The affected packages were upgraded, eight offline regression guards were
added, and the subsequent npm audit reported zero known advisories. This is a
dated registry result, not a guarantee of vulnerability-free software; see
[dependency maintenance](docs/dependency-maintenance.md).

Current run output is under `artifacts/`. Committed, actual execution receipts
and measurements are under [docs/results](docs/results). Receipts contain a
content fingerprint; the Project evidence screen labels them **stale** if code,
rules, fixtures, or dependencies have changed. No stored alert can make an
isolated validation pass.

[Testing methodology and commands](docs/testing.md) ·
[Saved dataset manifest](test-data/README.md) ·
[Source and license provenance](docs/data-provenance.md) ·
[Fresh-clone and custom-port verification](docs/fresh-clone.md)

## Reproduce a detection

With the application running:

```sh
.venv/bin/python scripts/demo_reset.py
.venv/bin/python scripts/replay_events.py \
  --file test-data/authentication/brute_force.jsonl --speed instant
.venv/bin/python scripts/replay_events.py \
  --dataset powershell-indicators --speed 10x
.venv/bin/python scripts/validate_detections.py \
  --dataset auth-normal-failures --rule AUTH-001
```

The first replay processes 25 included failed logins and produces one AUTH-001
alert with 25 distinct evidence records. Each new replay is an isolated run.
Duplicate IDs inside a run cannot inflate a threshold; conflicting content is
rejected. Appends before a run's `(timestamp, event ID)` watermark are rejected
atomically. Rule toggles affect **new runs**, not an in-progress pinned replay.

Use the UI's Replay, Detection testing, and Sigma pages for the corresponding
backend-powered workflows. [Full demo procedure and recording](docs/demo.md).

The repository includes the [real six-minute application recording](recordings/sentinelflow-final-demo.mp4),
[media inspection receipt](recordings/recording.json), and all seven requested
screenshots plus a [mobile dashboard capture](screenshots/mobile-dashboard.png).
The recording shows actual replay arrivals, evidence, positive and benign
results, Sigma compilation, and a real `make validate` execution.

## Data and licensing

All deterministic synthetic datasets are saved in `test-data/`, with authored
expectations, counts, formats, and checksums. Synthetic identities are invented,
addresses are private/reserved, and domains use `.test`. The included benchmark
contains 5,600 persisted events across 100 separate hourly incident cycles.

Two SigmaHQ rules are included unchanged at a pinned revision under **DRL 1.1**,
not MIT. The original authors, source URIs, and license are retained in imported
rules **and messages based on matches**. See [Sigma support](docs/sigma.md).

A six-event privacy-reduced OTRF public lab sample exercises parser
interoperability. Its root MIT notice, archive hash, source row numbers,
transformations, and the upstream README licensing discrepancy are documented.
It is **not labeled benign**, and a non-match is not presented as public attack
detection success.

Application code and synthetic data: [MIT](LICENSE). Third-party materials keep
their own licenses: [notices](docs/third-party-notices.md).

## Security and honest limits

- Loopback-only unauthenticated mode. Optional ASCII bearer token, centralized
  access dependency, origin/Host protections, safe errors, and audit entries.
  The private full-stack Docker option requires a token. Public hosting requires
  the explicitly restricted synthetic-only mode, not weakened private access.
- Size/event/rule/concurrency limits, safe YAML/JSON, duplicate-key rejection,
  finite numbers, parameterized queries, and bounded regex evaluation. Log
  commands and uploaded payloads are **never executed**.
- No binary EVTX, packet capture, agents, production connectors, enterprise
  retention/search, distributed processing, full Sigma compatibility, tenancy,
  SSO/RBAC, or migration management.
- Re-evaluation on append favors deterministic correctness over streaming scale.
  Slow/late telemetry handling is explicit; it is not an enterprise correlation
  watermark implementation.
- Controlled synthetic negatives do not measure enterprise false-positive rates.
  The benchmark is a measured local, engine-only exercise, not a capacity promise.

See [security model](docs/security.md), [API](docs/api.md), and
[limitations](docs/limitations.md).

## Docker

```sh
# Supply your own randomly generated ASCII token; do not commit it.
export SENTINEL_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose up --build
```

Open http://127.0.0.1:8765 and enter that token in the UI's API settings.
The published port is loopback-only, the container runs as a non-root user, and
the demo database uses a named volume. This remains the private full-stack
option. `Dockerfile.backend` is the separate public API-only image used by the
deployment verifier; Vercel serves its frontend independently.

The original delivery did not execute Docker. The deployment report records
the later actual build/run attempts, the Linux hash-lock repair, the final
container results and their exact scope. Do not confuse a parsed Compose file
or an older receipt with a completed container test.
