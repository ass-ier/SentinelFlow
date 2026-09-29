# SentinelFlow deployment readiness

**READY WITH DOCUMENTED LIMITATIONS**

Prepared and verified locally on **2026-09-28**. The Vercel frontend / Render
backend configuration, public-demo restrictions, production builds, native and
Docker execution, clean-source installation, application workflows and
restart/reset behavior have been exercised. **Nothing has been committed,
pushed, authenticated to a deployment provider, or externally deployed.**

Use [deployment.md](deployment.md) for the exact owner-run procedure,
[deployment-checklist.md](deployment-checklist.md) for acceptance items, and
[results/deployment](results/deployment/README.md) for actual saved receipts.
The earlier [implementation status](implementation-status.md) remains a
historical, separately requested document; it was not overwritten.

## What is implemented and functional

| Area | Private/local installation | Public portfolio mode |
|---|---|---|
| Existing normalized event pipeline and seven YAML detections | Preserved; all original tests remain | Same engine/rules, applied only to bundled synthetic inputs |
| Dashboard, event search, alerts, raw evidence and pinned snapshots | Functional | Functional, using real stored synthetic telemetry |
| Event import / upload | Functional | Intentionally blocked, including direct API requests |
| Rule detail and definition testing | Functional | Functional; catalog remains read-only |
| Rule enable/disable and import | Functional | Intentionally blocked for all visitors, including owner-token requests |
| Alert statuses and investigation notes | Functional | Read-only; no public free-text investigation collection |
| Instant, realtime and 10x replay | Preserved | Functional; shared cancellation, two active jobs, bounded history |
| Detection validation | All 50 saved scenarios / 14 benign | All 49 synthetic scenarios / 14 benign; isolated from operational storage |
| Restricted Sigma | Compile, import and test | Compile/test the two unchanged licensed bundled samples; no arbitrary input/import |
| Developer project evidence and logs | Available with the existing access policy | Blocked; the public page explains data provenance and limitations instead |
| Demo initialization | Existing private workflow retained | Automatic first-start 56-event/seven-alert seed |
| Reset | Existing named private demo reset retained | Optional owner-token reset, only the marked public database, mandatory reseed |
| Backend startup | Existing development commands retained | Single-process Uvicorn, `0.0.0.0`, environment `PORT`, no interactive terminal |
| Frontend routing / API | Existing proxy and combined app retained | Configured backend origin, real cross-origin `/api`, Vercel SPA rewrite |
| Database | SQLite retained | Dedicated configurable SQLite file; no PostgreSQL migration |

These public restrictions are a deliberate safety boundary, not missing buttons
that simulate success. The full private workflow still performs actual import,
status changes, rule toggles and Sigma import, as independently exercised by the
original 33 browser checks in the fresh clone.

## Exact validation results

| Result | Unchanged baseline | Final worktree | Independent clone |
|---|---:|---:|---:|
| Backend tests | 268 passed | **351 passed** | **351 passed** |
| Frontend tests | 93 passed | **122 passed** | **122 passed** |
| Unique backend + frontend tests | 361 | **473** | **473** |
| Failed / skipped tests | 0 / 0 | **0 / 0** | **0 / 0** |
| Exact local detection scenarios | 50 | **50** | **50** |
| Controlled benign scenarios | 14/14 | **14/14** | **14/14** |
| Standalone licensed Sigma cases | 4 | **4** | **4** |

There are **112 added tests**: 83 backend and 29 frontend. No original test,
scenario or dataset was removed to obtain a pass. Ruff, formatting, strict MyPy,
ESLint, Prettier, TypeScript, Vite build, dependency consistency, saved-fixture
reproduction, parser/storage/API/evidence integration, replay, Sigma, security,
regressions and benchmark assertions all ran through the established
`make validate` workflow. Every failed phase still exits nonzero.

Final backend subsets overlap and must not be added together:

| Subset | Passed |
|---|---:|
| Parser | 35 |
| Detection | 50 |
| Controlled negative | 14 |
| Integration | 133 |
| Replay | 17 |
| Sigma | 34 |
| Regression | 151 |
| Security | 92 |

Combined branch/statement backend coverage was **88.66%** in both final
environments. This is coverage of tested code, not a measure of detection
efficacy, production safety or enterprise false-positive rates.

## Production and browser execution

| Environment | Actual execution | Outcome |
|---|---|---|
| Worktree native production rehearsal | Production SPA on 18879, backend on 18869 | 10 orchestration checks and **27 browser checks passed** |
| Worktree backend container | Linux/amd64 image, SPA on 18878, API on 18868 | 11 orchestration checks and **27 browser checks passed** |
| Fresh-clone native rehearsal | Production SPA on 18881, backend on 18871 | 10 orchestration checks and **27 browser checks passed** |
| Fresh-clone backend container | Fresh-context image build, SPA on 18882, API on 18872 | 11 orchestration checks and **27 browser checks passed** |
| Fresh-clone private workflow | Combined production build on 18873, separate private database | **All 33 original analyst browser checks passed**, with `--no-capture` |
| Preserved full-stack Docker option | Final `Dockerfile` image on isolated port 18874 | Token boundary, SPA routes, seed, replay, exact evidence and status APIs passed |

Browser counts are separate workflow checks, not extra unique unit tests.
Repeated checks across environments are not presented as new detection cases.
The Linux/amd64 containers ran through Docker Desktop on an Apple-silicon host:
this is actual container execution using emulation, not a native-x86 hardware
benchmark or a broad cross-platform matrix.

The public browser runs verified populated counts, event search, raw evidence,
alert details, pinned rules, definition tests, AUTH-001 / PowerShell / DNS replay,
positive and benign validation, and pinned Sigma compilation/testing. Eight
routes were directly opened and refreshed, including the `/detections` alias.
Seven main views and navigation were exercised at a 390px mobile viewport.
There were no unexpected API failures or critical browser console errors.

Successful browser requests used the independently configured backend origin.
Completed POSTs carried the actual frontend Origin header; completed requests
carried neither an Authorization header nor a cookie. The preview's `/api/health`
returned SPA HTML, proving that a hidden development proxy was not making the
cross-origin tests pass.

Actual Vercel-like builds also proved that an external HTTPS API origin builds
successfully, while missing and loopback values are rejected when `VERCEL=1`.
Generated HTML contains one exact-origin CSP, and a server-only test marker
supplied as `SENTINEL_API_TOKEN` did not appear in frontend assets.

## Persistence, reset and public-data proof

Each isolated public rehearsal began with **56 events, seven alerts and one
seed run**. Real replay operations produced **89 events, ten alerts and four
runs**. After stopping and restarting the backend, those counts, run IDs and
the selected complete alert/evidence response were identical.

An unauthenticated reset was rejected. An authenticated owner reset restored
**56 events, seven alerts and one run**. The container checks recreated the
container against its same named volume, verified UID **10001** and waited for
the image's real healthcheck to become healthy. Only task-owned containers and
volumes were cleaned up.

Public databases require the dedicated filename and application ownership
marker. Existing unmarked data, unrelated SQLite tables and incompatible run
provenance are rejected rather than exposed. The public catalog excludes the
six-event, non-synthetic OTRF interoperability sample. All local fixtures remain
present. Only unchanged bundled Sigma source/provenance is accepted publicly.

Shared history is capped at 20 runs: the protected seed and 19 finished/active
replays. Old finished replays and dependent evidence/audit rows are pruned as
new ones start; active jobs are not pruned. This is not multi-tenancy or an
enterprise retention system.

## Measured performance

**Engine-only detection throughput, not end-to-end ingestion throughput.**
All three benchmark iterations in each environment processed 5,600 events,
evaluated 39,200 event-rule pairs, and produced exactly 700 alerts: 100 per rule.

| Measurement | Median detection seconds | Events/second |
|---|---:|---:|
| Before deployment changes | 0.451625 | 12,399.66 |
| Final worktree | 0.438835 | 12,761.05 |
| Final independent clone | 0.442400 | 12,658.21 |

The measured worktree duration was about 2.83% lower than the baseline; no
material regression was observed in this controlled check. These three-sample
local timings exclude parsing, SQL storage, append re-evaluation, HTTP and UI.
They are not a service capacity claim or timing SLA.

## Issues actually found and resolved

| Finding | Resolution and evidence |
|---|---|
| Linux Docker install failed because SQLAlchemy's conditional `greenlet` dependency was absent from the macOS-generated hash lock | Added the explicit `greenlet==3.5.6` pin and regenerated hashes; preserved all 42 existing package versions. Both x86_64/aarch64 metadata regressions failed first, then passed. Actual amd64 images subsequently built and ran. |
| Adding public health metadata initially changed the exact private health contract | Restored the original three-field private response; public-only fields are added only in public mode. Original and new regression checks pass. |
| Offline reset ignored environment configuration | It now uses `Settings.from_env()`; a regression verifies the configured public database, while the original fixture-before-reset ordering remains intact. |
| Docker's port proxy briefly accepted then reset connections before ASGI readiness | The verifier now retries only bounded transient connection failures, uses short startup probes and rejects exited processes. Actual container restart tests pass. |
| Provisional browser headers omitted Origin, and aborted navigation requests could leave final-header retrieval pending | The verifier inspects completed browser requests and bounds command execution. Native and container browser runs now record actual Origin/no-credential evidence without hangs. |
| Verification command failures needed durable output | Command output is streamed to the saved log; a failing real subprocess regression verifies that output is retained. Its standalone probe is isolated from pytest-cov's application measurement environment. |

Initial unsuccessful attempts remain diagnostic artifacts, not final passes.
The saved final receipts are specifically named below; no stale result was
substituted for a failed execution.

## Dependency and sensitive-data review

The final `npm audit --json` reported **zero known advisories**. Fresh-clone
`npm ci` also reported zero. Python installation used the hash lock and
`pip check`; no unrelated dependency version was upgraded.

No dedicated gitleaks, trufflehog, detect-secrets or Python advisory scanner was
available. A bounded local current-tree review searched tracked and untracked
non-ignored text for token/private-key patterns, credential assignments and
sensitive-data indicators. No actual credential was found. Four assignment
candidates were reviewed: two synthetic test tokens and two environment/random
generation expressions. Public data provenance and the dedicated database
boundary were also checked.

This was **not** a full Git-history, entropy-based or enterprise secret scan,
independent penetration test, Python advisory scan or base-image vulnerability
scan. Historical local execution paths and legitimate upstream attribution
remain in the repository's historical evidence; the public backend does not
serve developer logs/documents or those media files.

The Render Blueprint passed local validation against its downloaded official
JSON schema. The official Vercel schema itself failed meta-schema validation in
an unused `functions/experimentalTriggers` definition. That vendor schema was
not weakened or silently repaired. Vercel routing, headers, builds and actual
SPA behavior were independently exercised locally; provider acceptance remains
part of the owner's hosted verification.

## Clean-clone method and source identity

No new commit was authorized. Therefore the clean-source test was explicitly:

1. A fresh local `git clone --local --no-hardlinks` of the existing commit.
2. A recorded Git-derived overlay of the reviewed uncommitted source files.
3. Independent `make install`, producing the clone's own virtual environment and
   node_modules; neither was copied from the worktree.
4. Full validation, production builds, browser installation check, native and
   Docker workflows, persistence/reset and all 33 original private browser checks.
5. A final documentation/evidence refresh and byte/fingerprint comparison.

This is **clone + final-source overlay**, not a claim that uncommitted changes
were in Git history.

```text
Unchanged base commit:
b987e6d7526b9a643bf9813fe816ada21c706b55

Final executable/configuration/input fingerprint, worktree and clone:
d618438a4506636078d672bc8b4fcf444d0685970d2d06f3d7515b089c957595
```

The clone is retained at:

```text
/Users/triplea/.copilot/session-state/c558b1b2-adb7-42c1-a3c1-217aa9ca7c3b/files/sentinelflow-deployment-clone
```

The original eight PNGs and MP4 are unchanged in both locations. The MP4 remains
9,730,783 bytes with SHA-256
`aa444d5de6e407cd1977cd41690fc972e3e92f6fa13ec854942f91af01366df5`.
It is the original real 5:56.16 recording, not newly recorded deployment media.

## Important commands actually run

```sh
make validate
npm --prefix frontend audit --json
.venv/bin/pip-compile --allow-unsafe --generate-hashes --extra dev \
  --output-file requirements.lock pyproject.toml
.venv/bin/python -m pip install --require-hashes -r requirements.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
.venv/bin/python -m pip check
.venv/bin/python scripts/verify_deployment.py \
  --label native-final --backend-port 18869 --frontend-port 18879
.venv/bin/python scripts/verify_deployment.py \
  --label docker-4 --docker --backend-port 18868 --frontend-port 18878
docker --context desktop-linux build --platform linux/amd64 \
  -f Dockerfile -t sentinelflow-deployment:legacy-final .
```

In the independently installed clone, `make install`, `make validate`,
`npx playwright install chromium`, both `verify_deployment.py` modes and
`node scripts/browser_verify.mjs --no-capture` were actually executed.
The private browser command used an isolated server/database and ephemeral
token, never the original live instance. Raw logs and command receipts are saved.

## Files changed or created

The following are deployment changes. The pre-existing untracked
`docs/implementation-status.md` is preserved separately and is not counted as a
newly authored deployment file.

| File | Purpose |
|---|---|
| `.dockerignore` | Exclude environment secrets, databases and temporary outputs from build contexts |
| `.gitignore` | Ignore environment variants, private keys, databases and provider-local state while retaining examples |
| `.env.example` | Document real private/deployment settings without secrets |
| `.env.public-demo.example` | Separate synthetic-only local production rehearsal example |
| `Dockerfile` | Preserve private full-stack build; use the production launcher and include Swagger favicon |
| `Dockerfile.backend` | Non-root API-only public backend image with runtime initialization and healthcheck |
| `render.yaml` | Native Python Blueprint, free/ephemeral default, explicit origin input, no automatic deploy |
| `Makefile` | Add `serve` without replacing existing development/validation commands |
| `pyproject.toml` | Pin the actually required cross-platform greenlet dependency |
| `requirements.lock` | Regenerated hash lock; existing package versions retained |
| `backend/app/core/config.py` | Public mode, dedicated DB guard, origin/host validation and Render hostname support |
| `backend/app/core/security.py` | Public read/workflow access, private-feature denial and owner-only public reset |
| `backend/app/core/evidence.py` | Include deployment configuration in receipt freshness |
| `backend/app/main.py` | Configurable hosts, public body limits/health/API-only behavior, local Swagger favicon and SPA alias |
| `backend/app/api/routes.py` | Enforce public endpoint restrictions, pinned Sigma source and validation concurrency |
| `backend/app/services/datasets.py` | Synthetic-only public catalog/scenario filtering |
| `backend/app/services/platform.py` | Owned initialization, restart-safe seed, public retention, validation slot and safe reset |
| `backend/tests/integration/test_public_demo.py` | Actual public API, data, evidence, reset, persistence and restriction regressions |
| `backend/tests/unit/test_deployment_config.py` | Configuration, ports, platform lock, reset, readiness and logging regressions |
| `frontend/src/services/apiBase.ts` | Validated backend origin / API-prefix normalization |
| `frontend/src/services/api.ts` | Use configured API base; do not ask visitors for credentials to unlock forbidden features |
| `frontend/vite.config.ts` | Root environment loading, exact-origin production CSP and proxy-free preview headers |
| `frontend/vercel.json` | SPA fallback and security headers |
| `frontend/src/types/index.ts` | Optional public health metadata while preserving legacy responses |
| `frontend/src/hooks/workspace.ts` | Shared health/public-mode context |
| `frontend/src/components/WorkspaceProvider.tsx` | Central health discovery and existing run state |
| `frontend/src/components/Shell.tsx` | Shared-synthetic notice, accurate connection state and public navigation/credential controls |
| `frontend/src/App.tsx` | `/detections` alias retaining query scope |
| `frontend/src/pages/DashboardPage.tsx` | Hide private import action in public mode |
| `frontend/src/pages/EventsPage.tsx` | Block public import UI, including direct bookmarked import routes |
| `frontend/src/pages/AlertDetailPage.tsx` | Preserve evidence while making public status/notes read-only |
| `frontend/src/pages/RulesPage.tsx` | Read-only public catalog with working isolated definition tests |
| `frontend/src/pages/SigmaPage.tsx` | Pinned-source public compilation/testing; private editor/import preserved |
| `frontend/src/pages/EvidencePage.tsx` | Public limits/provenance page; no premature developer endpoint request |
| `frontend/tests/deployment.test.tsx` | API configuration and public UI interaction regression coverage |
| `scripts/serve.py` | Production Uvicorn entrypoint with `PORT`, one worker and safe proxy policy |
| `scripts/verify_deployment.py` | Reproducible isolated native/Docker production-build, browser, persistence and reset checks |
| `scripts/browser_deployment.mjs` | Real public desktop/mobile workflows and complete cross-origin request evidence |
| `scripts/browser_workflows.mjs` | Recognize actual private/public connection state in shared browser helpers |
| `scripts/demo_reset.py` | Honor environment settings in offline mode |
| `scripts/validate.py` | Include deployment browser syntax in the complete existing workflow |
| `README.md` | Live Demo Deployment, explicit public restrictions, historical evidence distinction and owner URL placeholders |
| `docs/api.md` | Split-origin/public API contract and preserved private health semantics |
| `docs/security.md` | Public restrictions, ownership, resource bounds, reset and audit limitations |
| `docs/limitations.md` | Shared-demo/storage/platform verification limits |
| `docs/demo.md` | Distinguish original private media and no-capture regression procedure |
| `docs/testing.md` | Deployment regressions, actual workflow method and scope |
| `docs/dependency-maintenance.md` | Real Linux lock failure, minimal repair and reproduction |
| `docs/fresh-clone.md` | Mark original clone evidence historical and link the new overlay-based test |
| `docs/deployment.md` | Exact owner-run GitHub, Render, Vercel, reset and acceptance instructions |
| `docs/deployment-checklist.md` | Evidence-backed preparation and unchecked hosted-owner actions |
| `docs/deployment-readiness.md` | This complete final assessment |

Every newly saved evidence file under `docs/results/deployment/`, including its
purpose, is individually inventoried in that directory's [README](results/deployment/README.md).
Those are actual output artifacts, not implementation changes or regenerated media.

## What remains / what is not verified

Only the owner can finish publication: review and commit the uncommitted files,
push their selected branch, create/configure the two hosting projects, supply
the actual API/frontend origins, choose ephemeral versus paid persistent storage,
and execute the hosted acceptance checklist. The supplied URL placeholders are
intentionally still unfilled.

Actual Vercel/Render deployment, hosted TLS/CORS behavior, provider cold starts,
custom domains, paid-disk persistence/backups and external availability have
**not** been verified. Neither have Windows/WSL, Firefox/Safari, native-x86
hardware performance, enterprise load, complete secret history, Python advisory
databases or base-image vulnerabilities. Full EVTX/PCAP/Sigma, SSO/RBAC,
multi-tenancy and production-SIEM scale remain outside scope.

## Final repository / live-instance state

```text
Worktree:
/Users/triplea/Documents/CyberProjects/copilot-worktrees/sentinelflow/mk23rd-urban-journey

Branch:
mk23rd-sentinelflow-implementation

HEAD:
b987e6d7526b9a643bf9813fe816ada21c706b55

Working tree:
Deployment changes are uncommitted. No existing remote is configured.
No commit, push, merge, branch switch or history rewrite was performed.
```

The original attached private application at **http://127.0.0.1:8765** and its
data were preserved. That process was not restarted to adopt backend edits.
Production rehearsals used different ports and databases. The saved original
recording/screenshots were not regenerated, and no session was archived.
