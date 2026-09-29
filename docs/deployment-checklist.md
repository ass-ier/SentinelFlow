# Deployment checklist

This checklist distinguishes locally verified preparation from owner-only
publication and hosted acceptance. Its final evidence is linked from
[deployment-readiness.md](deployment-readiness.md). No unchecked item is an
implied pass.

## Repository and configuration

- [ ] Git repository clean after owner review/commit; preparation is intentionally uncommitted.
- [x] Current-tree secret review completed with its documented limits.
- [x] Backend production start and `PORT` / `0.0.0.0` binding verified.
- [x] Frontend production build verified.
- [x] HTTPS API environment configuration and missing/local hosted-value rejection verified.
- [x] Explicit CORS and Host boundaries verified.
- [x] Vercel SPA direct navigation and refresh verified locally.
- [x] Health, offline Swagger assets and OpenAPI verified.
- [x] Python hash-locked installation and current npm audit completed.

## Data and application behavior

- [x] Dedicated public SQLite initialization and provenance guards verified.
- [x] Deterministic 56-event/seven-alert demo initialization verified.
- [x] Actual operations survive a local restart.
- [x] Visitor reset denied and operator reset restores the deterministic demo.
- [x] Public catalog/data remain synthetic-only; full local fixtures are retained.
- [x] Read-only public controls and server-side restrictions verified.
- [x] Dashboard, search, alert details, evidence, rule tests and replay verified.
- [x] Positive/benign detection validation and licensed Sigma tests verified.
- [x] Desktop/mobile production-browser smoke tests passed.
- [x] Complete existing validation suite and added regressions passed.
- [x] Measured engine-only benchmark checked against baseline.

## Container and clean environment

- [x] Backend Docker image actually built.
- [x] Backend Docker container actually run and its healthcheck verified.
- [x] Docker volume persistence, non-root execution and protected reset verified.
- [x] Fresh clone plus explicitly recorded uncommitted-source overlay installed independently.
- [x] Fresh-clone full validation, production build and browser checks passed.
- [x] Fresh-clone Docker build/run and critical workflows passed.
- [x] Original private workflow checked without regenerating final media.

## Handoff

- [x] README updated with Live Demo Deployment and unfilled owner URL placeholders.
- [x] Exact Render/Vercel setup and post-deployment instructions documented.
- [x] Every changed file, command, result and limitation recorded in the readiness report.
- [x] Original live server and historical media preserved.

## Owner actions not performed by this task

- [ ] Review and commit the uncommitted changes.
- [ ] Push the selected branch to the owner's GitHub repository.
- [ ] Create/configure Render and deploy the backend.
- [ ] Create/configure Vercel and deploy the frontend.
- [ ] Set the actual Render API origin and exact Vercel/custom-domain CORS origins.
- [ ] Choose ephemeral storage or deliberately configure a paid persistent disk.
- [ ] Complete the hosted HTTPS/CORS/routes/replay/Sigma and restart/reset acceptance checks.
- [ ] Replace `LIVE_DEMO_URL`, `GITHUB_URL` and `DEMO_VIDEO_URL` with real owner-supplied links.

The local secret search is not a full Git-history or enterprise scan. Python
advisory scanning, base-image vulnerability scanning, full browser/OS matrices
and actual Vercel/Render hosting are not implied by the local checks.
