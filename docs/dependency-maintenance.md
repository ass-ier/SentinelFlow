# Dependency maintenance evidence

The sections below preserve earlier maintenance history. The current release
baseline is Python 3.13.15 and Node 24.21.0/npm 11.19.0. The
[security assessment](security-assessment.md) supersedes the earlier scan scope
and records actual pip-audit, npm, OSV, Retire.js, filesystem and image results.

A fresh installation of the initial locked frontend dependencies reported
**seven vulnerable packages: one critical, five high, and one moderate**.
These are package/advisory findings, not seven demonstrated exploits in
SentinelFlow. Some advisory paths concern framework SSR or development-server
features that this client-side application does not use; the packages were
updated rather than dismissing those findings.

| Direct dependency | Original pin | Patched pin |
|---|---|---|
| `react-router-dom` | 7.8.2 | 7.18.4 |
| `vite` | 7.1.3 | 7.3.6 |
| `vitest` | 3.2.4 | 4.1.11 |
| `@playwright/test` | 1.55.0 | 1.63.0 |

The regenerated lockfile also updates their affected transitive dependencies.
Vitest 4.1.11 was selected instead of the newer major that requires a different
Node baseline. These releases retain support for the documented Node 20.19.2
environment. The patched Playwright release also verifies browser-download TLS
certificates; the new pinned Chromium build was actually installed and used.

## Verification

`backend/tests/regression/test_dependency_baseline.py` contains eight
parameterized offline checks for the affected direct/transitive package floors.
All eight failed against the old lockfile and passed after the update.
The full backend, frontend, detection, Sigma, security and live browser workflows
were then rerun. The subsequent actual `npm audit --json` exited successfully
with **zero known advisories at the time of execution**.

The machine-readable [before report](results/dependency-audit-before.json)
preserves exact advisory IDs, URLs and affected ranges. The
[after report](results/dependency-audit-after.json) preserves the actual clean
registry result. These are historical observations, not an indefinitely valid
security attestation or an independent penetration test.

## Rechecking

```sh
# Networked registry advisory check; separate from offline validation.
npm --prefix frontend audit --json

# Offline checks and the complete reproducible application workflow.
.venv/bin/python -m pytest backend/tests/regression/test_dependency_baseline.py
make validate
```

When upgrading, use explicit compatible versions, regenerate the npm lockfile,
and rerun the complete workflow. Do not blindly use `npm audit fix --force`.
Retain the resulting receipts and refresh screenshots/recording when their
source fingerprint changes. Offline version floors prevent these known
regressions; they do not discover newly published advisories.

At the original-delivery phase, Python packages were hash-locked and passed
`pip check`, but no Python advisory database scan had been executed. That changed
in the later security assessment. Package consistency, registry advisory checks,
untrusted-input tests and an independent security assessment are different
forms of evidence.

## Deployment platform dependency

The first actual Linux/amd64 Docker build exposed a missing lock entry:
SQLAlchemy 2.0.43 requires `greenlet>=1` on Linux x86_64/aarch64 with Python 3.13,
but that conditional dependency was absent from the lock generated on macOS
arm64. Installation correctly failed under `--require-hashes`; dependency
checking was not bypassed.

Two offline regressions now evaluate the installed SQLAlchemy dependency
metadata for the deployment platforms. Both failed against the previous lock.
`greenlet==3.5.6` is explicitly pinned so the common hash lock includes it on
every development platform. Existing dependency pins are retained.

Reproduce the hash lock with the pinned pip-tools environment:

```sh
.venv/bin/pip-compile --allow-unsafe --generate-hashes --extra dev \
  --output-file requirements.lock pyproject.toml
.venv/bin/python -m pip install --require-hashes -r requirements.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
.venv/bin/python -m pytest backend/tests/unit/test_deployment_config.py -k sqlalchemy
```

This is a deployment compatibility repair, not a claim of a newly discovered
application exploit or a reason to upgrade unrelated packages. The deployment
readiness report records the subsequent real container and clone results.

## Current release maintenance

`requirements.lock` remains the complete development lock.
`requirements-runtime.lock` contains production dependencies only; neither tests
nor scanners need to be installed in a production image. Every pin includes
hashes, and the gate checks the installed environment against the full lock.

Use the pinned compiler and scanner environment after `make security-tools`:

```sh
.venv/bin/pip-compile --allow-unsafe --generate-hashes --extra dev \
  --strip-extras --no-emit-index-url --no-emit-trusted-host \
  --output-file requirements.lock pyproject.toml
artifacts/security/tools/python-release/bin/uv pip compile pyproject.toml \
  --constraint requirements.lock --generate-hashes --no-emit-index-url \
  --output-file requirements-runtime.lock
.venv/bin/python -m pip install --require-hashes -r requirements.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
make security
```

The former Python Swagger wrapper contained DOMPurify 2.3.10 inside its
JavaScript even when Python/npm package audits did not identify it. Retire.js
confirmed 19 distinct advisories in that bundle. It is replaced by the locked
Swagger UI 5.33.0 distribution with preserved licenses and exact byte checks.
Run `python scripts/vendor_swagger.py` after an intentional Swagger version
change; `--check` never rewrites assets. Scan the actual shipped bundles as
well as the locks.

The unmaintained `ffmpeg-static` wrapper was removed only after tracing its
recording use and replacing it with the maintained, separately installed
FFmpeg 9.0.2 tool. The original recording remains intact. Its new encoder
smoke check and optional environment/explicit platform lock are documented in
[demo.md](demo.md); optional native recording libraries are inventoried separately,
not represented as Python/npm packages.

Review npm install hooks explicitly. The lock-approved esbuild/fsevents hooks
remain available; Scarf telemetry is denied and `scarfSettings.enabled` is false.
Scanner executables have pinned versions and publisher SHA-256 digests.
Advisory/rule databases are fetched for each assessment and saved with hashes.

Do not rewrite historical receipts, erase Git history, automatically approve
scanner findings, or run `audit fix --force`. Raw findings stay in evidence.
SAST exceptions require a technical rationale bound to the whole reviewed source
file hash; a changed file or new rule fails the gate until reviewed again.
