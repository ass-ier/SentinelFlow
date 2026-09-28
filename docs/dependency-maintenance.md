# Dependency maintenance evidence

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

Python packages are hash-locked and pass `pip check`, but no Python advisory
database scan was executed. Package consistency, registry advisory checks,
untrusted-input tests and an independent security assessment are different
forms of evidence.
