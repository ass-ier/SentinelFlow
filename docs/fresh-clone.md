# Fresh-clone verification

**Historical original-delivery receipt.** The account below describes the
original committed implementation and is preserved unchanged as evidence.
Deployment preparation is uncommitted; its separate clone uses the same base
commit plus an explicitly recorded final-source overlay, not a fictitious new
commit. See [deployment-readiness.md](deployment-readiness.md) for that later
installation, production-build, Docker, browser and persistence verification.

The patched implementation was cloned locally into a new directory, not tested
only in the original development environment. `make install` created that
clone's own `.venv` and `frontend/node_modules` from the committed hash-locked
Python requirements and npm lockfile. No virtual environment or installed
modules were copied from the development worktree.

The installed source commit was
`8a8170225fa71544a73cb654cfd39dcfeb695a8d`. Its code, rule, fixture and dependency
fingerprint is
`f4f27c57afbd72864a29557fec670a2cb2865ff6f2bfe95a3e8af03808aeae5e`.
Later documentation/media packaging does not change this fingerprint.

## Actual outcome

- `make install` completed; the fresh npm installation reported zero known
  advisories after the pinned dependency remediation.
- `make validate` passed **268 backend and 93 frontend tests**, **50 detection
  scenarios**, **14/14 controlled benign scenarios**, Sigma compatibility,
  static/types/build checks, fixture reproduction and the exact benchmark.
- The clone's seeded application ran with **Vite on 5174** and its own backend
  on **8766**. The existing production preview on 8765 was not used as its API.
- All **33 live browser checks** passed through that Vite proxy, including
  ingestion, replay, evidence, rule toggles, Sigma and responsive navigation.
- Two additionally captured browser POSTs to
  `http://127.0.0.1:5174/api/detections/validate` carried the actual
  `Origin: http://127.0.0.1:5174` header and returned **HTTP 200**.
  The positive test returned **AUTH-001 / high / 25 evidence events**; the
  benign test returned **zero alerts**. Operational alerts remained **11 before
  and after** these isolated tests.

This tests the custom-port write path, not just a successful health GET. The
clone-owned servers were stopped after verification; unrelated listeners were
not terminated.

## Saved receipts

| Evidence | File |
|---|---|
| Checkout, independent Python path, versions, real request headers and results | [fresh-clone.json](results/fresh-clone.json) |
| Exact installation output | [fresh-clone-install.log](results/fresh-clone-install.log) |
| Full validation receipt | [fresh-clone-validation.json](results/fresh-clone-validation.json) |
| Actual validation output | [fresh-clone-validation.log](results/fresh-clone-validation.log) |
| All live browser checks | [fresh-clone-browser-results.json](results/fresh-clone-browser-results.json) |

The receipts identify exactly which source was executed. They do not claim a
different machine, container or operating-system test matrix.

## Reproduce locally

After cloning the feature branch into an unused directory:

```sh
make install
make validate
.venv/bin/python scripts/demo_reset.py --offline --seed \
  --api http://127.0.0.1:8766
SENTINEL_BACKEND_PORT=8766 SENTINEL_FRONTEND_PORT=5174 make dev
```

In another terminal in the same clone, after browser tooling is installed:

```sh
SENTINEL_API_URL=http://127.0.0.1:8766 \
SENTINEL_UI_URL=http://127.0.0.1:5174 \
node scripts/browser_verify.mjs --no-capture
```

Use free ports. If a copied `.env` contains `SENTINEL_ALLOWED_ORIGINS`, update
or remove that override so it agrees with the selected frontend port. Explicit
API URLs keep demo-reset and browser commands pointed at the intended instance.
