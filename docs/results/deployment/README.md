# Deployment execution evidence

These are actual outputs from the deployment-readiness phase, separate from the
historical original-delivery receipts in the parent directory. Final executable
source fingerprint:

`d618438a4506636078d672bc8b4fcf444d0685970d2d06f3d7515b089c957595`

Final unique test count: **351 backend + 122 frontend = 473**, with 50 complete
local detection scenarios, 14 controlled benign scenarios and four standalone
Sigma cases. Public-only validation retains 49 synthetic scenarios. Repeated
browser/environment checks are reported separately, not added to unique tests.

| File | Actual evidence / purpose |
|---|---|
| `baseline-validation.json` | Unchanged 361-test baseline before deployment source edits |
| `baseline-benchmark.json` | Actual pre-change 5,600-event engine measurement |
| `validation.json` | Final worktree commands, exit statuses, counts, categories and freshness |
| `validation.log` | Full actual final comprehensive validation output |
| `backend-junit.xml` | All 351 backend cases |
| `frontend-tests.json` | All 122 frontend cases |
| `detection-validation.json` | Exact final 50-scenario rule/severity/evidence results |
| `detection-validation.txt` | Human-readable final detection report |
| `sigma-validation.json` | Real licensed Sigma compatibility results |
| `benchmark.json` | Final worktree measured timing, count contract and samples |
| `npm-audit.json` | Current registry audit: zero known advisories at execution |
| `python-pins-before.json` | Existing 42 pinned versions before the Linux dependency repair |
| `python-pins-after.json` | Same existing versions plus greenlet |
| `linux-lock-before.log` | Two real failing Linux dependency-lock reproducers |
| `linux-lock-after.log` | The same regressions passing after the minimal repair |
| `native.json` | Worktree production-build startup, real operations, restart and reset |
| `native-browser.json` | 27 worktree native public browser checks and actual request evidence |
| `docker.json` | Actual Linux/amd64 backend image, startup, volume persistence, UID and healthcheck |
| `docker-browser.json` | 27 public browser checks against the actual container backend |
| `legacy-docker.json` | Preserved private full-stack image built/run from final source |
| `hosted-builds.json` | HTTPS Vercel-like build succeeds; missing/loopback configuration fails as intended |
| `provider-schemas.json` | Render schema pass and explicit upstream Vercel meta-schema limitation |
| `clone-install.log` | Independent hash-locked Python and npm installation |
| `clone-validation.json` | Final independent clone's full 473-test validation receipt |
| `clone-validation.log` | Actual clone validation console output |
| `clone-benchmark.json` | Actual independently installed clone benchmark |
| `clone-native.json` | Clone native production startup, browser, restart and reset |
| `clone-native-browser.json` | 27 clone native public browser checks |
| `clone-docker.json` | Clone-context backend image build/run and persistent-volume checks |
| `clone-docker-browser.json` | 27 clone-container public browser checks |
| `clone-private-browser.json` | All 33 original private analyst browser checks; no media capture |
| `clone-private-console.log` | Actual private browser command output |
| `preserved-media.json` | Byte/hash equality of all original PNGs and MP4 in worktree and clone |
| `secret-review.json` | Bounded current-tree search, reviewed candidates and explicit limitations |
| `source-overlay.json` | Unchanged base commit, final-source clone method and file comparison |
| `artifact-integrity.json` | Actual saved receipt inventory, hashes and source consistency |
| `README.md` | This inventory and interpretation guidance |

Full local command/build logs, isolated databases, production bundles and new
live screenshots also remain under `artifacts/deployment/` in the worktree or
clone. They are ignored build/verification outputs, not deployment inputs.
Initial failed attempts are retained there as diagnostics and are not counted
as final passes.

The final original MP4 and eight screenshots remain untouched under
`recordings/` and `screenshots/`. No external deployment, hosted URL, production
capacity, enterprise false-positive measurement or vulnerability-free status
is implied by these receipts.
