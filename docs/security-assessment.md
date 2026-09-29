# SentinelFlow Security Hardening & Vulnerability Assessment

## Verdict

**Status: PASS for the defined local security release gate.**

The final gate ran from **2026-09-28 23:50:01 UTC to 23:55:34 UTC** and
returned exit status 0. All 37 gate checks passed. It executed the full
application validation, dependency and source scans, actual image builds/scans,
browser workflows, collector recovery and deployment rehearsals.

**No known vulnerabilities were reported by the specified scanners against
the scanned dependency set at the validation time.**

This is not a claim that vulnerabilities cannot exist, a production SIEM
certification, an independent penetration test, or live Microsoft validation.
The scope exclusions and remaining operational responsibilities below are part
of this verdict, not optional footnotes.

| Final release result | Observed |
|---|---:|
| Reported dependency findings in the final scanned release set | 0 |
| Critical / high / medium / low dependency findings | 0 / 0 / 0 / 0 |
| Confirmed or unreviewed release-blocking SAST findings | 0 |
| Confirmed committed/current-tree secrets | 0 |
| Backend tests | 801 passed; 0 failed; 0 skipped |
| Frontend tests | 145 passed; 0 failed; 0 skipped |
| Total backend + frontend tests | 946 passed |
| Detection scenarios | 50/50 |
| Core controlled-benign scenarios | 14/14 |
| Browser checks across five suites | 127/127 |
| Live integrations | **Not tested** |
| Release blockers in the defined local gate | None identified |

The primary machine-readable receipt is
[final/summary.json](results/security/final/summary.json).
The full [evidence manifest](results/security/evidence-manifest.json) and
[evidence index](results/security/README.md) accompany this document.

## Exact assessed state

| Property | Value |
|---|---|
| Repository | `/Users/triplea/Documents/CyberProjects/copilot-worktrees/sentinelflow/mk23rd-urban-journey` |
| Branch | `mk23rd-sentinelflow-implementation` |
| HEAD | `b987e6d7526b9a643bf9813fe816ada21c706b55` |
| Worktree | Contains uncommitted deployment, integration and security changes |
| Release fingerprint | `2485344225394ffafaaa9feba73eac583d02e704e3d26747d38fe9abcbe22ea6` |
| Validation host | macOS 26.6.2, arm64 |
| Python used | 3.13.15 in `.runtime/venv` |
| Node / npm used | 24.21.0 / 11.19.0 |
| Container target | Linux/amd64, locally built and rehearsed |
| Final original evidence directory | `artifacts/security/release-delivery/` |
| Curated persistent evidence | `docs/results/security/` |

**HEAD alone does not identify the hardened code.** The source fingerprint
covers application code, tests, scripts, rules, datasets, dependency locks,
security tooling, workflow configuration and deployment configuration. The
manifest separately binds documentation and the curated evidence. Historical
reports retain their original fingerprints rather than being rewritten.

Nothing was pushed, merged or deployed to a hosting provider. No Microsoft
resources were created and no real tenant credentials were requested or used.

The existing processes at `http://127.0.0.1:8765` and
`http://127.0.0.1:18881` were preserved. They were not restarted into the new
runtime and are **not** the evidence for this hardened release. Their old
environments can retain the baseline dependency risks. All new verification
used isolated owned processes, databases, ports and container volumes.

## Functional status

| Surface | Implemented and locally verified | Deliberate boundary |
|---|---|---|
| Event pipeline | JSON, JSONL, CSV, authentication/syslog, Windows JSON/XML, normalization and linked raw evidence | No full EVTX parser; logs are not proof of trustworthy upstream origin |
| Detection engine | Data-driven YAML predicates, thresholds, event-time windows, groups, suppression and exact evidence | Seven built-in portfolio detections, not enterprise coverage |
| Analyst application | Dashboard, search, alert investigation/status, rules, replay, validation and Sigma workflows | No multi-tenant RBAC or production operations platform |
| Detection validation | 50 exact scenarios, 14 core benign cases, boundaries and regressions | Controlled negatives do not measure an enterprise false-positive rate |
| Sigma | Two licensed upstream rules compiled/imported/tested; four expected outcomes passed | Explicit supported subset, not arbitrary Sigma compatibility |
| Sentinel / Azure Monitor | OAuth/query adapters, checkpoints, normalized events and source attribution | Tested with local HTTP mocks, not a live tenant |
| Graph / Entra | Authentication, paging/query adapters, normalization and checkpoints | Tested with local HTTP mocks, not a live tenant |
| Windows / WEF | Collector implementation, authenticated ingestion, bookmark/dedup and durable spool | Actual CLI used fixtures; no live Windows domain/Event Log deployment |
| Notifications | Transactional outbox, delivery attempts, retries, per-destination idempotency and mock receipt evidence | No real Power Automate, Teams or external webhook delivery |
| Public deployment mode | Synthetic-only boundary, public OpenAPI pruning, real cross-origin UI and restart/reset behavior | Vercel/Render deployment was not performed |
| Security release tooling | Fail-closed scans, inventory, SBOM, source-bound triage and full local rehearsal | Hosted GitHub Actions run has not occurred |

See [architecture](architecture.md), [security model](security.md),
[integration implementation report](integrations-implementation-report.md) and
[deployment runbook](deployment.md) for the implementation details.

## Dependency inventory and maintenance

[dependency-inventory.json](results/security/final/dependency-inventory.json)
records direct/transitive dependencies, installed versions, declared
requirements, lock hashes, npm install hooks and optional recorder packages.

| Set | Actual inventory |
|---|---|
| Complete Python lock | 43 packages |
| Production Python lock | 20 packages; version-consistent subset |
| Installed application environment | 44 distributions, including the local application |
| Scanner Python lock | 87 audited dependency records |
| npm lock | 373 package-path entries, including development/optional dependencies |
| OSV npm output | 364 package records; not the same counting unit as npm paths |
| Each final image | 29 Alpine APK packages and 20 Python packages |
| Combined CycloneDX SBOM | 545 components |
| Optional recording environment | 88 inventoried native conda packages |

The installed Python environment exactly matches the full lock; unexpected
packages and missing locked versions fail the gate. Both Python locks contain
hashes. npm resolved artifacts use the reviewed npm registry.

| Component | Baseline | Final action |
|---|---|---|
| Python | Earlier runtime retained only for preserved processes | New isolated Python 3.13.15 runtime |
| pip | 25.2 | 26.2.1; not shipped in production images |
| pytest | 8.4.1 | 9.1.1; development only |
| python-dotenv | 1.1.1 | 1.2.3 |
| python-multipart | 0.0.20 | 0.0.32 |
| setuptools | 80.9.0 | 84.0.0; not shipped in production images |
| Starlette | 0.47.3 | 1.7.0, with FastAPI 0.141.1 compatibility changes |
| XML implementation | Standard parser plus textual declaration guard | defusedxml 0.7.1 and explicit structural limits |
| Swagger distribution | Python wrapper containing DOMPurify 2.3.10 | Byte-verified Swagger UI 5.33.0, containing DOMPurify 3.4.13 |
| Unused Swagger wrapper dependencies | Jinja2 and MarkupSafe through that wrapper | Removed after tracing actual repository use |
| Recording executable | `ffmpeg-static` wrapper shipping FFmpeg 6.0 | Optional maintained FFmpeg 9.0.2 environment; wrapper removed after replacement |
| Production base | Debian-based image with reported OS advisories | Digest-pinned Python 3.13.15 / Alpine 3.24 |

The Swagger Python wrapper and recording wrapper were not removed to hide
findings. Their actual functionality remains available and was verified.
Swagger is served offline with original licenses and upstream byte provenance.
The recorder passed a real H.264 encoder smoke check; the existing video was
also decoded without modification.

The optional recorder's native packages are inventoried, **not comprehensively
advisory-scanned by pip/npm**. Likewise, final-image OS scans do not certify the
host OS, Docker daemon, every transient build-stage package or every native
scanner binary's transitive library. Those are outside the zero-finding claim.

## Scanners actually executed

Commands below summarize invocation; the final receipt contains the complete
argv, working directory, start/end times, exit code and output hashes.

| Tool/version | Scope and representative command | Actual result |
|---|---|---|
| pip-audit 2.10.1 | Full/runtime/tool locks using `--require-hashes --disable-pip`; actual installed `--path` | 43 / 20 / 87 lock records and 44 installed records; zero reported findings |
| npm 11.19.0 | `npm audit --package-lock-only --json`, with and without `--omit=dev` | Zero reported findings in both scans |
| OSV Scanner 2.6.0 | Both Python locks and npm lock; `--all-packages --all-vulns` | Zero reported findings |
| Retire.js 5.7.0 | Actual vendored Swagger and built frontend JavaScript | Zero reported findings; not merely a package-lock audit |
| Bandit 1.9.4 | Backend, tests, scripts and collector; `--ignore-nosec` | 111 nonempty Python files covered; all raw findings classified |
| Semgrep 1.178.0 | OWASP, Python, React, TypeScript and secrets packs; `--oss-only --strict --disable-nosem --metrics=off` | All 174 expected first-party code files covered; 195 paths scanned; no parse errors |
| Gitleaks 8.30.1 | Current source snapshot and available Git history with `--log-opts=--all --redact=100` | Eleven current and three historical matches, all individually verified false positives; zero confirmed secrets |
| Trivy 0.74.0 | Filesystem, installed Python SBOM and both final immutable images | Zero reported dependency/image vulnerability findings |
| Syft 1.52.0 | Installed environment SBOM | Actual package inventory incorporated in CycloneDX evidence |
| uv 0.12.19 | Pinned lock-generation/tooling helper | Version checked; scanner environment audited |
| ESLint 9.33.0 | Existing frontend rules, `--max-warnings 0` | Passed |
| TypeScript 5.9.2 | `tsc --noEmit` and production build | Passed |
| Ruff / MyPy / Prettier | Existing repository static/type/format checks | Passed in full validation |

ESLint is the repository's standard lint configuration, not a claimed separate
security plugin or replacement for Semgrep/browser tests.

Native scanner download hashes and versions are pinned in
[`security/tools.json`](../security/tools.json). Python scanner dependencies are
hash-locked in [`security/requirements.lock`](../security/requirements.lock).
No source was submitted to hosted SAST. Semgrep metrics/version checks and
Scarf telemetry were disabled.

The Trivy database metadata records an update at
**2026-09-28 13:05:44 UTC**; the gate requires age at most 48 hours. Other
advisory requests, downloaded rule/database hashes and timestamps are retained
with the run. New advisories can change a later result.

## Vulnerabilities found and dependency remediation

The baseline was not clean. Package counts, aliases and repeated container
package/advisory pairs are intentionally distinguished.

| Baseline group | Critical | High | Medium | Low | Unknown | Total / counting unit |
|---|---:|---:|---:|---:|---:|---|
| Python, deduplicated advisory groups | 0 | 6 | 11 | 5 | 0 | 22 groups |
| Original container OS packages | 6 | 106 | 151 | 148 | 2 | 413 package/advisory pairs |
| Original container Python packages | 0 | 8 | 11 | 5 | 0 | 24 package/advisory pairs |
| Old bundled Swagger/DOMPurify | 0 | 3 | 13 | 3 | 0 | 19 distinct advisories |
| Final scanned release set | 0 | 0 | 0 | 0 | 0 | Zero reported findings |

pip-audit originally returned 42 package/advisory entries containing 21 distinct
primary advisory IDs. OSV returned 44 IDs representing 22 advisory groups after
alias deduplication, including an additional multipart advisory. These numbers
are not contradictory and must not be summed as distinct vulnerabilities.

The [dependency remediation ledger](results/security/dependency-remediation.json)
contains **478 attributed records**: 22 Python groups, 437 container pairs and
19 bundled-JavaScript advisories. Every record includes scanner, advisory ID,
component/version, severity, dependency path, affected runtime, exploitability
qualification, remediation, status and before/after evidence. Some advisories
appear in more than one environment; 478 is not a unique-CVE count.

Affected pins were upgraded, compatible application APIs adjusted and locks
regenerated. Production images now omit test/build packages, pip and ensurepip.
No CVE blanket suppression or dependency-wide vulnerability waiver was used.
Scanner-clean package locks were not accepted as proof of bundled-JavaScript
safety: the actual Swagger bundle was separately inspected, found vulnerable,
replaced and rescanned.

No external exploitation was performed. An applicable package advisory does not
by itself establish a reachable exploit through SentinelFlow.

## Application and verification-tool hardening

Internal classifications below describe the tested issue and its conditions;
they are not independently assigned CVSS scores or newly issued CVEs.

| Finding / classification | Root cause and implemented fix | Verification |
|---|---|---|
| XML declaration bypass / medium | `backend/app/parsers/windows_xml.py`: a substring guard missed UTF-16 DTD/entity declarations. `defusedxml` now forbids DTDs, entities and external resolution independently of encoding. | Original reproducer: 7 failures / 7 passes; final XML boundary suite: 14/14 |
| Unicode input failures / medium | `backend/app/core/safe.py`: lone surrogates could reach serialization/storage error paths. Controlled UTF-8 validation now rejects invalid values and keys before use. | Input boundary, parser and bounded-fuzz suites |
| HTTP body resource exhaustion / medium | `backend/app/core/security.py`: added a ten-second absolute reception deadline, one byte-bounded buffer and strict Content-Length parsing. | Actual ASGI frame/deadline regressions; explicit 408/rejection responses |
| Empty HMAC configuration key / medium, configuration-dependent | `backend/app/integrations/destinations.py`: verification now rejects empty configuration before computing a signature. | Original 1 failed / 13 passed; final webhook boundary suite 14/14 |
| Corrupt collector spool / medium availability risk | `backend/app/integrations/collector.py`: invalid persisted JSON or non-object rows are retained and quarantined as `invalid_payload`, rather than crashing delivery. | Collector corruption tests and actual outage/recovery CLI |
| Collector filesystem exposure / low, local-user dependent | `backend/app/integrations/collector.py`: added 0600 file handling, 0700 new directory, `O_NOFOLLOW` and rejection of unsafe direct parent/file paths. | Seven spool-hardening tests; Windows ACL limitation retained |
| Incomplete database schema / medium integrity risk | `backend/app/storage/migrations.py`: required existing columns are checked before schema mutation; malformed/future schemas are rejected. | Resource/migration tests and ten migration-marker cases |
| IPv6 transition/site-local destinations / medium, configuration-dependent | `backend/app/integrations/transport.py`: deprecated site-local, 6to4 and Teredo are denied even under broad internal allowlists. | Transport rejection tests plus real local TLS/SNI/pinning tests |
| Scoped credential lifetime / hardening | Added optional timezone-aware expiry, UTC normalization, immediate request-time rejection, legacy non-expiring handling and UI status. | Auth matrix, frontend tests and actual browser expiry/revocation |
| OpenAPI exposure/accuracy / low information exposure | Lazy router generation required security declarations and public pruning after actual schema generation. Private models/operations are removed from public schemas. | Both route-prefix authorization tests and rendered offline Swagger |
| Private scan artifacts / medium, local-user dependent | `scripts/security_scan.py`: output and source snapshot directories start with mode 0700, including when a local `.env` is copied for scanning. | Saved failing reproducer, fixed test, and final actual mode checks |
| Verification harness rate/lease handling / verification defect | `scripts/container_security_probe.py`: the verifier respects genuine rate/lease enforcement and retries only those two explicit errors within a finite deadline. | Permanent positive/negative/deadline tests; final container observed one rate limit and recovered; earlier real run also observed busy responses |

The verifier was corrected, not the application's production rate limit.
Unexpected HTTP failures, exhausted retry deadlines, missing rate enforcement,
disabled assertions and incomplete scan output still fail.

Before-fix logs are preserved under [baseline](results/security/baseline/) and
[remediation](results/security/remediation/). Failing tests were not deleted.
The full gate was executed again after the final artifact-permission fix.

## Focused security coverage

| Boundary | Implemented controls and actual coverage | Remaining boundary |
|---|---|---|
| SSRF | Scheme/host/IP validation, metadata/private-network rejection, mixed-DNS rejection, pinned numeric connection, no redirects, verified TLS, fixed timeouts/response limits | Private HTTPS requires explicit operator CIDRs; not a network firewall |
| Authentication | Constant-time owner/scoped token handling, malformed/missing/revoked/expired rejection, masked UI input | Owner session is not a short-lived SSO session; tokens remain in the trusted server environment |
| Authorization | Four narrow integration scopes, Windows connector binding, owner-only management, both API prefixes checked | No tenant roles or per-dataset RBAC |
| Auth matrix | 37 endpoint/method combinations, two route prefixes and 11 credential states: 814 requests | Covers the defined API matrix, not every possible future route |
| HMAC | Exact body bytes, tamper detection, constant-time comparison, nonempty key and inclusive 300-second timestamp tolerance | Receiver must maintain durable idempotency; timestamp tolerance is not a replay cache |
| Notification queue | Transactional alert/outbox creation, retry/backoff, redacted attempt history, alert/destination idempotency across restart | No guarantee of exactly-once delivery to arbitrary external receivers |
| Windows collector | Bounded fixture/native adapter input, authenticated push, durable spool, corrupt-row quarantine, restart/bookmark behavior | Native Windows domain and endpoint ACL deployment not exercised |
| XML | DTD/entity/external rejection, 64 KiB, depth 12 and 1,024-node bounds | Normalized value limits can reject unusually large records rather than truncate them |
| YAML | SafeLoader-derived loader, duplicate-key/unsafe-tag/alias/nonfinite-value/depth/size rejection | Only the documented rule/Sigma schema is accepted |
| JSON | Duplicate-key, nonfinite-number, nesting, invalid Unicode and resource boundaries | Original field values are preserved, not cryptographically authenticated upstream bytes |
| ReDoS | Bounded regex syntax/input and 5 ms matching timeout with explicit failure/rollback | Not a promise that every allowed workload is cheap |
| SQL injection | SQLAlchemy bound parameters and escaped wildcard search; hostile search inputs covered | SQLite file access remains an OS trust boundary |
| XSS | Raw logs, rule/alert/destination names rendered as text; real browser payload markers remained inert | The docs-only Swagger script policy is distinct from the application CSP |
| Path traversal | Named reset/path restrictions, collector symlink and directory checks, non-extracting public sample handling | Trusted ancestor-directory ownership remains required |
| Command injection | No telemetry payload reaches shell execution; local tooling uses fixed argv and validated inputs | Operator-selected PATH/executables are trusted local configuration |
| Resource exhaustion | Body deadline/byte cap, input structural caps, run/rule/replay limits, operation limits and container resource bounds | No distributed or enterprise DDoS protection |
| CORS/host/origin | Exact allowlists, wrong-origin/host rejection, explicit production API origin, untrusted proxy-header behavior | CORS does not authenticate non-browser clients |
| Information disclosure | Structured errors, redacted integration failures, no secrets in UI/history, pruned public OpenAPI | Local audit records and original telemetry are not encrypted/tamper-proof |
| Public mode | Separate marked synthetic database, mutation/collector/private-management denial, external flags rejected, bounded retention | Visitors share synthetic replay/cancel state |

The permanent corpus in [`test-data/security/`](../test-data/security/)
contains 207 bounded fuzz requests exercised by 72 parametrized tests.
Malformed inputs did not produce uncontrolled 500 responses or mutate state
in those tests. This was bounded defensive testing, not an attack on an
external system.

## SAST and secret triage

The final Bandit result contains **843 raw findings**: 831 low and 12 medium.
Semgrep contains **two raw findings** with its `ERROR` rule-severity label.
That label is not a scanner execution/parsing error.

Across both tools, **34 findings were classified as false positives and
811 as not applicable**. None remained unreviewed or release-blocking.
Raw reports were retained, not made cosmetically empty.

Most not-applicable findings are intentional test/verification assertions.
Other cases include fixed local development subprocesses, synthetic tokens,
environment-reference labels, SafeLoader subclass recognition and an
ElementTree type-only import while actual parsing uses defusedxml.
Verification scripts refuse optimized Python so required assertions cannot
silently disappear.

Technical exceptions are bound to complete source-file SHA-256 values in
[`security/sast-reviews.json`](../security/sast-reviews.json). Changed source or
an unreviewed rule blocks the gate. The
[raw reports and per-finding rationale](results/security/final/sast-triage.json)
allow independent review of those classifications.

Gitleaks reported **11 current-tree matches** and **three historical matches**,
with **zero confirmed secrets**. The current matches are ten occurrences of
the published CPython signing-key fingerprint in image evidence, plus its
focused regression fixture. It was verified against the official
`docker-library/python` Dockerfile, not assumed harmless from its name.
[Public-key provenance](results/security/public-key-provenance.json) records
the upstream blob and exact public value.

Classification accepts only the exact GPG match/value in eight named
evidence/test paths and reads the actual scanned snapshot or historical Git
blob. Tests prove a different value, different credential key or changed
snapshot still blocks. No private key or authentication value is waived.

All three historical matches were the same empty `.env.example` assignment
spanning into the following poll-interval setting. Each classification verifies
the exact immutable commit, file, line range, scanner rule and empty bytes.
A regression proves that a nonempty value at the same location still blocks.
No real secret was classified as harmless merely because its filename said
"test".

The historical matches are at commits `f658159093bf68572720608e033229ad47186fc8`,
`ae65f0707dc882c05d5ffd99ecff898c35c11269` and
`27d1d39bb5fb6a14baf089f7e91ba727bcd152d7`. The latter is an automatic Copilot
checkpoint ref, not a new feature-branch commit from this assessment.
History was not rewritten.

The reviewed tree scan includes first-party tracked/untracked content and any
local `.env` inputs, not ignored dependency caches or scanner installations.
Those environments have separate dependency inventories/audits. Private
source/environment snapshots and SQLite databases are not in the curated
package or the workflow's upload selection.

## Regression and browser results

The final validation receipt reports **801 backend tests and 145 frontend
tests**, with zero failures/skips. Backend measured coverage was **88.98%**.

| Backend marker / subset | Passed |
|---|---:|
| Integration | 472 |
| Security | 434 |
| Regression | 440 |
| Connectors | 103 |
| Notifications | 42 |
| Parsers | 64 |
| Replay | 17 |
| Sigma | 34 |
| Migrations | 10 |
| Detection scenarios | 50 |
| Controlled negatives, including three provider cases | 17 |
| End-to-end marker | 7 |
| Unit marker | 128 |

**Markers overlap and must not be summed.** By individual test file, Windows
integration coverage has 36 cases, collector-corruption coverage has seven,
XML security has 14, transport security has 15, webhook security has 14, and
release-gate security has 45. These are subsets of the same 801 backend tests.

The suite retained its Starlette warning that TestClient's `httpx` integration
is deprecated in favor of `httpx2`. It is recorded rather than suppressed.
It did not fail the tested stack or produce an advisory finding; a future
TestClient migration still needs ordinary compatibility testing.

| Real browser suite | Checks |
|---|---:|
| Existing analyst workflows | 33/33 |
| Integration/notification workflows | 28/28 |
| New security workflows | 12/12 |
| Native public deployment UI | 27/27 |
| Docker public deployment UI | 27/27 |
| Total | 127/127 |

The security browser checked actual authentication errors, masked owner input,
reference-only scoped credential creation, UTC expiry, immediate revocation,
expired credential rejection, inert hostile destination/alert/raw-event text,
redacted delivery history and offline Swagger. Credential controls were used
at 1440 px and 390 px widths. No browser runtime errors occurred in that suite.

New screenshots are in the curated rehearsal directories, including
[credential expiry](results/security/final/rehearsals/security-browser/credential-expiry.png),
[literal raw evidence](results/security/final/rehearsals/security-browser/literal-evidence.png)
and [mobile integrations](results/security/final/rehearsals/integration-browser/integrations-mobile.png).
They are actual browser captures, not mockups.

## Integration, collector and deployment rehearsals

| Local provider flow | Normalized events | Alerts | Deliveries to mock |
|---|---:|---:|---:|
| Sentinel / Azure Monitor | 13 | 2 | 2 |
| Graph / Entra | 13 | 2 | 2 |
| Windows / WEF fixture | 36 | 7 | 7 |

Sentinel and Graph each generated the expected AUTH-001 and IAM-001 alerts.
Windows generated one alert for every built-in rule. Repeated operations did
not create duplicate notifications for the same alert/destination.
These flows used real loopback HTTP, persistence, normalization and the actual
detection/outbox implementations, not fabricated delivery results.

The actual collector CLI was run against a deliberate TCP outage:
exit 2 with all 36 events durably pending. After process restart and backoff,
it exited 0 with 36 ingested events and seven alerts. Repeating the bookmark
after restart did not duplicate events. Notification idempotency across
restart was verified separately for two independent destinations.

Native public deployment passed **10 checks plus 27 browser checks**.
Docker public deployment passed **12 checks plus 27 browser checks**.
Both exercised the 56-event/seven-alert seed, real independent frontend/API
origins, allowed/denied cross-origin requests, offline docs, restart persistence
and operator-only reset. Public validation intentionally runs 49 synthetic
scenarios; the private 50-scenario suite includes an additional non-public
interoperability case.

The full application image passed **nine in-container checks** with external
networking disabled. They covered UID 10001, read-only root, zero effective
capabilities, no-new-privileges, absence of development tools and historical
audit archives, actual rate-limit recovery and all three exact mock workflows.

### Exact final images

| Image | Immutable local image ID | Critical / high / medium / low |
|---|---|---|
| Backend-only | `sha256:4a3af9297da770e8e3d24f1beb14f05850686d489ee4b2dfa161d3d365db41d9` | 0 / 0 / 0 / 0 |
| Full application | `sha256:69b32fc8ceafe8edeb6971df88ee5d16a9bf69769d881977c451c6876c937b00` | 0 / 0 / 0 / 0 |

These are actual local image IDs, not claimed registry-published digests.
Both were labeled with the final source fingerprint and rehearsed by immutable
ID, not by a potentially changed tag.

The production base is
`python:3.13.15-alpine3.24@sha256:79e7a9b9ff1cbceff819f856fb374477792a5967759d94df266de7b7b4120e6f`.
The frontend builder is
`node:24.21.0-alpine3.24@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1`.

Rehearsals/Compose use read-only root filesystems, dropped capabilities,
no-new-privileges, a bounded noexec/nosuid tmpfs, 768 MiB memory, two CPUs,
128 PIDs, dedicated volumes and loopback publishing where an HTTP port is
needed. The private image probe used `--network none`.

Packaging the historical evidence originally embedded its old SBOM in the full
image. Trivy's `sbom` analyzer consequently attributed 23 historical Python
advisory pairs to that image, even though the runtime probe confirmed those
old development modules were absent. The
[packaging diagnostic](results/security/packaging-diagnostic.json) preserves
the exact attribution and source-report hash.

The fix keeps `docs/results/security` in the repository but excludes that
historical archive from runtime images. Ordinary application documentation
remains included. No installed package or CVE was excluded from scanning;
both rebuilt images were rescanned, and the runtime probe now checks the
archive's absence. Historical and current SBOMs remain available beside the
release instead of being mistaken for each other's installed inventory.

## Measured performance

The final benchmark used the saved, hash-identified
`mixed/benchmark_5600.jsonl` fixture on Python 3.13.15.

| Metric | Actual final result |
|---|---:|
| Events processed per iteration | 5,600 |
| Iterations | 3 |
| Active rules | 7 |
| Rule evaluations per iteration | 39,200 |
| Alerts per iteration | 700, exactly 100 per rule |
| Median detection duration | 0.425440083 seconds |
| Median throughput | 13,162.84 events/second |
| Individual durations | 0.435880875, 0.425440083, 0.424754917 seconds |

The prior integration-phase median was 0.442448291 seconds; the final median
is approximately 3.84% lower. Three samples on a shared workstation are not
evidence of a meaningful performance improvement. This is engine-only
measurement, excluding parsing/storage/network latency, not a production
capacity or availability claim. No result was selected from an earlier faster
candidate to improve the final report.

## Reproduction and release gate behavior

For a fresh installation, follow the pinned-runtime instructions in
[README](../README.md) and [dependency maintenance](dependency-maintenance.md).
Docker must be available locally for the full security gate.

```sh
make install
make security-tools
frontend/node_modules/.bin/playwright install chromium
make validate
make security
```

Without Make, use `python3 scripts/manage.py install`, `security-tools`,
`validate` and `security`. Advisory/rule/tool installation and security scans
require the network; the installed application and ordinary validation remain
offline-capable. Linux browser setup can require Playwright's `--with-deps`.

In this existing worktree, preserve the old processes/environments by using
the already verified isolated runtimes:

```sh
export PATH="$PWD/.runtime/node-v24.21.0-darwin-arm64/bin:$PATH"
export SENTINELFLOW_PYTHON="$PWD/.runtime/venv/bin/python"
make validate
make security
```

To choose a new evidence label:

```sh
.runtime/venv/bin/python scripts/security_release.py \
  --output artifacts/security/my-new-assessment
```

The label must not already exist. The gate refuses stale/failed receipts,
changed source during validation, missing tools, incomplete scan coverage,
unreviewed findings, failed tests/builds, disabled Python assertions and
incomplete deployment/browser rehearsals. No failed phase becomes success
through a fallback. Each execution retains commands, outputs and real counts.

The new GitHub Actions workflow is pinned and configured for PR/push/manual
execution and daily 05:17 UTC scanning. **It has not been run on hosted
GitHub infrastructure.** Its existence is not represented as hosted CI proof.

Earlier failed candidate receipts are retained. They exposed a browser fixture
operator error, an already-expanded raw-event control, genuine application
rate/lease enforcement and an unreviewed synthetic test token. Those failures
were corrected or technically classified, then the complete gate rerun.
The later snapshot-permission defect also received a failing regression,
a fix and another complete successful gate.
The packaging pass additionally verified public-key metadata classifications,
absolute snapshot paths and exclusion of historical audit archives from
production images. The complete gate was rerun with those changes and the
packaged evidence present.

## Evidence identity and preservation

| Artifact | SHA-256 |
|---|---|
| Final release summary | `441326e4b85d45e1f3ceba1ebcaad9b1212e49e0ea354c5615d8df3bbd52fe22` |
| Final validation receipt | `4e8603e22bab97a9d903751c7a698637c9e5ab4b74b67cad97c75bca6d650c92` |
| Dependency inventory | `7db9ba077c1e45237e10205aa6772e844145281d5b7d75d299c237c075ba755c` |
| Combined CycloneDX SBOM | `98e1319e6ab05b46aa6fa6e118fe11adf2a5dcb808474f73c355fd986c6c7fc7` |
| Original full-run manifest | `7b8f93319b441048e0856df8cfb0cb2f8bbec0fd751ae4e98b211964eec5603c` |
| Preserved original demonstration MP4 | `aa444d5de6e407cd1977cd41690fc972e3e92f6fa13ec854942f91af01366df5` |

The original eight screenshots and `recordings/sentinelflow-final-demo.mp4`
remain byte-identical to their committed versions. The MP4 is 9,730,783 bytes,
356.16 seconds, 1440 x 1000, 25 fps, H.264 and silent. It demonstrates the
original application phase, not a newly recorded security assessment.
No original media was regenerated.

The curated package contains raw scanner output, classifications, SBOMs,
JUnit/frontend/coverage reports, detection/Sigma/integration/benchmark results,
browser screenshots, deployment/collector receipts and before-fix evidence.
`curation.json` records the copied source and hash of every unmodified raw file.
Its dependency ledger explicitly remaps after-fix references to the final
verified scans while preserving the original ledger.
After the document and refreshed reports were written, a separate
[current-tree secret check](results/security/documentation-check/summary.json)
passed with the same exact public-key classification policy. It is labeled as
a documentation check, not substituted for the complete release gate.
The [preservation receipt](results/security/preservation.json) records the
unchanged media, HEAD and healthy legacy services.

Private source/environment snapshots, SQLite databases, installed scanners and
downloaded third-party Semgrep rule packs are excluded from the distributable
package. Their original hashes/commands remain in the local full-run manifest;
the local originals remain under the ignored artifact directory. Do not
publish that directory wholesale.

## What remains unperformed or outside this release

| Item | Exact status |
|---|---|
| Live Microsoft Sentinel/Azure Monitor tenant | Not tested |
| Live Microsoft Graph/Entra tenant | Not tested |
| Live Windows domain/Event Log/WEF deployment | Not tested |
| Live Power Automate | Not tested |
| Live Teams channel | Not tested |
| External webhook receiver | Not tested |
| Independent penetration test | Not performed |
| Enterprise HA, failover and scale validation | Not performed |
| Multi-tenant RBAC / SSO | Not implemented |
| Distributed DDoS protection | Not implemented |
| Encrypted SQLite application/collector spool | Not implemented |
| Immutable audit storage / enterprise backup platform | Not implemented |
| Hosted CI execution / Vercel or Render deployment | Not performed |
| Preserved service cutover to the hardened runtime | Not performed; existing processes deliberately preserved |
| Complete advisory coverage of optional native recorder and host/toolchain software | Not claimed |
| Full EVTX and arbitrary Sigma support | Not implemented; documented subsets remain |
| Enterprise false-positive-rate measurement | Not performed; included benign fixtures are controlled tests |

**Known remaining vulnerabilities in the final scanned dependency set:
none reported. Release blockers in the defined local scope: none identified.**

That statement does not clear the preserved legacy runtimes or the explicitly
unscanned/unperformed environments. Re-scan before a future release, obtain
approval before replacing existing processes, and perform real tenant/Windows/
receiver and hosting verification before making any live-integration or
production-readiness claim.
