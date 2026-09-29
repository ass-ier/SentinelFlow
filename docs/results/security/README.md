# Security evidence index

The final local gate passed on **2026-09-28 at 23:55:34 UTC**.
Read the [assessment](../../security-assessment.md) for scope, findings,
functional status, limitations and reproduction commands.

Source fingerprint:
`2485344225394ffafaaa9feba73eac583d02e704e3d26747d38fe9abcbe22ea6`.

HEAD is `b987e6d7526b9a643bf9813fe816ada21c706b55`; the assessed worktree
contains uncommitted changes. The fingerprint, not HEAD alone, binds this release.

## Main evidence

| Evidence | File |
|---|---|
| Final gate and full commands | [summary.json](final/summary.json) |
| File/hash manifest for this curated package | [evidence-manifest.json](evidence-manifest.json) |
| Original full-run file manifest | [manifest.json](final/manifest.json) |
| Post-documentation current-tree secret check | [summary.json](documentation-check/summary.json) |
| Media / legacy service preservation | [preservation.json](preservation.json) |
| Byte-identical copy mapping / exclusions | [curation.json](curation.json) |
| Dependency inventory | [dependency-inventory.json](final/dependency-inventory.json) |
| Combined 545-component CycloneDX SBOM | [sbom.cdx.json](final/sbom.cdx.json) |
| Python complete lock audit | [python-lock.json](final/python-lock.json) |
| Python runtime lock audit | [python-runtime.json](final/python-runtime.json) |
| Python installed environment audit | [python-installed.json](final/python-installed.json) |
| Python scanner lock audit | [python-scanners.json](final/python-scanners.json) |
| npm complete / production audits | [complete](final/node-all.json), [production](final/node-production.json) |
| OSV | [osv.json](final/osv.json) |
| Shipped Swagger / frontend JavaScript | [Swagger](final/retire-swagger.json), [frontend](final/retire-frontend.json) |
| Filesystem / installed-environment scans | [filesystem](final/filesystem-trivy.json), [installed](final/installed-sbom-trivy.json) |
| Backend / application image scans | [backend](final/container-backend.json), [application](final/container-application.json) |
| Per-image SBOMs | [backend](final/container-backend.cdx.json), [application](final/container-application.cdx.json) |
| Raw Bandit / Semgrep | [Bandit](final/bandit.json), [Semgrep](final/semgrep.json) |
| Per-finding SAST classification | [sast-triage.json](final/sast-triage.json) |
| Raw current / historical Gitleaks | [current](final/secrets-working-tree.json), [history](final/secrets-history.json) |
| Historical secret-match classification | [secrets-triage.json](final/secrets-triage.json) |
| Published Python signing-key provenance | [public-key-provenance.json](public-key-provenance.json) |
| Historical SBOM packaging diagnosis | [packaging-diagnostic.json](packaging-diagnostic.json) |
| 478-record dependency remediation ledger | [dependency-remediation.json](dependency-remediation.json) |
| Tool versions / advisory database | [versions](final/tool-versions.json), [Trivy database](final/advisory-database.json) |
| Complete validation receipt and log | [receipt](final/validation.json), [log](final/validation.log) |
| Backend JUnit / frontend results | [JUnit](final/backend-junit.xml), [frontend](final/frontend-tests.json) |
| Coverage | [coverage.json](final/coverage.json) |
| Detection validation | [JSON](final/detection-validation.json), [text](final/detection-validation.txt) |
| Sigma / integration validation | [Sigma](final/sigma-validation.json), [integrations](final/integrations-validation.json) |
| Actual measured benchmark | [benchmark.json](final/benchmark.json) |

## Real browser, collector and deployment evidence

| Rehearsal | Receipt |
|---|---|
| Entire rehearsal sequence | [rehearsals.json](final/rehearsals/rehearsals.json) |
| 33 analyst browser checks | [analyst-browser.json](final/rehearsals/analyst-browser.json) |
| 28 integration browser checks | [browser-results.json](final/rehearsals/integration-browser/browser-results.json) |
| 12 security browser checks | [browser.json](final/rehearsals/security-browser/browser.json) |
| Native public deployment | [report.json](final/rehearsals/deployment-native/report.json) |
| Docker public deployment | [report.json](final/rehearsals/deployment-docker/report.json) |
| Network-isolated application image | [private-image-probe.log](final/rehearsals/private-image-probe.log) |
| Collector actual outage / restart / repeat | [outage](final/rehearsals/collector-outage.log), [recovery](final/rehearsals/collector-recovery.log), [repeat](final/rehearsals/collector-repeat.log) |
| Expired credential UI | [credential-expiry.png](final/rehearsals/security-browser/credential-expiry.png) |
| Inert malicious raw evidence | [literal-evidence.png](final/rehearsals/security-browser/literal-evidence.png) |
| Mobile integration UI | [integrations-mobile.png](final/rehearsals/integration-browser/integrations-mobile.png) |
| Docker desktop/mobile UI | [desktop](final/rehearsals/deployment-docker/desktop-dashboard.png), [mobile](final/rehearsals/deployment-docker/mobile-dashboard.png) |

These checks used real local HTTP and browser processes. All Microsoft/provider
and notification receivers were mocks or fixtures. **Live integrations: not
tested.** The original eight screenshots and six-minute MP4 were preserved
separately and were not re-recorded.

## Baseline and failed candidates

`baseline/` retains actual old advisory/SAST/secret reports, the vulnerable
Swagger scan and the failing XML reproducer. `remediation/` retains additional
before-fix logs, the artifact-permission failure and passing regression, the
corrected real container probe and final gate console output.

`earlier-gates/` preserves candidate summaries, including failed runs and the
earlier passes before all packaging changes. Only `final/`, copied from
`artifacts/security/release-delivery/`, is the completed source identified
above. No earlier receipt is presented as current.

Paths inside unmodified raw receipts retain their original execution locations
and command arguments. `curation.json` maps those copies to this package.
The derived remediation ledger points its after-fix references to `final/`;
its unchanged original is `baseline/dependency-triage-original.json`.

## Scope of the manifests

`final/manifest.json` is the original run manifest. It also records local
private files intentionally not copied here. The top-level
`evidence-manifest.json` is the manifest to verify this curated package and its
assessment document. Neither includes its own hash, avoiding a circular digest.
The separately labeled `documentation-check/` receipt verifies the refreshed
working tree after documentation/evidence packaging, using the same fail-closed
secret classifications.

Source/environment snapshots, SQLite databases, installed tools and downloaded
third-party Semgrep rule packs are deliberately not distributed here. Their
local originals, command provenance and hashes remain under
`artifacts/security/release-delivery/`; the snapshot directories are mode 0700.
No raw scanner report in this package has been rewritten to remove findings.

All counts are time-bound observations, not a certification that vulnerabilities
cannot exist. Re-run the gate against current advisory databases before a
future release.
