# Third-party notices

Application code and deterministic synthetic telemetry use the root MIT license.
This does not relicense third-party material.

- **SigmaHQ detection rules:** Detection Rule License 1.1. Authors Florian Roth
  (Nextron Systems) and frack113. Unmodified rule files, original comments,
  source/revision/hash metadata, and the full license are under
  `test-data/sigma/`. Attribution is also retained on match messages as required.
- **OTRF Security Datasets:** copyright (c) 2021 Open Threat Research Forge,
  MIT at the explicitly pinned root LICENSE. The full notice is
  `test-data/public/LICENSE.OTRF`. Read the upstream README discrepancy and
  modifications in `docs/data-provenance.md`; only the disclosed adapted sample
  is redistributed.
- **Python / JavaScript libraries:** installed from their pinned package
  distributions, which retain their upstream licenses. Lockfiles record exact
  dependencies. Offline Swagger UI 5.33.0 is copied byte-for-byte from the locked
  `swagger-ui-dist` npm distribution. Its Apache-2.0 LICENSE, NOTICE, bundled
  component notices and integrity/provenance record are retained under
  `backend/app/static/swagger/`; `scripts/vendor_swagger.py --check` verifies it.
  Retire.js separately scans shipped JavaScript, including embedded libraries.
  The replaced `swagger-ui-bundle` Python package is not part of the release.
  The UI icon set is Lucide. Optional Scarf installation telemetry is disabled.
- **Design assistance:** the bundled Impeccable design skill by Paul Bakaus,
  https://impeccable.style, was used during implementation. No proprietary design
  assets, source code from unrelated repositories, or third-party marketing
  imagery is included.

No sample command, image, URL, or attack-themed telemetry is executed. Public
source reproduction scripts are explicit optional actions; core operation and
validation use the saved, licensed files.
