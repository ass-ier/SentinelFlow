# Integration fixture manifest

All telemetry here is deterministic, invented and synthetic. It is generated
locally by `scripts/generate_integration_data.py`, released under the project's
MIT license, and contains no exported customer/tenant/domain data. Identities
are fictional, email/DNS names use `.invalid`, and addresses use reserved
documentation ranges. Source: this repository's generator; no external telemetry
was downloaded for this phase. The fixed event date is 2026-01-15 UTC.

`microsoft-windows.json` is a JSON object, not a single generic event array.
Its collections are consumed by the connector mock server, collector fixture
mode, and tests. It is separate from the core 50-scenario dataset manifest.

| JSON collection | Records | Purpose | Expected clean-run alerts |
|---|---:|---|---|
| `sentinel.SigninLogs` | 12 | Ten failed sign-ins and two successes | One AUTH-001 with ten evidence events |
| `sentinel.AuditLogs` | 1 | Explicit host detail and privileged group membership | One IAM-001 |
| `graph.signIns` | 12 | Graph equivalent, including IDs/result/device/account/IP | One AUTH-001 |
| `graph.directoryAudits` | 1 | Graph initiator/target/additionalDetails equivalent | One IAM-001 |
| `windows` | 36 | Security, PowerShell, Sysmon, System and Application | Seven alerts, one per bundled rule |
| `wazuh` | 1 | Wazuh EventChannel adapter compatibility | No alert from this one failed login |
| `benign.sentinel.SigninLogs` | 2 | Successful sign-ins | None |
| `benign.sentinel.AuditLogs` | 1 | Membership in Readers, not a privileged group | None |
| `benign.graph.signIns` | 2 | Successful sign-ins | None |
| `benign.graph.directoryAudits` | 1 | Non-privileged Readers membership | None |
| `benign.windows` | 4 | Success, ordinary Notepad, System and Application | None |

The positive top-level collections contain 63 source rows including Wazuh; the
three full integration demos consume 62. Benign collections contain ten rows.
`expected` and `benign.expected` preserve authored event/rule-count expectations.
They are not generated from observed engine output.

The Windows sequence includes fifteen distinct Security ID examples, nine
additional 4625 failures, two additional 4740 lockouts, PowerShell 4104,
Sysmon process 1, three network 3, three DNS 22, System 7036 and Application 1000.
The scripts and encoded strings are inert telemetry, never executed.

The audit fixtures intentionally include a supplied Computer additional detail.
Real Graph directory audits often lack a host. The normalizer leaves such a
host absent rather than inventing one, which affects host-grouped IAM detection.
The benign cases measure these controlled examples only, not an enterprise
false-positive rate.

`notification.schema.json` is generated from the actual Pydantic
`NotificationPayload` model. It defines version 1.0 security alert/test messages,
not credentials or raw telemetry. No proprietary flow or notification export is
included.

Regenerate and compare:

```sh
.venv/bin/python scripts/generate_integration_data.py
.venv/bin/python scripts/generate_integration_data.py --check
.venv/bin/python scripts/validate_integrations.py
```

`make validate` performs the byte-for-byte generator check. Actual measured
results are written to `artifacts/integrations-validation.json`; the immutable
phase evidence copy is under `docs/results/integrations/`. Positive, benign,
failure, retry, pagination, checkpoint, scope, collector and migration behavior
is covered in `backend/tests/integrations/`.
