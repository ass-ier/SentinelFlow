# Included telemetry manifest

Generator: `python scripts/generate_test_data.py`; fixed seed `sentinelflow-20260115-v1`.

All generated telemetry is inert text and is never executed. Identities are invented;
addresses are private/reserved and domains use `.test`. Expected results below are
authored policy contracts, not learned from detector output. Counts are per isolated run
with the seven bundled rules enabled. Duplicate input records do not increase evidence.

| Dataset / path | Format | Input records | Expected alerts | Rules | Purpose / class | Source / license |
|---|---|---:|---:|---|---|---|
| `authentication/brute_force.jsonl` | jsonl | 25 | 1 | AUTH-001 | Repeated failed login: 25 attempts, one source / positive | Synthetic generator / MIT |
| `benign/normal_authentication.jsonl` | jsonl | 3 | 0 | none | Three ordinary login errors remain below threshold / benign | Synthetic generator / MIT |
| `authentication/normal_login.jsonl` | jsonl | 8 | 0 | none | Successful employee logins / benign | Synthetic generator / MIT |
| `authentication/lifecycle.jsonl` | jsonl | 2 | 0 | none | Logout and password change / benign | Synthetic generator / MIT |
| `authentication/distributed_failures.jsonl` | jsonl | 12 | 0 | none | Distributed low-volume failures; no per-source threshold / boundary | Synthetic generator / MIT |
| `authentication/password_spray.jsonl` | jsonl | 12 | 1 | AUTH-001 | One source targets multiple users / positive | Synthetic generator / MIT |
| `authentication/account_lockout.jsonl` | jsonl | 4 | 1 | AUTH-002 | Four lockouts on one domain controller / positive | Synthetic generator / MIT |
| `benign/normal_lockouts.jsonl` | jsonl | 2 | 0 | none | Two isolated account lockouts / benign | Synthetic generator / MIT |
| `authentication/below_threshold.jsonl` | jsonl | 9 | 0 | none | Exactly one event below the brute-force threshold / boundary | Synthetic generator / MIT |
| `authentication/window_boundary.jsonl` | jsonl | 10 | 1 | AUTH-001 | Inclusive 300-second event-time boundary / boundary | Synthetic generator / MIT |
| `authentication/window_outside.jsonl` | jsonl | 10 | 0 | none | One microsecond outside the inclusive window / boundary | Synthetic generator / MIT |
| `authentication/group_separation.jsonl` | jsonl | 20 | 2 | AUTH-001 | Independent sources create independent evidence / regression | Synthetic generator / MIT |
| `authentication/duplicate_events.jsonl` | jsonl | 50 | 1 | AUTH-001 | Repeated identical event IDs cannot inflate thresholds / regression | Synthetic generator / MIT |
| `authentication/shuffled_events.jsonl` | jsonl | 25 | 1 | AUTH-001 | A shuffled batch is evaluated chronologically / regression | Synthetic generator / MIT |
| `authentication/suppression_boundary.jsonl` | jsonl | 25 | 2 | AUTH-001 | Suppression ends exactly 600 seconds after the first trigger / regression | Synthetic generator / MIT |
| `authentication/missing_source.jsonl` | jsonl | 10 | 0 | none | Missing grouping entities are not merged into an unknown source / regression | Synthetic generator / MIT |
| `powershell/suspicious_powershell.jsonl` | jsonl | 5 | 1 | PROC-001 | Five suspicious PowerShell indicators; never executed / positive | Synthetic generator / MIT |
| `powershell/encoded_command.jsonl` | jsonl | 1 | 1 | PROC-001 | Inert encoded-command telemetry / positive | Synthetic generator / MIT |
| `benign/administrative_powershell.jsonl` | jsonl | 4 | 0 | none | Routine unencoded PowerShell administration / benign | Synthetic generator / MIT |
| `powershell/legitimate_installer.jsonl` | jsonl | 1 | 1 | PROC-001 | Legitimate download still flags the indicator; intent is not inferred / policy | Synthetic generator / MIT |
| `process/suspicious_execution.jsonl` | jsonl | 3 | 1 | PROC-002 | Configurable process relationships and command-line patterns / positive | Synthetic generator / MIT |
| `benign/normal_processes.jsonl` | jsonl | 2 | 0 | none | Ordinary command prompt and script execution / benign | Synthetic generator / MIT |
| `privilege-escalation/privileged_group.jsonl` | jsonl | 2 | 1 | IAM-001 | Add and remove a privileged group member / positive | Synthetic generator / MIT |
| `benign/normal_group_modification.jsonl` | jsonl | 2 | 0 | none | Nonprivileged helpdesk group maintenance / benign | Synthetic generator / MIT |
| `benign/privileged_group_maintenance.jsonl` | jsonl | 2 | 0 | none | Explicit service, host, and ticket maintenance exception / benign | Synthetic generator / MIT |
| `privilege-escalation/maintenance_wrong_host.jsonl` | jsonl | 2 | 1 | IAM-001 | A service name and ticket alone must not exempt another host / regression | Synthetic generator / MIT |
| `privilege-escalation/privileged_account.jsonl` | jsonl | 2 | 1 | IAM-001 | Privileged account creation and escalation / positive | Synthetic generator / MIT |
| `privilege-escalation/service_account_activity.jsonl` | jsonl | 2 | 0 | none | Nonprivileged account provisioning and service login / benign | Synthetic generator / MIT |
| `benign/normal_dns.jsonl` | jsonl | 10 | 0 | none | Low-volume ordinary DNS names / benign | Synthetic generator / MIT |
| `dns/long_labels.jsonl` | jsonl | 3 | 1 | DNS-001 | Unusually long labels, not proof of tunneling / positive | Synthetic generator / MIT |
| `dns/high_entropy.jsonl` | jsonl | 3 | 1 | DNS-001 | Repeated high-entropy-looking labels / positive | Synthetic generator / MIT |
| `dns/high_frequency.jsonl` | jsonl | 25 | 1 | DNS-001 | 25 queries in 25 seconds / positive | Synthetic generator / MIT |
| `dns/repeated_subdomains.jsonl` | jsonl | 22 | 1 | DNS-001 | Repeated unusual subdomains cross the configurable frequency threshold / positive | Synthetic generator / MIT |
| `benign/dns_below_threshold.jsonl` | jsonl | 19 | 0 | none | 19-query controlled burst, below the configured frequency threshold / boundary | Synthetic generator / MIT |
| `network/unusual_ports.jsonl` | jsonl | 6 | 1 | NET-001 | Repeated connections to an unusual port / positive | Synthetic generator / MIT |
| `benign/normal_connections.jsonl` | jsonl | 8 | 0 | none | Repeated normal HTTPS connections and requests / benign | Synthetic generator / MIT |
| `network/below_threshold.jsonl` | jsonl | 2 | 0 | none | Two unusual-port events are below threshold / boundary | Synthetic generator / MIT |
| `benign/monitoring_connections.jsonl` | jsonl | 6 | 0 | none | Explicit allowlisted monitoring destination / benign | Synthetic generator / MIT |
| `benign/private_connections.jsonl` | jsonl | 6 | 0 | none | Private service connections excluded by configured policy / benign | Synthetic generator / MIT |
| `mixed/incident_timeline.jsonl` | jsonl | 56 | 7 | AUTH-001, AUTH-002, DNS-001, IAM-001, NET-001, PROC-001, PROC-002 | Seven detection families interleaved with successful logins / mixed | Synthetic generator / MIT |
| `benign/baseline_1000.jsonl` | jsonl | 1000 | 0 | none | 1,000 successful logins for baseline and performance work / benign | Synthetic generator / MIT |
| `parsers/events.csv` | csv | 1 | 0 | none | Dotted-column CSV normalization contract / parser | Synthetic generator / MIT |
| `parsers/auth.log` | syslog | 5 | 0 | none | Five supported authentication syslog messages / parser | Synthetic generator / MIT |
| `parsers/windows_events.json` | windows | 5 | 0 | none | Windows Security/Sysmon-style exported JSON, not EVTX / parser | Synthetic generator / MIT |
| `parsers/normalized.json` | json | 2 | 0 | none | Nested normalized JSON objects / parser | Synthetic generator / MIT |
| `sigma/download_iex.jsonl` | jsonl | 1 | 1 | PROC-001 | Synthetic Sigma compatibility telemetry / sigma | Synthetic generator / MIT |
| `sigma/encoded.jsonl` | jsonl | 1 | 0 | none | Synthetic Sigma compatibility telemetry / sigma | Synthetic generator / MIT |
| `sigma/benign_encoding.jsonl` | jsonl | 1 | 0 | none | Synthetic Sigma compatibility telemetry / sigma | Synthetic generator / MIT |
| `sigma/benign_azure.jsonl` | jsonl | 1 | 0 | none | Upstream Azure parent-image exclusion / sigma | Synthetic generator / MIT |
| `public/otrf_adapted.json` | windows | 6 | 0 | none | Privacy-reduced public lab telemetry (parser interoperability) / public | OTRF public lab; adapted; see public/provenance.json / MIT at pinned revision (README caveat documented) |

## Sigma fixtures

| Path | Format | Events | Expected imported-rule alerts | Source / license |
|---|---|---:|---|---|
| `sigma/download_iex.jsonl` | JSONL | 1 | 1 high, upstream 85b0b087-eddf-4a2b-b033-d771fa2b9775 | Synthetic / MIT |
| `sigma/encoded.jsonl` | JSONL | 1 | 1 medium, upstream fb843269-508c-4b76-8b8d-88679db22ce7 | Synthetic / MIT |
| `sigma/benign_encoding.jsonl` | JSONL | 1 | 0 for both imported rules | Synthetic / MIT |

Unmodified upstream Sigma rules and license notices live in `sigma/rules/` and
`sigma/LICENSE.Detection.Rules.md`; pinned provenance is in `sigma/provenance.json`.

## Policy, not enterprise false-positive measurement

Legitimate download indicators deliberately still alert. The IAM maintenance exception
requires `svc_identity` on `id-admin-01` with a `CHG-` numeric ticket; removing any part
still alerts. These fields are untrusted telemetry, not authorization. Normal DNS bursts
below 20 queries/minute are negative fixtures, not a universal baseline. Distributed
low-rate login failures do not cross AUTH-001's **per-source** threshold. The controlled
benign set cannot establish an enterprise false-positive rate.

`expected-results/scenarios.json` is the machine-readable exact alert/severity/evidence
contract. `manifest.json` includes SHA-256 digests and synthetic/source labels.

## Additional validation inputs

| Path | Format | Records / purpose | Expected result | Source / license |
|---|---|---|---|---|
| `mixed/benchmark_5600.jsonl` | JSONL | 5,600 events; 100 hourly incident cycles | 700 alerts, 100 per bundled rule | Synthetic / MIT |
| `sigma/benign_azure.jsonl` | JSONL | 1 event; full parent executable filter | 0 imported encoded-rule alerts | Synthetic / MIT |
| `security/overflow_number.json` | JSON | 1 malformed metadata object | Reject non-finite number | Synthetic / MIT |
| `security/nonfinite.yaml` | YAML | 1 malformed metadata object | Reject non-finite number | Synthetic / MIT |
| `security/sigma_dates.yml` | YAML | 1 metadata object | Preserve unquoted dates as strings | Synthetic / MIT |
| `expected-results/parser-contracts.json` | JSON | Five parser contracts; 21 expected normalized objects | Exact equality | Authored independently / MIT |
| `expected-results/benchmark.json` | JSON | One authored benchmark contract | Exact counts and checksum | Synthetic / MIT |

The public sample, its six selected source rows, explicit privacy transformations,
MIT notice, and upstream README licensing caveat are in `public/provenance.json`
and `public/LICENSE.OTRF`. It is attack-simulation data used for parser
interoperability, not a benign scenario or a claim of public attack detection.
