# Event and alert data model

Every accepted event has the following nested shape. Nullable fields are still
present in normalized API responses; unknown top-level/schema keys are rejected.

| Path | Meaning |
|---|---|
| `event.id` | Source ID or deterministic 128-bit SHA-256 prefix of parser name and canonical original record |
| `event.timestamp` | Timezone-aware event time, normalized to UTC |
| `event.source` | Telemetry provider/source label, independent of source IP |
| `event.category` | `authentication`, `process`, `network`, `identity`, `file`, `system`, `application` |
| `event.type` | Source event type, e.g. `info` or `start` |
| `event.action` | Normalized action such as `login`, `process_created`, `dns_query` |
| `event.outcome` | `success`, `failure`, `unknown` |
| `event.severity` | `informational`, `low`, `medium`, `high`, `critical` |
| `host.name`, `host.ip` | Observed host identity |
| `user.name` | Actor identity |
| `source.ip`, `source.port` | Source endpoint |
| `destination.ip`, `destination.port` | Destination endpoint |
| `process.name`, `process.command_line` | Process basename and inert command-line text |
| `process.executable`, `process.pid` | Optional full executable path and PID |
| `process.parent.name`, `.executable`, `.pid` | Optional parent identity; full path retained for Sigma |
| `network.protocol` | Protocol, e.g. TCP/UDP |
| `dns.query` | DNS name, up to 253 characters |
| `file.path` | Optional file path |
| `raw_event` | Original record values or original syslog line |
| `metadata` | Bounded JSON-compatible source extensions and derived features |

IP addresses and ports are validated. Naive timestamps are rejected; there is
no implicit host timezone. Years are bounded to 1970-2100. JSON object order
does not change generated IDs; changing formats without an explicit source ID
can change the generated ID. IDs are reproducibility keys, not a claim of
cryptographic source authentication.

## Formats

- **JSON / JSONL:** nested normalized objects or documented flat aliases
  (`timestamp`, `category`, `action`, `outcome`, `source_ip`, `user`, `host`,
  `process_name`, `command_line`, etc.). A JSON file contains one object or a list;
  JSONL contains one object per nonblank line. BOMs are supported.
- **CSV:** UTF-8, a unique header, consistent row widths, dotted field names or
  flat aliases. Empty optional fields become null. The raw row retains strings.
- **Authentication syslog:** optional PRI, RFC3164-style or timezone-aware ISO
  timestamp, host, program/PID, then recognized failed/accepted SSH login, session
  open/close, lockout, or password-change messages. RFC3164 has no year/zone:
  the explicit import year defaults to **2026**, interpreted as UTC. Change
  `syslog_year` for other inputs; no current-year guessing occurs.
- **Windows JSON:** `System`/`EventData` envelopes or documented compact exports.
  Event IDs 4624, 4625, 4634, 4723, 4740, 4688, 4104, 4728/4729,
  4732/4733, 4756/4757, 4720, 4722, 4725, 4726, and 4672 are mapped. Sysmon IDs 1, 3, and 22
  require an explicit Sysmon provider to avoid ambiguous numeric event IDs.
  `Image` and `ParentImage` retain full paths as well as basenames.
- **Wazuh:** explicit `wazuh` input supports EventChannel
  `data.win.system`/`eventdata` and recognized authentication `full_log` messages.
  Raw alert JSON is preserved. This is a narrow file adapter, not a Wazuh API
  connector or every decoder's schema.
- **Windows collector XML:** the optional native collector converts XML to the
  same Windows envelope and also retains the original XML. Generic System and
  Application channel events are retained with distinct categories.

This is not a general RFC5424 or vendor syslog parser and does not parse binary
EVTX. Unsupported messages/IDs fail explicitly, not as silently dropped rows.
The OTRF adapter documents how its flat source fields are wrapped; arbitrary
flat vendor exports are not claimed compatible.

## Raw evidence

For JSON and Windows inputs, `raw_event` retains the original object values,
including source-specific fields. It is not a byte-for-byte copy of file
whitespace or original offsets. CSV retains the source row dictionary; syslog
retains its line without the newline. Normalized input can supply its own
`raw_event`, which is treated as untrusted source evidence.

DNS metrics are recalculated during normalization, overwriting any submitted
`metadata.dns_metrics`: maximum label length, maximum per-label character entropy,
label count, and a simple last-two-label `base_domain`. This last item is not
a public-suffix/registered-domain implementation.

## Alerts and evidence

Alerts store an ID, run ID, rule ID/name and snapshot, severity, workflow status,
ingestion-time `created_at`, event-time `first_seen`/`last_seen`/`triggered_at`,
source and affected entities, exact event count, MITRE IDs, branch/group,
description, provenance/author, and evidence IDs. A join table links alerts to
stored event observations using foreign keys.

Statuses are `new`, `investigating`, `resolved`, `false_positive`, `suppressed`.
They are analyst workflow states, not engine enable/disable switches.
The event count equals the number of linked distinct evidence records.

Optional connectors add provider, connector ID, table/channel, source host,
original UTC timestamp, ingestion timestamp and supplied identity/authentication
details to bounded `metadata`. No cloud application name is invented as a host.
Alert `telemetry_sources` is distinct from rule-author `provenance`.
`notifications` contains independently persisted delivery states. See
[integration normalization and queue contracts](integrations.md).
