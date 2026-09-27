# Security model

SentinelFlow treats telemetry, rules, Sigma documents, filenames, metadata, and
search parameters as untrusted. This is a local portfolio application, not a
hardened multi-tenant security service.

## Access boundary

Development binds both servers to `127.0.0.1`. Without a token, the backend
permits operational access only from loopback. Host validation and a narrow
origin allowlist protect the local app against obvious cross-origin writes and
DNS rebinding. Do not change these into wildcard allowlists.

Development origins follow `SENTINEL_FRONTEND_PORT` unless
`SENTINEL_ALLOWED_ORIGINS` explicitly overrides them. A copied `.env.example`
contains a 5173 override; update or remove it when using another frontend port.
The backend port and the allowed browser origin are separate settings.

Set `SENTINEL_API_TOKEN` for bearer-token access. It must be printable ASCII,
without whitespace, and at most 256 characters; use a randomly generated value.
It is compared in constant time behind one replaceable dependency, so a future
identity provider can replace the policy. Malformed/non-ASCII request tokens
receive an explicit 401. The frontend stores an analyst-supplied token in
session storage, not source control. `.env` and local databases are ignored.

Docker requires a token because container traffic is not loopback inside the
container. The host port remains bound to loopback and the process is non-root.
This is not SSO, RBAC, authorization per dataset, or tenant isolation.

## Input and resource limits

Default file size: **5 MiB**; **10,000 unique events per run**; **100 stored rules**;
**two concurrent replay jobs**; timed replay duration at most **10 minutes**.
The HTTP body has a bounded allowance for JSON encoding overhead and is limited
even when sent in chunks. Parsed individual text values are capped at 16,384
characters, nesting at 12 levels, rule YAML at 64 KiB, group keys at four fields,
and threshold windows at one day.

JSON duplicate keys, NaN/Infinity and overflowing numbers, ambiguous CSV widths,
invalid IPs/ports/times, unknown event fields, and unsupported parser messages
fail visibly. YAML uses a SafeLoader-derived mapping loader, rejects duplicate
keys, unsafe tags, anchors/aliases, nonfinite values, and non-string keys.
Dates remain safe strings for actual upstream Sigma metadata.

Regex patterns and inputs are bounded, dangerous constructs are rejected, and
matching has a 5 ms runtime timeout. A timeout is an explicit failure with an
ingest rollback. This is defense in depth, not a promise that all regex workloads
are cheap.

No parser uses shell execution. No uploaded script or PowerShell command is
executed. Synthetic fixtures are inert text. The only subprocesses in project
scripts are explicit local development, test, build, or recording commands.
Public ZIP data is size/hash checked and read in memory, never extracted or
executed; public source reproduction is optional and outside normal validation.

## Storage, presentation, errors

SQLAlchemy binds search parameters; wildcard search characters are escaped.
Foreign keys preserve evidence integrity. Raw telemetry is rendered as text,
not HTML. The app sends CSP, nosniff, no-referrer, and frame-denial headers.
Swagger's own local initialization script requires a docs-only inline-script
exception; app pages do not receive that exception.

Expected input failures return structured errors without echoing the entire
record or token. Unexpected failures log a request/run identifier and produce
an explicit generic failure for the client. Rule enablement, ingestion, replay,
and status updates leave audit records. Audit records are not tamper-proof.

## Reset and evidence integrity

Reset is restricted to `data/sentinelflow-demo.sqlite3`, rejects active replays,
and never accepts an arbitrary delete path. The CLI restores generated fixtures
before requesting reset/seed; a generation failure prevents that reset request.
It does not delete unrelated files or the repository.

Original logs are not authenticated. Raw JSON preserves original values, not
byte-for-byte file provenance. The OTRF sample intentionally preserves only an
adapted privacy-reduced export. Checksums and validation fingerprints detect
local drift; they do not certify a trustworthy upstream log source.

## Explicit limits

No rate-limit service, TLS termination, migrations, backup/retention system,
process sandbox, immutable audit storage, role management, secret rotation UI,
or incident-response automation. Do not expose the app to untrusted networks
or feed it production secrets. Use synthetic/local authorized telemetry.
