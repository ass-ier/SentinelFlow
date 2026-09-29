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
This private option is not SSO, RBAC, authorization per dataset, or tenant isolation.

## Explicit public-demo boundary

`SENTINEL_PUBLIC_DEMO=true` enables credential-free access to a separate,
synthetic-only shared demonstration. It does not bypass the private policy on an
existing database. A dedicated filename, ownership marker, schema check and
registered synthetic run provenance prevent accidental exposure of a private
database. The public-mode database cannot be opened in private mode.

Only bundled synthetic datasets may be replayed or validated. The non-synthetic
OTRF interoperability sample remains in the local repository but is excluded
from public data APIs. Telemetry uploads, rule mutations/imports, alert status
updates/notes, arbitrary Sigma input and developer project endpoints are denied
server-side under both route prefixes, including requests carrying an owner
token. Public Sigma compilation/testing requires unchanged bundled source and
license/provenance fields.

The owner token, if configured, authorizes only public reset. It is optional for
the service and never a visitor/browser build credential. Reset remains disabled
remotely when no token is configured. Public actors have a fixed audit label;
visitor IPs and arbitrary investigation text are not stored in application audit
records. Do not enter sensitive information into search fields or URLs either:
hosting infrastructure and browsers may keep their own request/history records.

Explicit origin and hostname allowlists remain enabled. CORS is a browser
boundary, not authentication or protection against reading intentionally public
synthetic data with other clients. The production launcher uses one worker and
does not trust forwarded client-IP headers to turn a remote private request into
loopback access. Render's supplied hostname is explicitly added; a custom
backend hostname/origin must be configured.

The Vercel build accepts a configurable HTTP(S) API origin, with external HTTPS
required when identified as a Vercel build. Its CSP permits only that API origin
and self. No tokens belong in `VITE_` variables. Frame-denial is an HTTP header,
not an ineffective `frame-ancestors` meta directive.

## Input and resource limits

Default file size: **5 MiB**; **10,000 unique events per run**; **100 stored rules**;
**two concurrent replay jobs**; timed replay duration at most **10 minutes**.
The HTTP body has a bounded allowance for JSON encoding overhead and is limited
even when sent in chunks. Parsed individual text values are capped at 16,384
characters, nesting at 12 levels, rule YAML at 64 KiB, group keys at four fields,
and threshold windows at one day.

The body has a ten-second absolute reception deadline and is coalesced into one
byte-bounded buffer, not an unbounded list of chunk objects. Invalid
Content-Length syntax is rejected; a stalled body returns 408. Surrogate Unicode
is rejected before parser serialization or storage.

JSON duplicate keys, NaN/Infinity and overflowing numbers, ambiguous CSV widths,
invalid IPs/ports/times, unknown event fields, and unsupported parser messages
fail visibly. YAML uses a SafeLoader-derived mapping loader, rejects duplicate
keys, unsafe tags, anchors/aliases, nonfinite values, and non-string keys.
Dates remain safe strings for actual upstream Sigma metadata.

Regex patterns and inputs are bounded, dangerous constructs are rejected, and
matching has a 5 ms runtime timeout. A timeout is an explicit failure with an
ingest rollback. This is defense in depth, not a promise that all regex workloads
are cheap.

Public mode further limits HTTP bodies to **128 KiB**, retains **20 runs**
(protected seed plus 19 replays), and admits only **one validation/compilation**
at a time. Existing two-job replay and timed-duration limits remain. Finished
replays are pruned with their dependent evidence/audit rows; active replays and
the seed are preserved. These are local process bounds, not per-client rate
limits or enterprise DDoS protection. All visitors share the same replay/cancel
state.

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

Public reset is additionally restricted to the marked, dedicated
`sentinelflow-public-demo.sqlite3`, requires `seed=true`, and restores the fixed
incident. A custom configured path is permitted only with that public filename
and valid ownership. An empty or previously interrupted owned public seed is
initialized at startup; a completed seed is not duplicated on ordinary restart.
Offline CLI reset now reads environment settings rather than silently selecting
the private default database.

Original logs are not authenticated. Raw JSON preserves original values, not
byte-for-byte file provenance. The OTRF sample intentionally preserves only an
adapted privacy-reduced export. Checksums and validation fingerprints detect
local drift; they do not certify a trustworthy upstream log source.

## Explicit limits

No distributed per-client rate-limit service, application TLS termination, backup system,
process sandbox, immutable audit storage, role management, secret rotation UI,
or incident-response automation. The small public history cap is not an enterprise
retention system. Do not expose private mode directly to untrusted networks or
feed this portfolio demo production secrets. Public deployment uses provider
HTTPS and the synthetic-only mode described in [deployment.md](deployment.md).

The historical deployment-phase secret review was a bounded pattern search.
The separate [security assessment](security-assessment.md) adds current-tree and
available-history Gitleaks, dependency/OSV/image scans, SBOMs, full-scope SAST,
bundled-JavaScript Retire.js, and source-bound technical triage. Public upstream
author attribution and historical local execution paths are not operational
telemetry. The public backend does not serve developer documents/logs or the
historical media. Package hashes, `pip check`, tests and successful image builds
still do not imply a clean advisory scan; only the named, dated receipts support
that conclusion.

Security assessment directories and their source snapshots are created with
POSIX mode 0700. The local source snapshot can include an ignored `.env` for
secret scanning; do not publish or upload it. Curated reports exclude source
snapshots and databases. Keep the workspace's ancestor directories trusted, and
review any evidence before sharing it.
The historical security report/SBOM archive in `docs/results/security` stays
in the repository, outside production images. It is not a runtime dependency
inventory for those images; embedding an old SBOM can make a container scanner
attribute historical packages to the current filesystem. Current packages are
still scanned without vulnerability suppressions, and the container probe
checks that the historical archive is absent.

## Optional integration boundary

Private integrations add a versioned additive migration, narrow automation
scopes, environment-only secret references and process-local operation limits.
They do not replace the private owner model with multi-tenant RBAC. Public
synthetic mode rejects external enable flags and management/collector mutations.
Optional `expires_at` values require an explicit timezone and normalize to UTC.
Expired/revoked scoped credentials fail on the next request. Existing credentials
without expiry remain explicitly non-expiring. This does not add expiring owner
sessions or tenant roles.

Microsoft and webhook HTTP is bounded, certificate-verified, DNS/IP-pinned and
redirect-free. Prohibited networks and metadata addresses are rejected, including
mixed DNS answers. Internal HTTPS requires an explicit CIDR allowlist; loopback
HTTP requires explicit test mode. Authentication/error bodies are not stored.
HMAC uses exact body bytes, timestamp tolerance and constant-time comparison;
receivers must also enforce idempotency. The outbox is transactional with alert
creation and cannot delete alerts on delivery failure.
Deprecated IPv6 site-local, 6to4 and Teredo destinations remain denied even with
an overbroad internal allowlist. Local TLS tests exercise certificate trust,
hostname/SNI verification, numeric-address pinning and ignored proxy variables.
The HMAC verifier rejects an empty key; its inclusive 300-second timestamp window
is not a persistent replay cache. Receivers still need durable idempotency.

Collector XML uses `defusedxml`, not a substring blacklist, to reject DTD and
internal/external entities, including disguised UTF-16 input. It is bounded to
64 KiB, 12 nested levels and 1,024 nodes and preserves original XML. The existing
16,384-character normalized value limit still applies, so unusually large XML
events can be rejected and retained in the spool for explicit handling rather
than silently truncated. Spool and application databases require operating
system permissions; neither is encrypted by this application.
Malformed persisted spool JSON is quarantined as `invalid_payload`, not deleted
or allowed to crash the delivery loop. POSIX spool files use mode 0600, an
other-user-writable immediate directory is rejected, and the spool file/direct
parent cannot be a symlink. Windows ACLs and the trusted directory hierarchy
remain operator responsibilities. Schema migration checks existing required
columns and refuses incomplete/future schemas before mutation.

Private OpenAPI declares owner/scoped bearer requirements. Public OpenAPI prunes
private operations and their unused schemas; this is documentation minimization,
not a replacement for endpoint authorization. Offline Swagger assets are locked,
license-preserved, byte-verified and scanned independently for bundled libraries.

Reset now also refuses enabled connectors/destinations and in-flight deliveries.
After disabling them, a named-demo reset clears connector checkpoints/dedup,
delivery history and counters while retaining disabled configuration references.
See [integration security and failure semantics](integrations.md) and its
scoped-token, SSRF, response-limit, timeout, redaction and restart tests.
