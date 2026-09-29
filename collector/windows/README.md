# Windows / WEF collector

`collect.py` is a real Windows Event Log reader and durable outbound collector.
It uses Python `ctypes` and `wevtapi`; it does not run PowerShell, execute event
commands, install WEF, alter audit policy, or remotely query a domain controller.
The fixture harness runs on other operating systems. Actual Windows/domain
permissions, throughput and WEF subscription behavior have **not been live-tested**.

## Owner-managed setup

1. Configure Windows Event Forwarding and a Windows Event Collector using
   [Microsoft's WEF guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection).
   Select required Security, PowerShell and Sysmon channels, enable the needed
   audit generation, and verify events reach WEC's ForwardedEvents log.
   WEF itself does not turn on audit policy or create missing events.
2. Install patched Python 3.13.15 and the repository's hash-pinned dependencies on
   the WEC host. From the repository root in PowerShell:

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements.lock
   .\.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation -e .
   ```

3. Run under a dedicated identity with appropriate channel read permissions.
   Apply restrictive ACLs to its spool/configuration directory. Logs, spool rows
   and bookmarks can contain sensitive telemetry; this implementation does not
   encrypt them. Choose the service/scheduled-task policy yourself.
4. On the SentinelFlow backend, enable `WINDOWS_COLLECTOR_ENABLED=true`.
   Create/enable a live Windows connector. Register a separate random server
   token through an environment reference with only `windows:ingest` and bind it
   to that connector. Do not use the analyst token.
5. Set collector environment variables locally, without putting real values in
   repository files, command history, screenshots, or shared logs:

   | Variable | Meaning |
   |---|---|
   | `SENTINEL_COLLECTOR_URL` | Complete HTTPS `/api/ingest/windows` endpoint |
   | `SENTINEL_COLLECTOR_ID` | Exact configured Windows connector ID |
   | `SENTINEL_COLLECTOR_TOKEN` | Collector-scoped token, not its reference name |
   | `SENTINEL_COLLECTOR_ALLOWED_NETWORKS` | Optional narrow internal HTTPS CIDRs |

6. Start a foreground collector from the repository root:

   ```powershell
   .\.venv\Scripts\python.exe collector\windows\collect.py `
     --spool C:\ProgramData\SentinelFlow\spool.sqlite3 `
     --channel ForwardedEvents --batch-size 100
   ```

   The URL must have a valid TLS certificate and no credential query string.
   Internal/private HTTPS endpoints require explicit CIDR allowlisting.
   Do not disable certificate verification. Loopback HTTP is only for the
   explicit `--local-test` harness.

The default channel is ForwardedEvents. `--channel` may be repeated for Security,
Microsoft-Windows-PowerShell/Operational, Microsoft-Windows-Sysmon/Operational,
System, and Application. Do not collect both direct and forwarded copies unless
their duplication is intentional and understood.

## Durability, exit status and recovery

An initial unbookmarked native query starts at the oldest available event in the
selected channel. Subsequent queries seek strictly after the durable bookmark.
The SQLite transaction inserts pending records and the last-read bookmark
together. Delivery deletes rows only after an exact acknowledgment from the
API, counting stored and identical-duplicate events. An HTTP 202 alone is not
sufficient if its count acknowledgment is malformed.

The collector retries transient failures with bounded backoff and honors
Retry-After. After ten attempts, or for a permanent failure such as 401/403,
rows become blocked. They stay on disk. Fix credentials/network/input first,
then use `--retry-blocked` to permit another attempt:

```powershell
.\.venv\Scripts\python.exe collector\windows\collect.py `
  --spool C:\ProgramData\SentinelFlow\spool.sqlite3 --retry-blocked --once
```

`--once` exits 0 only when no pending records remain, 2 when retained work is
pending/blocked, and 1 for controlled configuration/storage/collection failure.
A continuously running collector prints JSON with `pending`, `blocked` and
`status`; a pending result is not a delivery success.

Malformed JSON rows are retained and quarantined as `invalid_payload`; they
cannot crash the delivery loop or advance an acknowledgment. Repair/restore
from a known-good source rather than repeatedly retrying corrupted content.
The file and its immediate directory cannot be symlinks. POSIX spool files use
0600 permissions and an other-user-writable immediate directory is refused;
these checks do not configure Windows ACLs or encrypt telemetry.

The maximum spool is 100,000 rows. A full spool stops further reads and does not
advance its bookmark. Event reads have a bounded channel deadline. Spool leases
are renewed per channel, and an old process cannot release another process's
lease. Do not run multiple collectors against one spool intentionally.

Cleared/overwritten Windows logs can invalidate a bookmark. Strict seek raises
an explicit Windows error rather than skipping to an arbitrary point. Stop the
collector, preserve a backup of its spool/bookmarks, determine the lost-log
interval, and deliberately create a new spool only after deciding how to
reconcile existing pending events. There is no automatic destructive bookmark
reset. If a crash occurred after server acceptance, resend is safe for identical
events in the same connector; conflicting reused identities fail explicitly.

## Deterministic cross-platform harness

Use a private backend and a **demo-mode Windows connector**, with its own
`windows:ingest` credential. This still exercises authentication and the real
HTTP ingestion endpoint; no Windows domain is needed.

Set the collector variables locally as above, with a loopback HTTP URL and the
demo connector ID, then run:

```sh
.venv/bin/python collector/windows/collect.py \
  --spool data/collector-fixture-spool.sqlite3 \
  --fixture test-data/integrations/microsoft-windows.json \
  --local-test --once
```

The fixture contains 36 events and produces one alert for each bundled rule on
a clean, default-rule connector. Repeat with the same spool/connector: no extra
events or alerts should appear. A configured demo notification policy yields
seven real loopback receiver acknowledgments. The automated tests include
backend outage, restart, full spool, invalid acknowledgments, lease loss,
native API call/handle sequencing and authenticated end-to-end ingestion.

Full EVTX file parsing, Windows service installation, WEF/GPO deployment,
Sysmon installation, Security channel privilege management and production
retention are outside this collector. Do not present the portable harness as
a tested Windows deployment.
