# Detection engine and policy semantics

Rules in `rules/*.yml` are data, not Python detection branches. An analyst can
import another valid YAML rule through `POST /rules` without changing Python.
Rule/schema validation rejects unknown fields/operators and malformed expressions.

```yaml
id: EXAMPLE-001
name: Repeated failed authentication
description: A threshold indicator for analyst investigation.
severity: high
enabled: true
conditions:
  - field: event.category
    operator: equals
    value: authentication
  - field: event.outcome
    operator: equals
    value: failure
threshold: {count: 10, window_seconds: 300}
group_by: [source.ip]
suppression_seconds: 600
mitre_attack: [T1110]
```

## Predicates and Boolean expressions

`equals`, `not_equals`, `contains`, `starts_with`, `ends_with`, `regex`,
`greater_than`, `less_than`, and `in` are supported. A list of conditions is
implicit AND. Nested expressions use `all`, `any`, and `not`. Empty Boolean
groups, unknown normalized field paths, null predicate values, and ambiguous
leaf/group combinations are rejected. Bounded `metadata.*` paths are supported.

String comparisons are case-insensitive by default. A leaf may set
`case_sensitive: true` for non-regex operators. Equality and membership do not
coerce types (`true` is not `1`); numeric inequalities accept actual numbers,
not numeric-looking strings or booleans. A missing/null field does not satisfy
any leaf predicate, including `not_equals`. Explicit Boolean NOT negates its
child result, so `not` around a missing-field comparison is true.

Regex is case-insensitive, capped at 256 pattern characters and 16,384 input
characters. Backreferences, lookarounds, recursion, and certain repeat syntax
are rejected. Remaining patterns receive a **5 ms per-search timeout**.
Timeouts fail the operation visibly and roll back ingestion; they are not
treated as non-matches. These bounds reduce risk, not a claim of universal
regex safety or a substitute for authenticated deployment.

## Event time, groups, thresholds

1. Deduplicate by ID, rejecting conflicting content; sort by `(timestamp, ID)`.
2. Evaluate only the run's enabled, pinned rule definitions.
3. Evaluate predicates and partition matching events by `group_by`.
4. Keep matching candidates whose event time is at least
   `current_event_time - window_seconds` (the lower boundary is inclusive).
5. When the group reaches `count`, create an episode with exactly those
   candidates as initial evidence. Missing group values skip correlation and
   increment `missing_group_matches`; unrelated missing entities are not merged.

Time windows are bounded to 86,400 seconds, thresholds to 10,000 events, groups
to four fields. String grouping is case-sensitive; string predicate matching
is case-insensitive unless overridden.

## Suppression / deduplication

Suppression is per rule, branch, and group. It begins at the **trigger time**,
not the first candidate or ingestion clock. Matching events strictly before
`trigger_time + suppression_seconds` are appended to the existing episode's
evidence instead of generating additional alerts. The interval does not slide.
An event exactly at expiry starts a fresh candidate window.

Suppressed matches are not recycled into later episodes; evidence cannot be
counted twice within the same branch/group. Independent DNS branches may
legitimately reference the same event. Zero suppression allows a new alert for
every qualifying event/window.

`event_count`, first/last seen, and entity lists describe the entire correlated
episode, including suppressed follow-ups, which can span longer than the
original trigger window. `triggered_at` identifies when the threshold was met.
Analyst status changes do not automatically reopen an episode or discard its
subsequent evidence.

An incoming batch may be unordered; it is sorted first. An append older than
the already committed `(timestamp, ID)` watermark is rejected atomically with
409. Use a new complete replay for late telemetry. Appending a lower ID at the
same timestamp is also late, preserving deterministic tie ordering.

## Bundled policies and controlled negatives

| Rule | Group / threshold | Suppression | Negative policy and limits |
|---|---|---|---|
| AUTH-001 | Source IP; 10 failures / 300s | 600s | Three ordinary failures stay below threshold. Low-rate distributed sources are not aggregated. Multiple users from one source are covered. |
| AUTH-002 | Host; 3 lockouts / 300s | 600s | Two lockouts do not cross threshold; stale service credentials can still alert. |
| PROC-001 | Host + actor; one matching PowerShell indicator | 300s | Get-Service/Get-Process/unencoded administration stays negative. A legitimate download deliberately still alerts. |
| IAM-001 | Host + actor; privileged membership/identity action | 300s | Ordinary helpdesk groups are negative. Privileged maintenance requires **all three** of `svc_identity`, `id-admin-01`, and `CHG-` plus 4-10 digits. Wrong-host maintenance still alerts. |
| PROC-002 | Host + actor; configured process pattern | 300s | Normal explorer-to-cmd and routine scripts stay negative. Office automation can legitimately match. |
| DNS-001 | Source IP; independent configurable branches | 300s | Normal names and below-threshold bursts stay negative. This is not a learned enterprise baseline or a DNS-tunneling verdict. |
| NET-001 | Source IP + destination IP; 3 matches / 120s | 300s | Ports 1337/4444/9001 are suspicious here. Explicit IPv4 private ranges, loopback `::1`, and `203.0.113.10` are excluded. Normal HTTPS stays negative; no complete network baseline is claimed. |

DNS branches are `long-label` (>40 characters, one query), `high-entropy`
(maximum label length 26-40 and maximum per-label entropy >4.1, two queries
within 60s), and `query-frequency` (20 queries within 60s).
Large benign bursts and CDN/service-discovery labels can match. These
heuristics do **not** establish DNS tunneling.

All thresholds, exceptions, severity, and ATT&CK IDs are visible in YAML.
No rule checks a fixture filename, event ID prefix, synthetic flag, or expected
test name. Maintenance context is telemetry policy, not an authorization
assertion: an untrusted sender can forge those fields.

## Enablement and testing

Toggle state applies to the next run. Existing runs pin their definitions, so
a mid-replay toggle cannot silently alter their results. Rule detail tests
explicitly test the selected definition even when disabled, without changing
operational state. Bundled validation tests shipped definitions; `scope=current`
compares current enablement/definitions with the same authored expectations
and can correctly fail. Unknown custom-rule expectations display **observed**,
not PASS, unless the analyst supplies an expected count.

ATT&CK labels describe the implemented indicator context, not prevention,
confirmed attacker actions, or enterprise coverage.
