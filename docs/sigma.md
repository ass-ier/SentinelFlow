# Sigma subset and compatibility evidence

This is a restricted translator, not full Sigma compatibility, a pySigma
backend, or a production correlation translator. Import rejects unsupported
semantics with `unsupported_sigma` and an explanatory 422.

## Supported

- Required metadata: `title`, UUID `id`, `description`, `status`, `logsource`,
  `detection`, `level`, `tags`. Supported statuses are stable, test, experimental,
  and deprecated. Additional author/date/modified/references/falsepositives,
  license/related/regression-path metadata is retained in original YAML.
- `logsource` contains exactly `product` (`windows` or `linux`) and `category`
  (`process_creation`, `network_connection`, `dns_query`). Both product and
  action/category become actual predicates; they are never discarded.
- Named nonempty field-map selectors (AND between fields) or lists of field
  maps (OR). Scalar lists mean OR unless `|all` is present.
- Equality, `|contains`, `|startswith`, `|endswith`, and `|all` on lists.
  Unescaped `*` and `?` in string values are translated to bounded,
  case-insensitive regex with the proper anchoring.
- Conditions: named selectors, `and`, `or`, `not`, parentheses, `1 of pattern`,
  `all of pattern`, and `1/all of them`. Precedence is NOT, AND, OR.
- Level-to-severity mapping, `attack.tNNNN[.NNN]` technique tags, exact original
  YAML, author, upstream ID, source/license URLs, status, and logsource.

| Sigma field | Normalized field |
|---|---|
| `Image` | `process.executable` (full path, **not basename**) |
| `ParentImage` | `process.parent.executable` (full path) |
| `CommandLine` | `process.command_line` |
| `User`, `Computer` | `user.name`, `host.name` |
| `TargetFilename` | `file.path` |
| `SourceIp`, `SourcePort` | `source.ip`, `source.port` |
| `DestinationIp`, `DestinationPort` | `destination.ip`, `destination.port` |
| `QueryName` | `dns.query` |
| `EventID` | `metadata.windows_event_id` |

Input telemetry must include `metadata.product` for Sigma logsource matching.
Windows normalization supplies `windows`. Synthetic process fixtures explicitly
provide their platform and full paths. Missing fields fail their predicates;
an explicit NOT still behaves as ordinary Boolean negation.

## Explicitly unsupported

Correlations/aggregations/timeframes, multiple condition lists, arbitrary
logsource services, keyword-only selections, unknown fields, field references,
`|re`, `|base64`, `|windash`, `|exists`, pipeline transformations, more than one
string modifier, nulls/objects as field values, numeric quantifiers other than
`1`, and escaped wildcard values are rejected. Selectors, tokens, nesting,
pattern size, YAML size, and regex runtime are bounded.

## Included genuine upstream rules

Source revision:
`SigmaHQ/sigma@07ec293a51695cb1131a2e05260247872b31e1e1`.
Obtained 2026-09-27; original bytes are stored under `test-data/sigma/rules/`.

| Rule | Author | Severity | Compatibility checks |
|---|---|---|---|
| PowerShell Download and Execution Cradles (`85b0b087-eddf-4a2b-b033-d771fa2b9775`) | Florian Roth (Nextron Systems) | High | `all of selection_*`, two list-valued contains selections, positive and negative telemetry |
| Suspicious Execution of Powershell with Base64 (`fb843269-508c-4b76-8b8d-88679db22ce7`) | frack113 | Medium | Image suffixes, encoded switches, `selection and not 1 of filter_*`, Encoding and full Azure ParentImage exclusions |

Unquoted upstream dates are kept as strings by the safe YAML loader. Neither
rule is edited to fit the importer. The tests compare real compiled-rule
outputs, exact severity and evidence, and author attribution. API integration
imports each definition, ingests telemetry, retrieves its alert and evidence,
and confirms attribution survives persistence.

The source [Detection Rule License 1.1](../test-data/sigma/LICENSE.Detection.Rules.md)
requires author attribution on messages based on matches. SentinelFlow carries
that author into the alert API, evidence view, and pinned rule snapshot.
The rules are **not MIT-licensed**. Exact source/license URLs, revision, dates,
and SHA-256 hashes are in `test-data/sigma/provenance.json`.

```sh
.venv/bin/python scripts/validate_sigma.py
.venv/bin/python -m pytest backend/tests/integration/test_sigma.py
```

Compilation does not persist or enable a rule. Import defaults to disabled.
Testing is isolated and requires a stated expected count for a custom/Sigma
definition; mismatched expectations fail rather than echoing observed results
as their own expectation. Legitimate installers are a documented upstream
false-positive possibility.
