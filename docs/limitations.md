# Honest limits

SentinelFlow is a functional local detection-engineering portfolio application.
It is not a production SIEM, a managed SOC, an endpoint agent, or a guarantee of
attack detection.

- Included rules detect specified indicators and thresholds, not attacker
  intent or proof of compromise. MITRE labels describe those indicators only.
- Synthetic positives and negatives are controlled scenarios, not an enterprise
  false-positive or recall study. The adapted public sample tests parser
  interoperability, not public attack coverage.
- No full EVTX, PCAP, general syslog dialect support, or automated security
  platform connectors. Only documented Windows event IDs are normalized.
- Sigma support is deliberately restricted. Unsupported conditions, fields,
  modifiers and sources fail explicitly rather than approximating meaning.
- Private/local access or an explicitly restricted, shared synthetic public
  demo; no SSO, RBAC, tenants, application TLS endpoint, immutable audit storage,
  backup system, enterprise retention policy, or schema migration framework.
- Public mode disables arbitrary inputs, rule/status changes and developer
  endpoints. All visitors share replay/cancel state. Its 20-run history cap and
  concurrency bounds are not per-client rate limiting or DDoS protection.
- SQLite persistence on Render requires a paid disk. Free/ephemeral storage can
  lose history and reseed on restart/deploy. Local restart/volume evidence does
  not establish hosted persistence or high availability.
- Whole-run re-evaluation on each append is intentionally deterministic but
  does not scale like incremental stream processing. The benchmark excludes
  SQL and append re-evaluation.
- Late appends are rejected, not silently accepted or retroactively reconciled.
  Full chronological replay is the supported remedy.
- Suppression correlates an episode; its total evidence can exceed the initial
  threshold window. Workflow status does not alter that engine behavior.
- DNS entropy is a simple character-frequency heuristic, and `base_domain` is
  only the last two labels, not a public-suffix implementation.
- Network exceptions are explicit strings/patterns, not a full learned baseline
  or general IPv4/IPv6 CIDR policy language.
- Public raw evidence is the disclosed adapted export. Other JSON evidence
  preserves original values, not original byte offsets/whitespace.
- External-source downloads and initial dependency/browser setup require the
  network. Normal operation and validation after installation do not.
- Original delivery evidence is from macOS arm64. The separate deployment
  report records subsequent native, Linux/amd64 container and fresh-clone
  execution; it is not a full OS/CPU/browser matrix or a hosted deployment.
  Security tests and the bounded current-tree secret search are not an
  independent penetration test. npm audit is dated; no Python advisory or
  container base-image vulnerability scan is implied.

The committed execution receipts state what actually ran. Re-run validation
after any rule, dependency, fixture, or code change. A stale receipt is not
evidence that the changed version passed.

The original screenshots and recording remain historical evidence for the
original delivery commit. They were not regenerated to imply that deployment
changes or external hosting were recorded. See [deployment-readiness.md](deployment-readiness.md)
for the current, separately identified evidence and outstanding owner actions.
