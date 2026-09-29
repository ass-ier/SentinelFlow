# Defensive parser/security corpus

These are inert, locally authored synthetic security-test inputs under the
project's MIT license. They contain no real credentials, personal information,
external targets or executable telemetry. Tests derive bounded encoding,
nesting, truncation and type mutations deterministically.

`entity.xml` declares one harmless internal entity. It must be rejected, including
when its ASCII characters are interleaved with NULs to represent UTF-16/32 code
units. The pre-hardening byte-pattern guard incorrectly permitted that encoding.
No test needs to resolve an external entity or read an unrelated filesystem path.

Malformed-input tests belong under `backend/tests/security/`; they do not add
scenarios to the existing 50 detection datasets or alter expected detections.

`api-fuzz.json` permanently retains 16 invalid-shape mutations and seven malformed
byte payloads (hex encoded), seed 7341, nine API paths, and the expected zero
stored events/alerts/runs. This produces 207 bounded local requests in 72 pytest
cases. Reproduce with `python scripts/generate_security_data.py`; verify without
writing with `--check`. Input bytes include invalid UTF-8, non-finite numbers,
excessive integer digits, and excessive nesting. They are never sent externally.

The additional parameterized cases in the security tests use this synthetic
corpus or inline inert HTTP framing, credential-reference and path strings.
TLS tests generate their own short-lived local certificate and private key in
pytest's temporary directory; no private key is retained in the repository.
External-entity tests reference only a test-owned file and the reserved `.invalid`
namespace, with DNS forbidden. Address-policy checks do not connect to those
addresses; actual HTTP/TLS receivers bind only loopback.
