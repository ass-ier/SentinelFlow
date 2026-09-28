# Executed validation evidence

These files are outputs of actual local commands, not example reports. The
comprehensive run shown in the delivered recording started on
**2026-09-28 at 00:03:56 UTC** and completed at **00:04:29 UTC**.

Environment: Python **3.13.7**, Node **20.19.2**, npm **11.4.2**, macOS
**26.6.2 arm64**. The live automated browser was Chromium **153.0.8010.12**.
The backend served the actual production-built SPA at `http://127.0.0.1:8765`.

## Executed checks

| Check | Actual result |
|---|---:|
| Full backend pytest suite | 268 passed; 0 failed; 0 skipped |
| Full frontend Vitest suite | 93 passed; 0 failed; 0 skipped |
| Unique automated test cases | 361 passed |
| Exact detection scenarios | 50 passed; 0 failed |
| Controlled benign scenarios | 14 / 14 passed |
| Standalone licensed Sigma compatibility | 4 passed; 2 rules compiled/imported/tested; 2 expected and observed detections |
| Saved fixture reproduction | 56 generated files matched byte-for-byte |
| Live functional/responsive browser checks | 33 passed; no unexpected HTTP or page errors |
| Live screenshots | 7 required captures plus the mobile dashboard |

Backend subsets overlap: parser **35**, detection **50**, negative **14**,
integration **90**, replay **17**, Sigma **34**, regression **68**, security
**49**. They are not additional unique tests. The independent scenario runners
and browser checks are also not added to the 361-test total.

`make validate` additionally passed the environment and pinned Python
dependency consistency checks, Ruff lint/format, strict MyPy, ESLint, Prettier,
TypeScript, the Vite production build, and browser-script syntax checks.
Commands, exit statuses and measured durations are preserved in
[validation.json](validation.json) and [validation.log](validation.log).

The same 361 tests and all 33 browser checks also passed in a completely fresh
clone, including real browser POSTs through a custom-port Vite proxy. That
separate installation and its exact requests are documented in
[fresh-clone verification](../fresh-clone.md). The clean installation exposed
dependency advisories before release; affected pins were updated and a new
npm audit reported zero known advisories. The before/after evidence and eight
offline regression guards are described in
[dependency maintenance](../dependency-maintenance.md).

Coverage.py reports **86.84% combined line/branch coverage**: **1,655 / 1,847
statements (89.60%)** and **444 / 570 branches (77.89%)**. Coverage is not a
measure of detection accuracy or an independent security audit.

## Actual benchmark

The included `mixed/benchmark_5600.jsonl` was evaluated three times. Each
iteration asserted the same authored contract:

| Measurement | Actual result |
|---|---:|
| Processed events per iteration | 5,600 |
| Active rules | 7 |
| Event-rule evaluations per iteration | 39,200 |
| Generated alerts per iteration | 700; 100 per bundled rule |
| Median detection duration | 0.441789 seconds |
| Median-derived throughput | 12,675.72 events/second |

The three measured durations were 0.452206, 0.440971 and 0.441789 seconds.
This is **single-process engine-only** execution: parsing, SQL persistence,
live append re-evaluation and UI delivery are excluded. It is not a production
capacity claim. The raw precision, platform, fixture checksum and scope are in
[benchmark.json](benchmark.json).

## Media

The final [MP4](../../recordings/sentinelflow-final-demo.mp4) is **356.16 seconds
(5:56.16)**, **1440 x 1000**, H.264/yuv420p at 25 fps, **9,730,783 bytes**.
It is a silent, continuously captured real browser walkthrough, not a slideshow.
The capture ran `make validate` and showed its actual final output fully within
the viewport. Sample frames were inspected for replay progressing from 12 to
22 events, benign PASS, PowerShell/DNS raw evidence, compiled Sigma JSON, and
the completed validation output.

The entire final file was decoded successfully. Its SHA-256 is
`aa444d5de6e407cd1977cd41690fc972e3e92f6fa13ec854942f91af01366df5`.
Exact chapter times, browser/encoder metadata and the capture receipt are in
[recording.json](../../recordings/recording.json); full decode output is in
[media-inspection.txt](../../recordings/media-inspection.txt).
The recorder's real console output is [recording-execution.log](recording-execution.log).

Screenshots were captured after comprehensive validation and the live checks
passed. Their paths and actual byte sizes are in
[browser-results.json](browser-results.json). Screenshots and recording use
separate clean demo runs, so their generated run/alert IDs intentionally differ.

## Raw reports and freshness

- [Exact detector report](detection-validation.json) and [human-readable output](detection-validation.txt).
- [Sigma compatibility report](sigma-validation.json).
- [Backend JUnit](backend-junit.xml), [frontend test report](frontend-tests.json),
  and [full coverage report](coverage.json).
- [Validation workflow](../testing.md), [recording procedure](../demo.md), and
  [dataset manifest](../../test-data/README.md).

The validated code/rules/fixtures/dependency fingerprint is
`f4f27c57afbd72864a29557fec670a2cb2865ff6f2bfe95a3e8af03808aeae5e`.
The validation, benchmark, browser and media receipts agree on this fingerprint.
It is independent of checkout path; documentation, generated reports and media
are excluded, while the recording scripts are included. Media has its own hash.
Project evidence marks changed source receipts stale rather than displaying
them as current success.

Re-running validation produces new timestamps and timings in `artifacts/`
without overwriting these historical delivery receipts. One upstream
Starlette/AnyIO deprecation warning was emitted; there were no test failures.
Docker configuration was inspected, but Docker build/runtime and a cross-platform
matrix were not executed. The npm advisory report is a dated registry check,
not an independent penetration test; no Python advisory database scan was run.
