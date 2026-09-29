# Microsoft integration phase: actual execution evidence

These are copies of actual local results for the Microsoft/Windows connector
and outbound notification implementation. They are not example outputs,
Microsoft tenant receipts, or replacements for the original recording.

Final executable source fingerprint:

`9db953ffd9fa343a3219d36051910f93151d32682381440091614d72823f14a2`

The [implementation report](../../integrations-implementation-report.md)
explains exact results, architecture, operation and remaining live-verification
limits. The [evidence manifest](manifest.json) records file byte sizes and hashes.

| Evidence | File |
|---|---|
| Pre-change passing baseline | [baseline-validation.json](baseline-validation.json) |
| Full final validation receipt/log | [validation.json](validation.json), [validation.log](validation.log) |
| Backend cases and coverage | [backend-junit.xml](backend-junit.xml), [coverage.json](coverage.json) |
| Frontend cases | [frontend-tests.json](frontend-tests.json) |
| Exact detection scenarios | [detection-validation.json](detection-validation.json), [detection-validation.txt](detection-validation.txt) |
| Licensed Sigma compatibility | [sigma-validation.json](sigma-validation.json) |
| Actual engine benchmark | [benchmark.json](benchmark.json) |
| Actual local provider-to-receiver workflows | [integrations-validation.json](integrations-validation.json) |
| Original analyst workflow browser regression | [core-browser.json](core-browser.json) |
| New administration/investigation browser workflows | [integration-browser.json](integration-browser.json) |
| Native split-origin production rehearsal | [native-deployment.json](native-deployment.json), [public-native-browser.json](public-native-browser.json) |
| Linux/amd64 Docker production rehearsal | [docker-deployment.json](docker-deployment.json), [public-docker-browser.json](public-docker-browser.json) |
| Private HTTP integrations inside the offline container | [docker-private-integrations.json](docker-private-integrations.json) |
| Actual collector CLI/HTTP outage and recovery | [collector-http.json](collector-http.json) |

The baseline intentionally has the previous deployment fingerprint, not the
final integration fingerprint. Browser, standalone scenario and smoke checks
supplement the 668 unique backend/frontend cases; they are not added to that
test total. Backend marker categories overlap.

New, real screenshots captured after successful validation and browser checks:

- [Integration management, desktop](integrations-desktop.png)
- [Integration management, mobile](integrations-mobile.png)
- [Notification destinations and delivery history](notifications-desktop.png)
- [Alert with provider provenance and delivered notification](integration-alert.png)

The original eight files in `screenshots/` and
`recordings/sentinelflow-final-demo.mp4` were not regenerated. All original PNG
bytes match their committed objects. The MP4 retains SHA-256
`aa444d5de6e407cd1977cd41690fc972e3e92f6fa13ec854942f91af01366df5`.
It demonstrates the original core application, not these new integrations.

No live Azure/Graph authentication, real Windows domain collection, Power
Automate flow, Teams delivery, external webhook or hosted deployment was tested.
Local HTTP responses and database history are genuine; their scope is explicitly
mock/offline.
