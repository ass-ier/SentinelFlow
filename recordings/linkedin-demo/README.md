# SentinelFlow LinkedIn portfolio trailer

**Final video:** [sentinelflow-linkedin-demo.mp4](../sentinelflow-linkedin-demo.mp4)

| Property | Delivered |
|---|---|
| Duration | 100.700 seconds (1 minute 40.7 seconds) |
| Resolution / aspect | Native 1920 x 1080, 16:9 |
| Codec / frame rate | H.264 High profile, yuv420p, 30 fps |
| File size | 17,596,333 bytes |
| Audio | Silent, with readable on-screen titles for muted autoplay |
| Transitions | 300 ms cross-dissolves between real browser clips |
| SHA-256 | `183447c7d90c2e8a48fbf26f7bae02e8a78098c0cf04631da6acbe887f813114` |

This is edited **live application video**, not a slideshow or dashboard mockup.
The browser made real requests to an isolated SentinelFlow backend. Captions
were added after capture; no application data or results were replaced.

## Timestamped sections

Starts include the short overlap with the preceding cross-dissolve.

| Start | Section | One demonstrated feature |
|---|---|---|
| 00:00.0 | Intro / dashboard | Real metrics and telemetry activity, with the SentinelFlow introduction |
| 00:05.7 | Telemetry ingestion | Upload and ingest the existing 25-event JSONL fixture; show its stored events |
| 00:15.4 | Detection engineering | AUTH-001 only: high severity, 10-event/300-second threshold, source-IP grouping and T1110 |
| 00:25.1 | Detection in action | Replay the same deterministic fixture at the application's real 10x setting; generate one AUTH-001 alert |
| 00:36.8 | Alert investigation | Investigate that replay alert and save its status as investigating |
| 00:46.5 | Evidence | Expand exactly one underlying event from that same alert |
| 00:56.2 | MITRE ATT&CK | Show the same alert's T1110 / Brute Force mapping, without external navigation |
| 01:02.9 | Search | Search for `gateway-01` in the same replay run; receive 25 actual matching events |
| 01:10.6 | Microsoft integration | Show the implemented Graph / Entra connector configuration, explicitly not live-tested |
| 01:19.3 | Notifications | Show one Power Automate-compatible destination and its disabled AUTH-001 routing configuration |
| 01:28.0 | Security engineering | Show the current validation result: 946 automated tests, 50 detection scenarios and 127 browser checks |
| 01:35.7 | Finale | Return to the real dashboard; hold the product name and FastAPI / React / TypeScript / MITRE stack |
| 01:40.7 | End | Final MP4 ends |

The initial import and subsequent replay use the **same saved fixture** in
separate isolated runs, as the application actually implements them. All
investigation, evidence, MITRE and search sections then follow the single alert
created by the replay. The final dashboard truthfully includes the seed,
import and replay; its totals are not fabricated.

## Privacy and accuracy

No secrets or credentials were exposed in the delivered recording.

- Only the Chromium application viewport was recorded: no desktop, terminal,
  browser chrome, bookmarks, developer tools or operating-system notifications.
- The recording backend bound only to a new loopback port, used a fresh private
  synthetic database, ignored `.env`, and had no owner/tenant credentials
  configured. Existing services and databases were not used for filming.
- Microsoft and notification live-enable flags remained false. The displayed
  connector and destination used disabled demo configurations. Tenant/client
  ID and secret-entry fields were absent from the captured forms.
- No live Microsoft tenant, Graph tenant, Windows domain, Power Automate flow,
  Teams channel or external webhook was contacted or represented as tested.
- **Zero notifications were sent.** No destination or policy was enabled.
- Browser requests outside the recording backend were blocked; none occurred.
- The visible text was checked for credential-like strings and local execution
  paths. Off-screen logs and closed disclosure contents were not treated as
  painted text. Actual exported frames were also inspected.
- Shown `10.10.*` addresses, `gateway-01`, `analyst01` and January event times
  belong to the repository's deterministic synthetic fixture, not real private
  infrastructure or personal telemetry.
- The rule's structured conditions and raw telemetry are application data,
  not source-code or terminal demonstrations.

The displayed validation totals were checked against the complete successful
release receipt and the current application source fingerprint:

`2485344225394ffafaaa9feba73eac583d02e704e3d26747d38fe9abcbe22ea6`

The 946 tests comprise 801 backend and 145 frontend cases. Detection scenarios
and browser checks are separate counts. No full test suite was run on camera,
and no claim of being vulnerability-free or production-SIEM-ready was added.
The new recording helpers are media tooling, not additional cases counted in
that earlier application test result.

## Exact recording process

The actual commands were run from the repository root:

```sh
export PATH="$PWD/.runtime/node-v24.21.0-darwin-arm64/bin:$PATH"
export SENTINELFLOW_PYTHON="$PWD/.runtime/venv/bin/python"

node recordings/linkedin-demo/capture.mjs \
  --output artifacts/linkedin-trailer/final-capture

.runtime/venv/bin/python recordings/linkedin-demo/render.py \
  --capture artifacts/linkedin-trailer/final-capture \
  --output recordings/sentinelflow-linkedin-demo.mp4
```

For a repeat recording, choose **new** capture-directory and MP4 names.
The scripts refuse to overwrite existing recordings. Application dependencies,
the pinned Playwright browser and the documented FFmpeg 9.0.2 recording
environment must already be installed; see [the project demo guide](../../docs/demo.md).
`SENTINEL_FFMPEG` and `SENTINEL_FFPROBE` can name trusted local executables.

`capture.mjs` starts and verifies its own backend, seeds actual fixture data,
prepares disabled demonstration configurations, then performs twelve actual
browser scenes. The viewport is 1920 x 1080, with presentation zoom of 120%
(135% for the validation panel so its terminal log remains below the viewport).
Each scene is a real WebM browser recording, not a screenshot.

`render.py` trims setup/navigation lead-ins, normalizes to 30 fps, adds
original ASS text overlays, and joins the video clips with 300 ms dissolves.
It encodes H.264 with CRF 18 and fast-start metadata, checks the requested
duration/resolution, and decodes the entire resulting MP4.

The raw capture receipt, raw WebMs, exact encoder argument arrays, caption
tracks, ffprobe report and decoder log remain under:

`artifacts/linkedin-trailer/final-capture/`

The portable [verification receipt](verification.json) binds the delivered
video, application fingerprint, media scripts and observed workflow results.
No video or project content was uploaded, pushed or published externally.

## Problems encountered and resolution

One rehearsal stopped because the first text-visibility auditor included
off-screen, scroll-clipped validation-log text and closed disclosure contents.
The actual screenshot did not display that log. The auditor was corrected to
respect element visibility, closed disclosures, viewport bounds and ancestor
scroll clipping. The final twelve-scene capture passed without browser errors,
failed HTTP responses or privacy-check failures.

Media-script formatting and local-subprocess lint findings were resolved.
The caption output was compared byte-for-byte with the rendered tracks after
those non-visual edits; the delivered video did not require regeneration.

The browser automation tool blocked direct `file://` navigation, so the app
preview uses a loopback-only server serving just this MP4. Actual browser
playback was confirmed at 1920 x 1080 with a 100.700-second duration, advancing
playback and no media error. The file itself is permanent and can be opened
directly in a local video player; the preview server remains session-attached.

At the final read-only preservation check, the legacy service on port 18881
responded successfully; the older port-8765 endpoint was not reachable.
Neither endpoint was stopped, reconfigured or restarted by the recording
workflow. Filming used separate temporary ports and a separate database.
The unavailable legacy endpoint did not affect the verified video.

There are no outstanding recording blockers. Silence is intentional for
LinkedIn autoplay; no unlicensed soundtrack or fabricated voiceover was used.
The original eight screenshots, original six-minute MP4, release evidence and
application source were preserved. Unrelated services were left untouched.
