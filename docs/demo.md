# Reproducible live demonstration

The walkthrough uses the running application, saved telemetry, real API
responses, and the actual comprehensive validation command. No detections,
progress counters, validation statuses, or terminal output are fabricated.

This original walkthrough and its saved media describe **private/local mode**.
The Vercel/Render public demo deliberately omits uploads, catalog/status changes,
arbitrary Sigma input and developer evidence endpoints. Its supported public
walkthrough and reset policy are in [deployment.md](deployment.md). Deployment
verification saves separate evidence under `artifacts/deployment/`; it does not
regenerate the final phase-one media.

## Start clean

```sh
make install
make validate
.venv/bin/python scripts/demo_reset.py --offline --seed
make dev
```

Open http://127.0.0.1:5173. For an already running server, use
`.venv/bin/python scripts/demo_reset.py --seed` instead of `--offline`.
Do not reset an active replay; cancel it first. The named demo database is the
only reset target. Generated fixtures are restored before the reset request.

## Walkthrough

| Approximate chapter | Real workflow |
|---|---|
| 00:00 Dashboard | Inspect the saved incident's event/active-alert counts, event-time chart, sources, rules and MITRE activity. |
| 00:30 Events | Filter by source or outcome, inspect a normalized record and its raw evidence. |
| 00:52 Brute-force replay | Select `auth-brute-force`, choose realtime or 10x, start replay, observe 25 events and one AUTH-001 alert. |
| 01:17 Detection | AUTH-001 has fired; inspect the replay's actual detection count. |
| 01:29 Alert evidence | Open the alert, examine source/user/host, exact event count, UTC time bounds, T1110 and triggering records; inspect its rule snapshot. |
| 02:08 Detection testing | Run the brute-force positive scenario, then `auth-normal-failures`; inspect actual PASS, expected/actual results and zero benign alerts. |
| 02:40 PowerShell | Replay `powershell-indicators`, inspect PROC-001 and the inert command-line evidence. Note the legitimate-use limitation. |
| 03:09 DNS | Replay `dns-long-label`, inspect DNS-001, label metrics and evidence; do not describe it as confirmed tunneling. |
| 03:38 Sigma | Load a pinned upstream sample, read author/license, compile it, import it disabled, and run its positive and benign dataset tests. |
| 04:37 Complete validation | The recorder launches `make validate`; the Project evidence page streams that actual subprocess log and displays its resulting receipt. |
| 05:22 Included repository | Inspect the real inventory of `test-data/`, `backend/tests/`, `scripts/`, and `docs/`, then open the manifest and engine documentation. |

Each new replay has its own run. Replaying the same input does not reuse a
prior validation's state. Alert/status changes made during the walkthrough
affect only the named local demo database.

## Screenshots

Required captures from the live, validated application:

- [Dashboard](../screenshots/dashboard.png)
- [Event explorer](../screenshots/events.png)
- [Alert details and evidence](../screenshots/alert-details.png)
- [Detection rules](../screenshots/detection-rules.png)
- [Detection validation](../screenshots/detection-validation.png)
- [Replay](../screenshots/replay.png)
- [Sigma compilation and validation](../screenshots/sigma-validation.png)
- [Additional mobile dashboard](../screenshots/mobile-dashboard.png)

These are live application captures, not frontend mock data or hand-rendered
dashboard images.
The capture script first scrolls real code panes into view so Chromium paints
their contents before a full-page screenshot; it does not replace UI data or
composite invented evidence into the image.

## Recording

The included [final recording](../recordings/sentinelflow-final-demo.mp4) is
**5 minutes 56.16 seconds**, 1440x1000 at 25 fps, silent H.264 MP4. It was
recorded from the verified live app and fully decoded successfully. Its
measured size is 9,730,783 bytes; exact metadata is saved alongside it.

The reproducible recording script uses a separate local Chromium browser
context, records its real rendered frames continuously, and transcodes the
result into `recordings/sentinelflow-final-demo.mp4`. It captures only the app,
not unrelated desktop windows. It is a silent, paced walkthrough; the chapter
guide above supplies narration. Exact timing and media inspection are recorded
alongside the finished video.

```sh
# Optional, isolated recording tool; the core application does not need it.
# Use the recorded explicit macOS lock when available, or solve the declared runtime:
CONDA_PKGS_DIRS="$PWD/.runtime/conda-pkgs" conda env create \
  --prefix .runtime/recording --file security/recording-runtime.yml
node scripts/record_demo.mjs --check-encoder

# Browser setup is a one-time optional tooling download, after package installation.
cd frontend
npx playwright install chromium
cd ..

# First validate, then verify the live app and capture screenshots.
make validate
node scripts/browser_verify.mjs

# Only after live verification passes:
node scripts/record_demo.mjs
```

The security phase replaces the unmaintained `ffmpeg-static` wrapper's FFmpeg 6.0
binary with an independently installed FFmpeg 9.0.2 recording tool. Set
`SENTINEL_FFMPEG` to its absolute executable path when using another installation.
`--check-encoder` checks its real version and H.264 encoder without resetting a
database or creating/replacing any media. The historical recording remains
unchanged; its historical encoder metadata is not rewritten.

Use `node scripts/browser_verify.mjs --no-capture` to rerun the complete private
browser workflow without replacing saved screenshots. It still resets the API
instance selected by `SENTINEL_API_URL`; use only an explicitly isolated demo.

The recording script invokes the actual `make validate` while the Project
evidence page displays its real log. It checks that the completed command output
is fully inside the recorded viewport. The final MP4 is fully decoded to verify
the container, codec and measured 5-10 minute duration, rather than relying on
the filename. Exact metadata and chapter times are saved in
[recording.json](../recordings/recording.json); the decoder output is in
[media-inspection.txt](../recordings/media-inspection.txt).

For the single-server production preview used for the delivered media:

```sh
SENTINEL_UI_URL=http://127.0.0.1:8765 node scripts/browser_verify.mjs
SENTINEL_UI_URL=http://127.0.0.1:8765 node scripts/record_demo.mjs
```

For custom development ports, set both URLs explicitly, for example
`SENTINEL_API_URL=http://127.0.0.1:8766 SENTINEL_UI_URL=http://127.0.0.1:5174`.
The scripts reset the demo database at that API URL; do not point them at an
unrelated or production instance.

For a manual rerun, follow the same chapter table in a browser-window-only
recording tool at 1440x1000, allow approximately 5-10 minutes, preserve the real
terminal output, and save the output under `recordings/`. Never replace the
live application with a slideshow.
