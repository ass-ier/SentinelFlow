import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
  mkdir,
  readFile,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import ffmpeg from "../frontend/node_modules/ffmpeg-static/index.js";
import {
  api,
  assert,
  compileSigma,
  contextFor,
  expect,
  fingerprint,
  go,
  launch,
  loadSigma,
  openAlert,
  replay,
  requireValidation,
  root,
  testDetection,
  testSigma,
  uiResponse,
} from "./browser_workflows.mjs";

const validated = await requireValidation();
const browserReceipt = JSON.parse(
  await readFile(path.join(root, "artifacts/browser-results.json"), "utf8"),
);
assert.equal(
  browserReceipt.status,
  "passed",
  "Live browser verification must pass before recording",
);
assert.equal(
  browserReceipt.source_fingerprint,
  fingerprint(),
  "Browser verification is stale",
);
for (const name of [
  "dashboard",
  "events",
  "alert-details",
  "detection-rules",
  "detection-validation",
  "replay",
  "sigma-validation",
]) {
  assert.ok(
    (await stat(path.join(root, `screenshots/${name}.png`))).size > 1000,
  );
}
assert.ok(ffmpeg, "The pinned ffmpeg-static encoder is missing");
await access(ffmpeg);
const destination = path.join(root, "recordings");
await mkdir(destination, { recursive: true });
await api("/admin/demo-reset", { confirmation: "RESET DEMO", seed: true });
const browser = await launch();
const recordingBrowserVersion = browser.version();
const context = await contextFor(browser, {
  recordVideo: {
    dir: destination,
    size: { width: 1440, height: 1000 },
  },
});
const page = await context.newPage();
const video = page.video();
assert.ok(video, "The browser did not initialize real video capture");
const started = Date.now();
const chapters = [];
const pageErrors = [];
page.on("pageerror", (error) => pageErrors.push(error.message));
const chapter = (title, details = {}) => {
  const item = { title, at_seconds: (Date.now() - started) / 1000, ...details };
  chapters.push(item);
  console.log(`LIVE ${item.at_seconds.toFixed(1)}s ${title}`);
};
const holdUntil = async (seconds) =>
  page.waitForTimeout(Math.max(0, seconds * 1000 - (Date.now() - started)));
const scrollTo = async (locator) => {
  await locator.scrollIntoViewIfNeeded();
  await page.waitForTimeout(500);
};
let validationProcess;
let complete = false;

try {
  chapter("Dashboard: real event and detection statistics");
  await go(page, "/", "Overview");
  await expect(page.locator(".metrics-strip dd").first()).toHaveText("56");
  await holdUntil(12);
  await scrollTo(
    page.getByRole("heading", { name: "Recent alerts", exact: true }),
  );
  await holdUntil(22);
  await page.evaluate(() => window.scrollTo(0, 0));
  await holdUntil(30);

  chapter("Event explorer and original raw evidence");
  await go(page, "/events", "Event explorer");
  await page.getByRole("button", { name: "More filters", exact: true }).click();
  await page.getByLabel("Outcome", { exact: true }).selectOption("failure");
  await page.getByRole("button", { name: "Search", exact: true }).click();
  await page
    .getByRole("button", { name: /^Show raw event / })
    .first()
    .click();
  await scrollTo(page.locator(".evidence-row"));
  await holdUntil(52);

  chapter("Brute-force replay: real-time arrival of 25 events");
  const brute = await replay(page, "auth-brute-force", "realtime", true);
  assert.equal(brute.alerts_created, 1);
  chapter("AUTH-001 fired", {
    run_id: brute.id,
    events: brute.processed_events,
    alerts: brute.alerts_created,
  });
  await scrollTo(
    page.getByRole("heading", {
      name: "Detections in this replay",
      exact: true,
    }),
  );
  await holdUntil(89);

  const bruteAlert = await openAlert(page, brute.id, "AUTH-001");
  chapter(
    "Alert investigation: source, user, UTC time, MITRE and 25 evidence records",
    { alert_id: bruteAlert.id },
  );
  await page.evaluate(() => window.scrollTo(0, 0));
  await holdUntil(102);
  await page.getByLabel("Set alert status").selectOption("investigating");
  await page
    .getByLabel("Investigation note (optional)")
    .fill("Reviewed the included synthetic replay and its linked evidence.");
  await uiResponse(
    page,
    `/alerts/${bruteAlert.id}/status`,
    () =>
      page.getByRole("button", { name: "Save status", exact: true }).click(),
    { method: "PATCH" },
  );
  await scrollTo(
    page.getByLabel(`Raw event ${bruteAlert.evidence[0].event.id}`, {
      exact: true,
    }),
  );
  await holdUntil(116);
  await scrollTo(
    page.getByRole("heading", { name: "Pinned rule snapshot", exact: true }),
  );
  await holdUntil(128);

  chapter("Detection testing: exact positive and benign assertions");
  const positive = await testDetection(page, "auth-brute-force");
  assert.equal(positive.results[0].actual[0].event_count, 25);
  await scrollTo(
    page.getByRole("heading", { name: "Validation results", exact: true }),
  );
  await holdUntil(145);
  const negative = await testDetection(page, "auth-normal-failures");
  assert.equal(negative.results[0].actual.length, 0);
  await scrollTo(
    page.getByRole("heading", { name: "Validation results", exact: true }),
  );
  await holdUntil(160);

  chapter("PowerShell indicators, not proof of compromise");
  const powershell = await replay(page, "powershell-indicators", "10x");
  const psAlert = await openAlert(page, powershell.id, "PROC-001");
  assert.equal(psAlert.event_count, 5);
  await page.evaluate(() => window.scrollTo(0, 0));
  await holdUntil(174);
  await scrollTo(page.getByLabel("Process command line — inert text").first());
  await holdUntil(189);

  chapter("DNS anomaly: actual long-label evidence");
  const dns = await replay(page, "dns-long-label", "realtime");
  const dnsAlert = await openAlert(page, dns.id, "DNS-001");
  assert.equal(dnsAlert.branch, "long-label");
  await page.evaluate(() => window.scrollTo(0, 0));
  await holdUntil(203);
  await scrollTo(
    page.getByLabel(`Raw event ${dnsAlert.evidence[0].event.id}`, {
      exact: true,
    }),
  );
  await holdUntil(218);

  chapter(
    "Sigma: unchanged upstream source, compilation, import and real tests",
  );
  const sample = await loadSigma(page);
  await holdUntil(227);
  const compiled = await compileSigma(page);
  await scrollTo(
    page.getByRole("heading", { name: "Compilation result", exact: true }),
  );
  await holdUntil(235);
  await scrollTo(page.getByLabel("Compiled rule JSON", { exact: true }));
  await holdUntil(240);
  await uiResponse(page, "/sigma/import", () =>
    page
      .getByRole("button", { name: "Import disabled rule", exact: true })
      .click(),
  );
  await scrollTo(
    page.getByRole("heading", { name: "Imported rule", exact: true }),
  );
  await holdUntil(250);
  await testSigma(page);
  await scrollTo(
    page.getByRole("heading", { name: "Validation results", exact: true }),
  );
  await holdUntil(264);
  await testSigma(page, true);
  await scrollTo(
    page.getByRole("heading", { name: "Validation results", exact: true }),
  );
  assert.equal(compiled.rule.provenance.author, sample.author);
  await holdUntil(277);

  chapter("Execute make validate and show its real output");
  await go(page, "/evidence", "Project evidence");
  validationProcess = spawn("make", ["validate"], {
    cwd: root,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  validationProcess.stdout.on("data", (chunk) => process.stdout.write(chunk));
  validationProcess.stderr.on("data", (chunk) => process.stderr.write(chunk));
  const validationDone = new Promise((resolve, reject) => {
    validationProcess.on("error", reject);
    validationProcess.on("exit", (code) =>
      code === 0
        ? resolve()
        : reject(new Error(`make validate exited ${code}`)),
    );
  });
  await scrollTo(
    page.getByRole("heading", { name: "Live validation log", exact: true }),
  );
  await expect(
    page.getByLabel("Actual validation command output"),
  ).toContainText("Backend", { timeout: 45_000 });
  await validationDone;
  await expect(
    page.getByLabel("Actual validation command output"),
  ).toContainText("STATUS: VALIDATED", { timeout: 20_000 });
  const terminal = page.getByLabel("Actual validation command output");
  await scrollTo(terminal);
  await expect(terminal).toBeInViewport({ ratio: 1 });
  await page
    .getByLabel("Actual validation command output")
    .evaluate((element) => {
      element.scrollTop = element.scrollHeight;
    });
  await holdUntil(322);
  const finalValidation = await requireValidation();
  chapter("Actual validation completed", {
    backend_tests: finalValidation.backend.passed,
    frontend_tests: finalValidation.frontend.passed,
    detection_scenarios: finalValidation.detections.passed,
  });

  chapter("Included test data, tests, scripts and documentation");
  await scrollTo(
    page.getByRole("heading", { name: "Included file inventory", exact: true }),
  );
  await page.getByLabel("Filter file paths").fill("test-data/");
  await page.waitForTimeout(3000);
  await page.getByLabel("Filter file paths").fill("backend/tests/");
  await page.waitForTimeout(3000);
  await page.getByLabel("Filter file paths").fill("scripts/");
  await page.waitForTimeout(3000);
  await page.getByLabel("Filter file paths").fill("docs/");
  await page.waitForTimeout(3000);
  await page
    .getByLabel("Document", { exact: true })
    .selectOption("test-data/README.md");
  await scrollTo(
    page.getByLabel("Document content: test-data/README.md", { exact: true }),
  );
  await holdUntil(345);
  await page
    .getByLabel("Document", { exact: true })
    .selectOption("docs/detection-engine.md");
  await scrollTo(
    page.getByLabel("Document content: docs/detection-engine.md", {
      exact: true,
    }),
  );
  await holdUntil(355);
  assert.deepEqual(pageErrors, []);
  complete = true;
} finally {
  if (validationProcess && validationProcess.exitCode === null) {
    validationProcess.kill("SIGTERM");
  }
  await context.close();
  await browser.close();
}

assert.ok(
  complete,
  "Live walkthrough did not complete; no final recording may be claimed",
);
const raw = await video.path();
const output = path.join(destination, "sentinelflow-final-demo.mp4");
execFileSync(
  ffmpeg,
  [
    "-y",
    "-hide_banner",
    "-loglevel",
    "warning",
    "-i",
    raw,
    "-c:v",
    "libx264",
    "-preset",
    "fast",
    "-crf",
    "22",
    "-pix_fmt",
    "yuv420p",
    "-movflags",
    "+faststart",
    output,
  ],
  { stdio: "inherit" },
);
const probe = spawn(ffmpeg, ["-hide_banner", "-i", output, "-f", "null", "-"], {
  stdio: ["ignore", "ignore", "pipe"],
});
const probeDone = new Promise((resolve, reject) => {
  probe.on("error", reject);
  probe.on("close", resolve);
});
let probeText = "";
for await (const chunk of probe.stderr) probeText += chunk.toString();
const probeCode = await probeDone;
assert.equal(probeCode, 0, "The final video did not decode successfully");
const duration = /Duration: (\d+):(\d+):(\d+(?:\.\d+)?)/.exec(probeText);
assert.ok(duration, "No measured video duration");
const seconds =
  Number(duration[1]) * 3600 + Number(duration[2]) * 60 + Number(duration[3]);
assert.ok(
  seconds >= 300 && seconds <= 600,
  `Video duration outside 5–10 minutes: ${seconds}s`,
);
const bytes = await readFile(output);
assert.equal(
  bytes.subarray(4, 8).toString(),
  "ftyp",
  "Output is not an MP4 container",
);
const receipt = {
  status: "recorded-and-decoded",
  path: "recordings/sentinelflow-final-demo.mp4",
  created_at: new Date().toISOString(),
  duration_seconds: seconds,
  bytes: bytes.length,
  sha256: createHash("sha256").update(bytes).digest("hex"),
  browser: recordingBrowserVersion,
  capture: "Continuous real Chromium browser-context video",
  resolution: { width: 1440, height: 1000 },
  audio: "Silent walkthrough; chapter guide in docs/demo.md",
  source_fingerprint: validated.source_fingerprint,
  ffmpeg_version: execFileSync(ffmpeg, ["-version"], {
    encoding: "utf8",
  }).split("\n")[0],
  ffmpeg_sha256: createHash("sha256")
    .update(await readFile(ffmpeg))
    .digest("hex"),
  decoded_successfully: true,
  page_errors: pageErrors,
  chapters,
};
await writeFile(
  path.join(destination, "recording.json"),
  JSON.stringify(receipt, null, 2) + "\n",
);
await writeFile(path.join(destination, "media-inspection.txt"), probeText);
await unlink(raw);
console.log(JSON.stringify(receipt, null, 2));
