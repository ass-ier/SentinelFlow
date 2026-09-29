import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  api,
  apiBase,
  assert,
  base,
  compileSigma,
  contextFor,
  expect,
  fingerprint,
  go,
  launch,
  loadSigma,
  noHorizontalOverflow,
  openAlert,
  replay,
  requireValidation,
  root,
  testDetection,
  testSigma,
  uiResponse,
} from "./browser_workflows.mjs";

for (const address of [
  process.env.SENTINEL_UI_URL,
  process.env.SENTINEL_API_URL,
]) {
  assert.ok(address, "Explicit isolated UI and API URLs are required");
  assert.equal(
    new URL(address).hostname,
    "127.0.0.1",
    "This verifier is local-only",
  );
}
assert.ok(
  !process.env.SENTINEL_API_TOKEN,
  "Public browser verification must not use an owner token",
);
const output = path.resolve(
  process.env.SENTINEL_DEPLOYMENT_ARTIFACTS ||
    path.join(root, "artifacts/deployment-browser"),
);
assert.ok(
  output.startsWith(path.join(root, "artifacts") + path.sep),
  "Evidence must stay under artifacts/",
);
await mkdir(output, { recursive: true });
await requireValidation();
assert.equal(
  (await api("/health")).public_demo,
  true,
  "Refusing to mutate a non-public-demo backend",
);
const checks = [];
const record = (name, details = {}) => {
  checks.push({ name, status: "passed", ...details });
  console.log("PASS", name);
};
const browser = await launch();
const context = await contextFor(browser);
const page = await context.newPage();
const errors = [];
const failedRequests = [];
const apiRequests = [];
const pendingHeaders = [];
page.on("pageerror", (error) => errors.push(error.message));
page.on("console", (message) => {
  if (message.type() === "error") errors.push(message.text());
});
page.on("requestfinished", (request) => {
  if (new URL(request.url()).pathname.startsWith("/api/")) {
    // Aborted navigation reads may never supply final headers; inspect completed requests.
    pendingHeaders.push(
      request.allHeaders().then((headers) => {
        apiRequests.push({
          url: request.url(),
          method: request.method(),
          origin: headers.origin,
          authorization: Boolean(headers.authorization),
          cookie: Boolean(headers.cookie),
        });
      }),
    );
  }
});
page.on("response", (response) => {
  if (response.status() >= 400)
    failedRequests.push({ url: response.url(), status: response.status() });
});
page.on("requestfailed", (request) => {
  if (request.failure()?.errorText !== "net::ERR_ABORTED") {
    failedRequests.push({
      url: request.url(),
      error: request.failure()?.errorText,
    });
  }
});
const receipt = {
  status: "failed",
  started_at: new Date().toISOString(),
  source_fingerprint: fingerprint(),
  browser: browser.version(),
  ui: base,
  api: apiBase,
  checks,
  errors,
  failed_requests: failedRequests,
  api_requests: apiRequests,
  request_scope:
    "Completed browser API requests; intentional navigation cancellations excluded",
  screenshots: [],
};

try {
  await go(page, "/", "Overview");
  await expect(
    page
      .locator(".metrics-strip > div")
      .filter({
        has: page.locator("dt", { hasText: /^Events processed$/ }),
      })
      .locator("dd"),
  ).toHaveText("56");
  await expect(
    page
      .locator(".metrics-strip > div")
      .filter({
        has: page.locator("dt", { hasText: /^Active alerts$/ }),
      })
      .locator("dd"),
  ).toHaveText("7");
  await expect(
    page.getByText("Shared synthetic demo.", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Import events", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Connection settings", exact: true }),
  ).toHaveCount(0);
  record(
    "Public dashboard shows the real 56-event, seven-alert seed without credentials",
  );
  await noHorizontalOverflow(page);
  await page.screenshot({
    path: path.join(output, "desktop-dashboard.png"),
    fullPage: true,
  });
  receipt.screenshots.push("desktop-dashboard.png");

  const scripts = await page
    .locator("script[src]")
    .evaluateAll((items) => items.map((item) => item.src));
  assert.ok(
    scripts.length &&
      scripts.every((src) => new URL(src).pathname.startsWith("/assets/")),
  );
  assert.ok(
    scripts.every((src) => !src.includes("@vite") && !src.includes("/src/")),
  );
  const csp = await page
    .locator('meta[http-equiv="Content-Security-Policy"]')
    .getAttribute("content");
  assert.ok(csp.includes(`connect-src 'self' ${apiBase}`), csp);
  const document = await page.request.get(base + "/events");
  assert.equal(document.headers()["x-frame-options"], "DENY");
  assert.equal(document.headers()["x-content-type-options"], "nosniff");
  assert.equal(
    document.headers()["content-security-policy"],
    "frame-ancestors 'none'",
  );
  const notProxied = await page.request.get(base + "/api/health");
  assert.ok(notProxied.headers()["content-type"].includes("text/html"));
  record(
    "Production assets, exact API-origin CSP, security headers, and no preview API proxy",
  );

  for (const [route, heading] of [
    ["/events", "Event explorer"],
    ["/alerts", "Alert queue"],
    ["/rules", "Detection rules"],
    ["/testing", "Detection testing"],
    ["/detections", "Detection testing"],
    ["/replay", "Detection replay"],
    ["/sigma", "Sigma workbench"],
    ["/evidence", "Demo data & limits"],
  ]) {
    await go(page, route, heading);
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(
      page.getByRole("heading", { level: 1, name: heading }),
    ).toBeVisible();
    await expect(page.locator(".connection-status")).toHaveText(
      "Demo API connected",
    );
    record("Direct navigation and refresh: " + route);
  }

  await go(page, "/events", "Event explorer");
  await page.getByRole("button", { name: "More filters", exact: true }).click();
  await page.getByLabel("Outcome", { exact: true }).selectOption("failure");
  const searching = page.waitForResponse(
    (response) =>
      response.url().includes("/api/events/search") &&
      response.url().includes("outcome=failure"),
  );
  await page.getByRole("button", { name: "Search", exact: true }).click();
  assert.equal((await (await searching).json()).total, 29);
  await page
    .getByRole("button", { name: /^Show raw event / })
    .first()
    .click();
  await expect(page.locator(".evidence-row")).toBeVisible();
  record("Event search filters real results and expands inert raw evidence", {
    failed_events: 29,
  });

  const brute = await replay(page, "auth-brute-force", "10x", true);
  assert.equal(brute.alerts_created, 1);
  assert.equal(brute.processed_events, 25);
  record("10x replay processes 25 real authentication events", {
    run_id: brute.id,
  });
  const alert = await openAlert(page, brute.id, "AUTH-001");
  assert.equal(alert.event_count, 25);
  assert.equal(alert.severity, "high");
  assert.ok(alert.mitre_attack.includes("T1110"));
  await expect(
    page.getByRole("button", { name: "Save status", exact: true }),
  ).toHaveCount(0);
  await expect(page.getByLabel("Investigation note (optional)")).toHaveCount(0);
  await expect(
    page.getByRole("heading", { name: "Pinned rule snapshot", exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: path.join(output, "alert-evidence.png"),
    fullPage: true,
  });
  receipt.screenshots.push("alert-evidence.png");
  record(
    "AUTH-001 preserves 25 linked events, MITRE, snapshot, and read-only investigation",
  );

  await go(page, "/rules/AUTH-001", "Brute force authentication");
  await expect(page.getByRole("switch")).toBeDisabled();
  await page
    .getByLabel("Dataset", { exact: true })
    .selectOption("auth-brute-force");
  const definition = await uiResponse(page, "/rules/AUTH-001/test", () =>
    page
      .getByRole("button", { name: "Run definition test", exact: true })
      .click(),
  );
  assert.equal(definition.status, "passed");
  assert.equal(definition.results[0].actual[0].event_count, 25);
  record("Read-only rule detail still executes real isolated definition tests");

  const positive = await testDetection(page, "auth-brute-force");
  assert.equal(positive.results[0].actual[0].event_count, 25);
  const benign = await testDetection(page, "auth-normal-failures");
  assert.deepEqual(benign.results[0].actual, []);
  record(
    "Positive and benign validation return exact results without operational alerts",
  );

  const powershell = await replay(page, "powershell-indicators");
  assert.equal(
    (await openAlert(page, powershell.id, "PROC-001")).event_count,
    5,
  );
  const dns = await replay(page, "dns-long-label");
  const dnsAlert = await openAlert(page, dns.id, "DNS-001");
  assert.equal(dnsAlert.event_count, 3);
  assert.equal(dnsAlert.branch, "long-label");
  record("PowerShell and DNS replay preserve actual heuristic evidence");

  await loadSigma(page);
  await expect(page.getByLabel("Sigma YAML", { exact: true })).toHaveAttribute(
    "readonly",
    "",
  );
  await expect(
    page.getByRole("button", { name: "Import disabled rule", exact: true }),
  ).toHaveCount(0);
  await expect(page.getByLabel("Upload Sigma YAML")).toHaveCount(0);
  await compileSigma(page);
  await testSigma(page);
  await testSigma(page, true);
  assert.equal((await api("/rules")).total, 7);
  record(
    "Licensed pinned Sigma compilation and positive/benign tests work without import",
  );

  await page.setViewportSize({ width: 390, height: 844 });
  for (const [route, heading] of [
    ["/", "Overview"],
    ["/events", "Event explorer"],
    ["/alerts", "Alert queue"],
    ["/rules", "Detection rules"],
    ["/replay", "Detection replay"],
    ["/sigma", "Sigma workbench"],
    ["/evidence", "Demo data & limits"],
  ]) {
    await go(page, route, heading);
    record("Mobile layout: " + route, await noHorizontalOverflow(page));
  }
  await go(page, "/", "Overview");
  await page
    .getByRole("button", { name: "Open navigation", exact: true })
    .click();
  await expect(
    page.getByRole("navigation", { name: "Workspace navigation" }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(
    page.getByRole("button", { name: "Open navigation", exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: path.join(output, "mobile-dashboard.png"),
    fullPage: true,
  });
  receipt.screenshots.push("mobile-dashboard.png");
  record("Mobile navigation opens and closes by keyboard");

  await Promise.all(pendingHeaders);
  assert.ok(apiRequests.length > 20);
  assert.ok(
    apiRequests.every((request) => request.url.startsWith(apiBase + "/api/")),
  );
  assert.ok(
    apiRequests.every((request) => !request.authorization && !request.cookie),
  );
  const posts = apiRequests.filter((request) => request.method === "POST");
  assert.ok(
    posts.length >= 8 && posts.every((request) => request.origin === base),
  );
  assert.deepEqual(errors, []);
  assert.deepEqual(failedRequests, []);
  record(
    "All completed browser API requests use the configured backend without credentials",
  );
  record("No critical console errors or unexpected failed requests", {
    api_requests: apiRequests.length,
  });
  receipt.status = "passed";
} finally {
  receipt.completed_at = new Date().toISOString();
  await writeFile(
    path.join(output, "browser.json"),
    JSON.stringify(receipt, null, 2) + "\n",
  );
  await context.close();
  await browser.close();
}
console.log(
  JSON.stringify({ status: receipt.status, checks: checks.length, output }),
);
