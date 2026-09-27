import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
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
  noHorizontalOverflow,
  openAlert,
  replay,
  requireValidation,
  root,
  testDetection,
  testSigma,
  uiResponse,
} from "./browser_workflows.mjs";

const checks = [];
const record = (name, details = {}) => {
  checks.push({ name, status: "passed", ...details });
  console.log("PASS", name);
};
const screenshotNames = [
  "dashboard.png",
  "events.png",
  "alert-details.png",
  "detection-rules.png",
  "detection-validation.png",
  "replay.png",
  "sigma-validation.png",
];
await requireValidation();
const browser = await launch();
const context = await contextFor(browser);
const page = await context.newPage();
const pageErrors = [];
const serverErrors = [];
page.on("pageerror", (error) => pageErrors.push(error.message));
page.on("response", (response) => {
  const expectedRejection =
    response.status() === 422 &&
    new URL(response.url()).pathname === "/api/sigma/compile";
  if (response.status() >= 400 && !expectedRejection) {
    serverErrors.push({ url: response.url(), status: response.status() });
  }
});
const receipt = {
  status: "running",
  started_at: new Date().toISOString(),
  source_fingerprint: fingerprint(),
  browser: browser.version(),
  checks,
  screenshots: [],
};

try {
  const seeded = await api("/admin/demo-reset", {
    confirmation: "RESET DEMO",
    seed: true,
  });
  const seed = seeded.run.id;
  await go(page, "/", "Overview", seed);
  await expect(
    page
      .locator(".metrics-strip > div")
      .filter({ has: page.locator("dt", { hasText: /^Events processed$/ }) })
      .locator("dd"),
  ).toHaveText("56");
  await expect(
    page
      .locator(".metrics-strip > div")
      .filter({ has: page.locator("dt", { hasText: /^Active alerts$/ }) })
      .locator("dd"),
  ).toHaveText("7");
  record("Dashboard renders real scoped counts and event-time chart", {
    events: 56,
    alerts: 7,
  });

  await go(page, "/events", "Event explorer", seed);
  await page.getByRole("button", { name: "More filters", exact: true }).click();
  await page.getByLabel("Outcome", { exact: true }).selectOption("failure");
  const search = page.waitForResponse(
    (r) =>
      r.url().includes("/api/events/search") &&
      r.url().includes("outcome=failure"),
  );
  await page.getByRole("button", { name: "Search", exact: true }).click();
  assert.equal((await (await search).json()).total, 29);
  record("Event explorer filters backend results", { failedEvents: 29 });
  await page
    .getByRole("button", { name: /^Show raw event / })
    .first()
    .click();
  await expect(page.locator(".evidence-row")).toBeVisible();
  record("Event rows expand real raw evidence");

  await go(page, "/events?import=1", "Event explorer");
  await page
    .getByLabel("Telemetry file")
    .setInputFiles(
      path.join(root, "test-data/authentication/brute_force.jsonl"),
    );
  await expect(page.getByLabel("Event content")).toHaveValue(/auth-brute/);
  const imported = await uiResponse(page, "/events", () =>
    page.getByRole("button", { name: "Ingest events", exact: true }).click(),
  );
  assert.equal(imported.events_stored, 25);
  assert.equal(imported.alerts_created, 1);
  await expect(
    page.getByText("Import completed", { exact: true }),
  ).toBeVisible();
  record("File ingestion is real and changes the run scope", {
    events: 25,
    alerts: 1,
  });

  const brute = await replay(page, "auth-brute-force", "10x", true);
  assert.equal(brute.alerts_created, 1);
  assert.equal(brute.metrics.events_processed, 25);
  record("Chronological 10x replay reaches actual 25-event completion", {
    run_id: brute.id,
  });
  const alert = await openAlert(page, brute.id, "AUTH-001");
  assert.equal(alert.event_count, 25);
  assert.ok(alert.mitre_attack.includes("T1110"));
  await page.getByLabel("Set alert status").selectOption("investigating");
  await uiResponse(
    page,
    `/alerts/${alert.id}/status`,
    () =>
      page.getByRole("button", { name: "Save status", exact: true }).click(),
    { method: "PATCH" },
  );
  await expect(
    page.getByText("Investigation status saved.", { exact: true }),
  ).toBeVisible();
  assert.equal((await api("/alerts/" + alert.id)).status, "investigating");
  record(
    "Alert status, 25 linked events, raw evidence, MITRE and rule snapshot work",
    { alert_id: alert.id },
  );

  await go(page, "/rules/AUTH-001", "Brute force authentication");
  const disable = page.getByRole("switch", {
    name: "Disable Brute force authentication",
    exact: true,
  });
  await disable.click();
  await expect(
    page.getByRole("switch", {
      name: "Enable Brute force authentication",
      exact: true,
    }),
  ).toHaveAttribute("aria-checked", "false");
  await page
    .getByLabel("Dataset", { exact: true })
    .selectOption("auth-brute-force");
  const definition = await uiResponse(page, "/rules/AUTH-001/test", () =>
    page
      .getByRole("button", { name: "Run definition test", exact: true })
      .click(),
  );
  assert.equal(definition.status, "passed");
  assert.equal((await api("/rules/AUTH-001")).enabled, false);
  await page
    .getByRole("switch", {
      name: "Enable Brute force authentication",
      exact: true,
    })
    .click();
  await expect(
    page.getByRole("switch", {
      name: "Disable Brute force authentication",
      exact: true,
    }),
  ).toHaveAttribute("aria-checked", "true");
  record(
    "Rule toggle and explicit disabled-definition testing work without hidden enablement",
  );

  const positive = await testDetection(page, "auth-brute-force");
  assert.equal(positive.results[0].actual[0].event_count, 25);
  const negative = await testDetection(page, "auth-normal-failures");
  assert.deepEqual(negative.results[0].actual, []);
  record("Positive and benign detection tests display exact real results");

  const ps = await replay(page, "powershell-indicators");
  const psAlert = await openAlert(page, ps.id, "PROC-001");
  assert.equal(psAlert.event_count, 5);
  await expect(
    page.getByLabel("Process command line — inert text").first(),
  ).toBeVisible();
  record("PowerShell replay and inert command-line evidence work");
  const dns = await replay(page, "dns-long-label");
  const dnsAlert = await openAlert(page, dns.id, "DNS-001");
  assert.equal(dnsAlert.branch, "long-label");
  assert.equal(dnsAlert.event_count, 3);
  record("DNS heuristic alert exposes its branch and actual evidence");

  const sample = await loadSigma(page);
  await compileSigma(page);
  const sigmaImport = await uiResponse(page, "/sigma/import", () =>
    page
      .getByRole("button", { name: "Import disabled rule", exact: true })
      .click(),
  );
  assert.equal(sigmaImport.enabled, false);
  await testSigma(page);
  await testSigma(page, true);
  record(
    "Licensed Sigma compile/import and positive/negative tests preserve authorship",
  );
  await page
    .getByLabel("Sigma YAML", { exact: true })
    .fill(
      sample.yaml.replace(
        "all of selection_*",
        "selection_download | count() > 1",
      ),
    );
  const rejected = await uiResponse(
    page,
    "/sigma/compile",
    () =>
      page.getByRole("button", { name: "Compile rule", exact: true }).click(),
    { status: 422 },
  );
  assert.equal(rejected.error.code, "unsupported_sigma");
  await expect(
    page.getByText(/Unsupported Sigma feature:/).first(),
  ).toBeVisible();
  record(
    "Unsupported Sigma condition is a visible failure, never simulated success",
  );

  await go(page, "/evidence", "Project evidence");
  await expect(
    page.getByRole("heading", {
      name: "Comprehensive validation",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByLabel("Actual validation command output"),
  ).toContainText("STATUS: VALIDATED");
  await expect(
    page.getByRole("heading", { name: "Included file inventory", exact: true }),
  ).toBeVisible();
  record(
    "Project evidence reads actual make validate output and repository inventory",
  );

  const routes = [
    ["/", "Overview"],
    ["/events", "Event explorer"],
    ["/alerts", "Alert queue"],
    ["/rules", "Detection rules"],
    ["/testing", "Detection testing"],
    ["/replay", "Detection replay"],
    ["/sigma", "Sigma workbench"],
    ["/evidence", "Project evidence"],
  ];
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1000 });
    for (const [route, title] of routes) {
      await go(page, route, title);
      record(`${width}px layout: ${title}`, await noHorizontalOverflow(page));
      if (width === 390 && route === "/") {
        const identifiers = await page
          .locator(".technique-tag")
          .evaluateAll((tags) =>
            tags.map((tag) => {
              const text = [...tag.querySelector("a").childNodes].find(
                (node) => node.nodeType === Node.TEXT_NODE,
              );
              const range = document.createRange();
              range.selectNodeContents(text);
              return {
                id: text.textContent.trim(),
                lines: range.getClientRects().length,
              };
            }),
          );
        assert.ok(
          identifiers.length > 0 &&
            identifiers.every((item) => item.lines === 1),
        );
        record("Mobile technique identifiers stay on one line", {
          identifiers,
        });
      }
    }
  }
  await go(page, "/", "Overview");
  await page
    .getByRole("button", { name: "Open navigation", exact: true })
    .click();
  await page
    .getByRole("navigation", { name: "Workspace navigation" })
    .getByRole("link", { name: "Events", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Event explorer", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Open navigation", exact: true }),
  ).toBeVisible();
  record("Mobile navigation opens, navigates, and closes");
  await page.reload();
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Skip to main content" }),
  ).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();
  record("Keyboard skip link moves focus into the analyst workspace");
  assert.deepEqual(pageErrors, []);
  assert.deepEqual(serverErrors, []);
  record("No uncaught page errors or server errors during verified workflows");

  // Capture only after every functional and responsive check above passes.
  if (!process.argv.includes("--no-capture")) {
    const directory = path.join(root, "screenshots");
    await mkdir(directory, { recursive: true });
    await page.setViewportSize({ width: 1440, height: 1000 });
    const reset = await api("/admin/demo-reset", {
      confirmation: "RESET DEMO",
      seed: true,
    });
    const clean = reset.run.id;
    const screenshot = async (name, fullPage = true) => {
      if (fullPage) {
        const scroll = await page.evaluate(() => ({
          x: window.scrollX,
          y: window.scrollY,
        }));
        // Chromium can omit never-painted, offscreen scrollable code from full-page captures.
        for (const output of await page.locator(".code-block pre").all()) {
          if (await output.isVisible()) {
            await output.scrollIntoViewIfNeeded();
            await expect(output).not.toHaveText("");
            await page.waitForTimeout(100);
          }
        }
        await page.evaluate(({ x, y }) => window.scrollTo(x, y), scroll);
        await page.waitForTimeout(100);
      }
      await page.screenshot({ path: path.join(directory, name), fullPage });
      const bytes = await readFile(path.join(directory, name));
      assert.equal(bytes.subarray(1, 4).toString(), "PNG");
      receipt.screenshots.push({
        path: "screenshots/" + name,
        bytes: bytes.length,
      });
    };
    await go(page, "/", "Overview", clean);
    await expect(page.locator(".metrics-strip dd").first()).toHaveText("56");
    await screenshot("dashboard.png");
    await go(page, "/events", "Event explorer", clean);
    await expect(
      page.getByRole("button", { name: /^Show raw event / }).first(),
    ).toBeVisible();
    await screenshot("events.png", false);
    await openAlert(page, clean, "AUTH-001");
    await page.evaluate(() => window.scrollTo(0, 0));
    await screenshot("alert-details.png");
    await go(page, "/rules", "Detection rules");
    await expect(page.getByRole("switch").first()).toBeVisible();
    await screenshot("detection-rules.png");
    await testDetection(page, "auth-brute-force");
    await screenshot("detection-validation.png");
    await replay(page, "auth-brute-force", "10x");
    await page.evaluate(() => window.scrollTo(0, 0));
    await screenshot("replay.png");
    await loadSigma(page);
    await compileSigma(page);
    await testSigma(page);
    await page.evaluate(() => window.scrollTo(0, 0));
    await screenshot("sigma-validation.png");
    await page.setViewportSize({ width: 390, height: 844 });
    await go(page, "/", "Overview", clean);
    await noHorizontalOverflow(page);
    await screenshot("mobile-dashboard.png");
    assert.ok(
      screenshotNames.every((name) =>
        receipt.screenshots.some((item) => item.path.endsWith(name)),
      ),
    );
  }
  receipt.status = "passed";
} catch (error) {
  receipt.status = "failed";
  receipt.error = error.stack || String(error);
  console.error(receipt.error);
  process.exitCode = 1;
} finally {
  receipt.completed_at = new Date().toISOString();
  receipt.page_errors = pageErrors;
  receipt.server_errors = serverErrors;
  await mkdir(path.join(root, "artifacts"), { recursive: true });
  await writeFile(
    path.join(root, "artifacts/browser-results.json"),
    JSON.stringify(receipt, null, 2) + "\n",
  );
  await context.close();
  await browser.close();
}
