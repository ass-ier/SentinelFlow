import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  api, assert, base, contextFor, expect, fingerprint, go, launch,
  noHorizontalOverflow, openAlert, requireValidation, root, uiResponse,
} from "./browser_workflows.mjs";

await requireValidation();
assert.equal((await api("/health")).public_demo, undefined, "Use an isolated private backend");
const output = process.env.SENTINEL_INTEGRATION_ARTIFACTS || path.join(root, "artifacts/integrations-browser");
await mkdir(output, { recursive: true });
const receipt = {
  status: "running", started_at: new Date().toISOString(), source_fingerprint: fingerprint(),
  checks: [], screenshots: [], live_microsoft_tested: false,
};
const record = (name, details = {}) => {
  receipt.checks.push({ name, status: "passed", ...details });
  console.log("PASS", name);
};
const browser = await launch();
const context = await contextFor(browser);
const page = await context.newPage();
const pageErrors = [];
page.on("pageerror", error => pageErrors.push(error.message));
let sentinel;
let alert;
let testDelivery;

try {
  await page.route("**/api/integrations", async route => {
    await new Promise(resolve => setTimeout(resolve, 600));
    await route.continue();
  }, { times: 1 });
  await page.goto(base + "/integrations");
  await expect(page.getByText(/Loading connector status/)).toBeVisible();
  await expect(page.getByRole("table", { name: "Telemetry connectors" })).toBeVisible();
  record("Actual API load has an accessible loading state; no connectivity is invented");

  const defaultRow = page.getByRole("row").filter({
    has: page.getByText("sentinel-default", { exact: true }),
  });
  await expect(defaultRow).toContainText("Disabled");
  await expect(defaultRow).toContainText("No successful operation");
  assert.equal((await api("/integrations")).external_enabled, false);
  record("Default Microsoft and Windows sources remain externally disabled");
  await uiResponse(page, "/integrations/connectors/sentinel-default/test",
    () => defaultRow.getByRole("button", { name: "Test connection" }).click(), { status: 409 });
  await expect(page.getByRole("alert")).toContainText("Integration operation did not complete");
  record("Missing live enablement produces an actual, actionable error without an external request");

  const before = (await api("/events/search?limit=1")).total;
  await page.getByRole("button", { name: "Configure connector", exact: true }).click();
  await page.getByLabel("Connector name", { exact: true }).fill("Browser Graph configuration");
  await page.getByLabel("Telemetry provider").selectOption("microsoft_graph");
  await page.getByLabel("Connector mode").selectOption("demo");
  const connector = await uiResponse(page, "/integrations/connectors",
    () => page.getByRole("button", { name: "Save connector", exact: true }).click(), { status: 201 });
  assert.equal(connector.mode, "demo");
  assert.equal(connector.enabled, false);
  const custom = page.getByRole("row").filter({
    has: page.getByText(connector.id, { exact: true }),
  });
  await uiResponse(page, `/integrations/connectors/${connector.id}/test`,
    () => custom.getByRole("button", { name: "Test connection" }).click());
  await expect(page.getByText(/Connection query completed/)).toBeVisible();
  assert.equal((await api("/events/search?limit=1")).total, before);
  record("Connector form saves reference-only configuration; a real mock query test imports nothing");

  await go(page, "/notifications", "Notifications");
  await expect(page.getByText("No notification destinations configured.", { exact: true })).toBeVisible();
  await expect(page.getByText("No notification deliveries", { exact: true })).toBeVisible();
  record("Notification empty states leave core alerts and investigation available");
  await page.getByRole("button", { name: "Add destination", exact: true }).click();
  await page.getByLabel("Destination name").fill("Browser mock webhook");
  await page.getByLabel("Destination type").selectOption("webhook");
  await page.getByLabel("Delivery mode").selectOption("demo");
  const destination = await uiResponse(page, "/notifications/destinations",
    () => page.getByRole("button", { name: "Save destination", exact: true }).click(), { status: 201 });
  assert.equal(destination.enabled, false);
  const destinationRow = page.getByRole("table", { name: "Notification destinations" })
    .getByRole("row").filter({ hasText: "Browser mock webhook" });
  await uiResponse(page, `/notifications/destinations/${destination.id}/enabled`,
    () => destinationRow.getByRole("button", { name: "Enable", exact: true }).click());
  testDelivery = await uiResponse(page, "/notifications/test",
    () => destinationRow.getByRole("button", { name: "Send test", exact: true }).click(), { status: 202 });
  assert.equal(testDelivery.status, "pending");
  await expect(page.getByText(/Notification test queued/)).toBeVisible();
  await expect.poll(async () => (await api(`/notifications/deliveries/${testDelivery.id}`)).status,
    { timeout: 10000 }).toBe("delivered");
  await page.getByRole("button", { name: "Refresh workspace data" }).click();
  await expect(page.locator(`a[href="/notifications/${testDelivery.id}"]`)).toBeVisible();
  record("Destination enablement and test enqueue lead to a real persisted HTTP 202 mock delivery");
  await page.locator(`a[href="/notifications/${testDelivery.id}"]`).click();
  await expect(page.getByRole("table", { name: "Delivery attempts" })).toContainText("202");
  await expect(page.getByText(/No live Power Automate flow or Teams channel was contacted/)).toBeVisible();
  const detail = await api(`/notifications/deliveries/${testDelivery.id}`);
  assert.equal(detail.payload.event, "notification_test");
  assert.equal(detail.payload.alert, null);
  assert.equal(detail.attempts.length, 1);
  record("Delivery detail shows actual attempt evidence and an explicit non-incident test payload");

  await go(page, "/notifications", "Notifications");
  await page.getByRole("button", { name: "Create policy", exact: true }).click();
  await page.getByLabel("Policy name").fill("Browser routing configuration");
  await page.getByRole("checkbox", { name: "Browser mock webhook" }).check();
  await page.getByLabel("Severities", { exact: true }).fill("high, critical");
  await page.getByLabel("Rule IDs", { exact: true }).fill("AUTH-001");
  const policy = await uiResponse(page, "/notifications/policies",
    () => page.getByRole("button", { name: "Save policy", exact: true }).click(), { status: 201 });
  assert.deepEqual(policy.rule_ids, ["AUTH-001"]);
  assert.equal(policy.include_replays, false);
  const policyRow = page.getByRole("table", { name: "Notification policies" })
    .getByRole("row").filter({ hasText: policy.name });
  const disabled = await uiResponse(page, `/notifications/policies/${policy.id}`,
    () => policyRow.getByRole("button", { name: "Disable", exact: true }).click(), { method: "PATCH" });
  assert.equal(disabled.enabled, false);
  record("Notification policy filters persist, exclude replay by default and disable independently");

  for (const [source, events, deliveries] of [
    ["microsoft_sentinel", 13, 2], ["microsoft_graph", 13, 2], ["windows_wef", 36, 7],
  ]) {
    await go(page, "/integrations", "Integrations");
    await page.getByLabel("Demo telemetry source").selectOption(source);
    const demo = await uiResponse(page, "/integrations/demo",
      () => page.getByRole("button", { name: "Run offline demonstration", exact: true }).click());
    assert.equal(demo.events_processed, events);
    assert.equal(demo.status, "mock");
    await expect.poll(async () => {
      const rows = (await api("/notifications/deliveries?limit=100")).items;
      return demo.deliveries.every(item => rows.some(row => row.id === item.id && row.status === "delivered"));
    }, { timeout: 10000 }).toBe(true);
    assert.equal(demo.deliveries.length, deliveries);
    record(`${source} UI demo normalizes, detects and delivers to the real local receiver`, { events, deliveries });
    if (source === "microsoft_sentinel") sentinel = demo;
  }

  alert = await openAlert(page, sentinel.run_id, "AUTH-001");
  assert.equal(alert.event_count, 10);
  await expect(page.getByRole("heading", { name: "Telemetry provenance" })).toBeVisible();
  await expect(page.getByText("Microsoft sentinel", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Notifications", exact: true })).toBeVisible();
  assert.equal(alert.notifications[0].status, "delivered");
  record("Alert investigation joins rule, ten triggering events, Microsoft provenance and independent delivery state");

  const previous = (await api("/notifications/deliveries?limit=100")).total;
  await go(page, "/integrations", "Integrations");
  await page.getByLabel("Demo telemetry source").selectOption("microsoft_sentinel");
  await uiResponse(page, "/integrations/demo",
    () => page.getByRole("button", { name: "Run offline demonstration", exact: true }).click());
  assert.equal((await api("/notifications/deliveries?limit=100")).total, previous);
  record("Repeated UI demonstration does not duplicate notifications");

  await go(page, "/events", "Event explorer", sentinel.run_id);
  await page.getByRole("button", { name: /^Show raw event / }).first().click();
  await expect(page.locator(".evidence-row")).toContainText("microsoft_sentinel");
  record("Event evidence preserves connector attribution and source JSON");

  const routes = [
    ["/integrations", "Integrations"], ["/notifications", "Notifications"],
    [`/notifications/${testDelivery.id}`, "Notification delivery"],
    [`/alerts/${alert.id}`, "Brute force authentication"],
  ];
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1000 });
    for (const [route, heading] of routes) {
      await go(page, route, heading);
      await noHorizontalOverflow(page);
      record(`Integration surface fits ${width}px: ${route.split("/")[1]}`);
    }
    await go(page, "/integrations", "Integrations");
    await page.getByRole("button", { name: "Configure connector", exact: true }).click();
    await expect(page.getByLabel("Client secret environment reference")).toBeVisible();
    await noHorizontalOverflow(page);
    record(`Reference-only connector configuration is usable at ${width}px`);
  }
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await page.getByRole("button", { name: "Open navigation", exact: true }).click();
  await page.getByRole("navigation", { name: "Workspace navigation" })
    .getByRole("link", { name: "Notifications", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Notifications", level: 1 })).toBeVisible();
  record("Mobile navigation reaches new integration pages without a broken route");

  await go(page, "/notifications", "Notifications");
  const deletionRow = page.getByRole("table", { name: "Notification destinations" })
    .getByRole("row").filter({ hasText: "Browser mock webhook" });
  await deletionRow.getByRole("button", { name: "Delete", exact: true }).click();
  await uiResponse(page, `/notifications/destinations/${destination.id}`,
    () => deletionRow.getByRole("button", { name: "Confirm delete destination" }).click(), { method: "DELETE" });
  assert.equal((await api(`/notifications/deliveries/${testDelivery.id}`)).status, "delivered");
  record("Confirmed destination deletion retains its delivery evidence");
  assert.deepEqual(pageErrors, []);
  record("No uncaught rendering errors in real integration workflows");
  for (const value of [
    JSON.stringify(await api("/integrations")), await page.locator("body").innerText(),
  ]) {
    assert.doesNotMatch(value, /mock-token-not-live|synthetic-oauth-placeholder/);
  }
  record("Actual mock OAuth credentials are absent from management responses and rendered UI");

  for (const [route, heading, file, width] of [
    ["/integrations", "Integrations", "integrations-desktop.png", 1440],
    ["/notifications", "Notifications", "notifications-desktop.png", 1440],
    [`/alerts/${alert.id}`, "Brute force authentication", "integration-alert.png", 1440],
    ["/integrations", "Integrations", "integrations-mobile.png", 390],
  ]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1000 });
    await go(page, route, heading);
    await expect(page.getByRole("table").first()).toBeVisible();
    await page.screenshot({ path: path.join(output, file), fullPage: true });
    const bytes = await readFile(path.join(output, file));
    assert.equal(bytes.subarray(1, 4).toString(), "PNG");
    receipt.screenshots.push({ path: `artifacts/integrations-browser/${file}`, bytes: bytes.length });
  }
  assert.equal(receipt.source_fingerprint, fingerprint());
  receipt.status = "passed";
} catch (error) {
  receipt.status = "failed";
  receipt.error = error.stack || String(error);
  console.error(receipt.error);
  process.exitCode = 1;
} finally {
  receipt.completed_at = new Date().toISOString();
  receipt.page_errors = pageErrors;
  await writeFile(path.join(output, "browser-results.json"), JSON.stringify(receipt, null, 2) + "\n");
  await context.close();
  await browser.close();
}
