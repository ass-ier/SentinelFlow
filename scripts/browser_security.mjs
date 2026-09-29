import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  api,
  apiBase,
  assert,
  base,
  contextFor,
  expect,
  fingerprint,
  go,
  launch,
  noHorizontalOverflow,
  openAlert,
  requireValidation,
  root,
  uiResponse,
} from "./browser_workflows.mjs";

await requireValidation();
const output = process.env.SENTINEL_SECURITY_ARTIFACTS;
assert.ok(
  output &&
    path.resolve(output).startsWith(path.join(root, "artifacts") + path.sep),
);
await mkdir(output, { recursive: true });
const receipt = {
  status: "running",
  started_at: new Date().toISOString(),
  source_fingerprint: fingerprint(),
  checks: [],
  screenshots: [],
};
const record = (name) => {
  receipt.checks.push({ name, status: "passed" });
  console.log("PASS", name);
};
const owner = process.env.SENTINEL_API_TOKEN;
const scoped = process.env.SENTINEL_INTEGRATION_BROWSER;
assert.ok(
  owner && scoped,
  "Use the isolated security rehearsal, not an existing application",
);
const browser = await launch();
const context = await contextFor(browser);
const page = await context.newPage();
const errors = [];
page.on("pageerror", (error) => errors.push(error.message));
const marker = '<img src=x onerror="window.__sentinelflowXss=true">';

try {
  const unauthorized = await fetch(apiBase + "/api/integrations/credentials");
  assert.equal(unauthorized.status, 401);
  const denied = await unauthorized.text();
  assert.ok(!denied.includes(owner) && !denied.includes(scoped));
  record(
    "Unauthenticated private configuration is denied without credential disclosure",
  );

  await go(page, "/integrations", "Integrations");
  await page
    .getByRole("button", { name: "Connection settings", exact: true })
    .click();
  await expect(page.getByLabel("API token", { exact: true })).toHaveAttribute(
    "type",
    "password",
  );
  assert.ok(!(await page.locator("body").innerText()).includes(owner));
  await page.getByRole("button", { name: "Close connection settings" }).click();
  record("Owner token entry is masked and absent from rendered page text");

  await page
    .getByText("Scoped integration credentials", { exact: true })
    .click();
  await page
    .getByLabel("Credential name", { exact: true })
    .fill("Security browser reader");
  await page
    .getByLabel("Token environment reference")
    .fill("SENTINEL_INTEGRATION_BROWSER");
  await page.getByLabel("Expiration (local time)").fill("2099-01-01T12:30");
  const credential = await uiResponse(
    page,
    "/integrations/credentials",
    () =>
      page
        .getByRole("button", { name: "Register credential reference" })
        .click(),
    { status: 201 },
  );
  assert.equal(credential.expires_at, "2099-01-01T12:30:00Z");
  const headers = { Authorization: `Bearer ${scoped}` };
  assert.equal((await fetch(apiBase + "/api/alerts", { headers })).status, 200);
  assert.equal(
    (await fetch(apiBase + "/api/integrations/credentials", { headers }))
      .status,
    403,
  );
  assert.ok(
    !JSON.stringify(await api("/integrations/credentials")).includes(scoped),
  );
  record(
    "Reference-only credential creation enforces UTC expiry and the actual read-only scope",
  );

  const row = page
    .getByRole("table", { name: "Scoped integration credentials" })
    .getByRole("row")
    .filter({ hasText: "Security browser reader" });
  await uiResponse(
    page,
    `/integrations/credentials/${credential.id}`,
    () => row.getByRole("button", { name: "Revoke", exact: true }).click(),
    { method: "PATCH" },
  );
  assert.equal((await fetch(apiBase + "/api/alerts", { headers })).status, 401);
  record("UI revocation takes effect on the next authenticated request");
  const { id, ...config } = credential;
  await api(
    `/integrations/credentials/${id}`,
    { ...config, enabled: true, expires_at: "2000-01-01T00:00:00Z" },
    "PATCH",
  );
  await page.reload();
  await page
    .getByText("Scoped integration credentials", { exact: true })
    .click();
  await expect(
    page.getByRole("table", { name: "Scoped integration credentials" }),
  ).toContainText("Expired");
  assert.equal((await fetch(apiBase + "/api/alerts", { headers })).status, 401);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({
    path: path.join(output, "credential-expiry.png"),
    fullPage: true,
  });
  receipt.screenshots.push("credential-expiry.png");
  record(
    "Expired credentials are visibly distinguished and rejected by the backend",
  );

  await go(page, "/notifications", "Notifications");
  await page
    .getByRole("button", { name: "Add destination", exact: true })
    .click();
  await page.getByLabel("Destination name").fill(marker);
  await page.getByLabel("Destination type").selectOption("webhook");
  await page.getByLabel("Delivery mode").selectOption("demo");
  const destination = await uiResponse(
    page,
    "/notifications/destinations",
    () =>
      page
        .getByRole("button", { name: "Save destination", exact: true })
        .click(),
    { status: 201 },
  );
  const destinationRow = page
    .getByRole("table", { name: "Notification destinations" })
    .getByRole("row")
    .filter({ hasText: marker });
  await expect(destinationRow).toContainText(marker);
  assert.equal(await page.locator('img[src="x"]').count(), 0);
  await uiResponse(
    page,
    `/notifications/destinations/${destination.id}/enabled`,
    () =>
      destinationRow
        .getByRole("button", { name: "Enable", exact: true })
        .click(),
  );
  const delivery = await uiResponse(
    page,
    "/notifications/test",
    () =>
      destinationRow
        .getByRole("button", { name: "Send test", exact: true })
        .click(),
    { status: 202 },
  );
  await expect
    .poll(
      async () =>
        (await api(`/notifications/deliveries/${delivery.id}`)).status,
      { timeout: 10000 },
    )
    .toBe("delivered");
  await go(page, `/notifications/${delivery.id}`, "Notification delivery");
  await expect(
    page.getByRole("table", { name: "Delivery attempts" }),
  ).toContainText("202");
  assert.ok(!(await page.locator("body").innerText()).includes(scoped));
  record(
    "Malicious destination text remains inert and delivery history contains no server secrets",
  );

  await api("/rules", {
    yaml: [
      "id: SECURITY-XSS-001",
      `name: ${JSON.stringify(marker)}`,
      "description: Inert synthetic browser security regression",
      "severity: low",
      "conditions:",
      "  field: process.name",
      "  operator: equals",
      "  value: security-fixture.exe",
    ].join("\n"),
  });
  const incident = {
    event: {
      id: "security-browser-event",
      timestamp: "2026-01-15T00:00:00Z",
      source: "security-fixture",
      category: "process",
      type: "start",
      action: "process_started",
      outcome: "success",
    },
    host: { name: "security-demo" },
    process: { name: "security-fixture.exe", command_line: marker },
    raw_event: { synthetic: true, payload: marker },
  };
  const imported = await api("/events", {
    format: "json",
    content: JSON.stringify(incident),
    name: "Inert browser security fixture",
  });
  const alert = await openAlert(page, imported.run.id, "SECURITY-XSS-001");
  assert.equal(alert.evidence[0].raw_event.payload, marker);
  assert.equal(await page.locator('img[src="x"]').count(), 0);
  assert.equal(await page.evaluate(() => window.__sentinelflowXss), undefined);
  record(
    "Actual stored malicious alert names render as text, never executable markup",
  );
  const raw = page.getByLabel(`Raw event ${alert.evidence[0].event.id}`, {
    exact: true,
  });
  await expect(raw).toBeVisible();
  assert.equal(JSON.parse(await raw.innerText()).payload, marker);
  assert.equal(await page.locator('img[src="x"]').count(), 0);
  assert.equal(await page.evaluate(() => window.__sentinelflowXss), undefined);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({
    path: path.join(output, "literal-evidence.png"),
    fullPage: true,
  });
  receipt.screenshots.push("literal-evidence.png");
  record(
    "Raw evidence preserves malicious bytes while remaining inert in the real browser",
  );

  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1000 });
    await go(page, "/integrations", "Integrations");
    await page
      .getByText("Scoped integration credentials", { exact: true })
      .click();
    await expect(page.getByLabel("Expiration (local time)")).toBeVisible();
    await noHorizontalOverflow(page);
    record(`Credential expiry controls remain usable at ${width}px`);
  }
  await page.goto(base + "/docs");
  await expect(page.locator("#swagger-ui .opblock").first()).toBeVisible();
  const schema = await (await fetch(apiBase + "/openapi.json")).json();
  assert.equal(schema.components.securitySchemes.OwnerBearer.scheme, "bearer");
  assert.equal(
    schema.paths["/ingest/windows"].post["x-required-integration-scope"],
    "windows:ingest",
  );
  record(
    "Updated offline Swagger renders and declares actual bearer/scoped authorization",
  );
  assert.deepEqual(errors, []);
  record("Security workflows completed without browser runtime errors");
  receipt.status = "passed";
} catch (error) {
  receipt.status = "failed";
  receipt.error = String(error);
  throw error;
} finally {
  receipt.finished_at = new Date().toISOString();
  await writeFile(
    path.join(output, "browser.json"),
    JSON.stringify(receipt, null, 2) + "\n",
  );
  await context.close();
  await browser.close();
}
