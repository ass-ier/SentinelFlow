import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "../frontend/node_modules/playwright/index.mjs";
import { expect } from "../frontend/node_modules/@playwright/test/index.mjs";

export const root = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
export const base = process.env.SENTINEL_UI_URL || "http://127.0.0.1:5173";
export const apiBase = process.env.SENTINEL_API_URL || "http://127.0.0.1:8765";
export { assert, expect };

export function fingerprint() {
  return execFileSync(
    process.env.SENTINELFLOW_PYTHON || path.join(root, ".venv/bin/python"),
    [
      "-c",
      "from app.core.evidence import source_fingerprint; print(source_fingerprint())",
    ],
    { cwd: root, encoding: "utf8" },
  ).trim();
}

export async function requireValidation() {
  const receipt = JSON.parse(
    await readFile(path.join(root, "artifacts/validation.json"), "utf8"),
  );
  assert.equal(
    receipt.status,
    "validated",
    "Run make validate successfully before live verification/media",
  );
  assert.equal(
    receipt.source_fingerprint,
    fingerprint(),
    "Validation receipt is stale",
  );
  return receipt;
}

export async function api(endpoint, body, method) {
  const response = await fetch(apiBase + endpoint, {
    method: method || (body === undefined ? "GET" : "POST"),
    headers: {
      "Content-Type": "application/json",
      ...(process.env.SENTINEL_API_TOKEN
        ? { Authorization: `Bearer ${process.env.SENTINEL_API_TOKEN}` }
        : {}),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  assert.ok(
    response.ok,
    `${endpoint}: HTTP ${response.status}: ${await response.clone().text()}`,
  );
  return response.json();
}

export async function launch() {
  return chromium.launch({
    headless: true,
    ...(process.env.SENTINEL_BROWSER_CHANNEL
      ? { channel: process.env.SENTINEL_BROWSER_CHANNEL }
      : {}),
  });
}

export async function contextFor(browser, extra = {}) {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    locale: "en-US",
    timezoneId: "UTC",
    reducedMotion: "reduce",
    ...extra,
  });
  if (process.env.SENTINEL_API_TOKEN) {
    await context.addInitScript(
      (token) => sessionStorage.setItem("sentinelflow.token", token),
      process.env.SENTINEL_API_TOKEN,
    );
  }
  return context;
}

export async function go(page, route, heading, runId) {
  const suffix = runId
    ? `${route.includes("?") ? "&" : "?"}run_id=${runId}`
    : "";
  await page.goto(base + route + suffix, { waitUntil: "domcontentloaded" });
  await expect(
    page.getByRole("heading", { level: 1, name: heading }),
  ).toBeVisible();
  await expect(page.locator(".connection-status")).toHaveText(
    (await api("/health")).public_demo
      ? "Demo API connected"
      : "Local API connected",
  );
}

export async function uiResponse(
  page,
  endpoint,
  action,
  { method = "POST", status } = {},
) {
  const waiting = page.waitForResponse(
    (response) =>
      new URL(response.url()).pathname === "/api" + endpoint &&
      response.request().method() === method,
  );
  await action();
  const response = await waiting;
  assert.equal(
    response.status(),
    status ??
      (endpoint === "/events" || endpoint === "/sigma/import"
        ? 201
        : endpoint === "/detections/replay"
          ? 202
          : 200),
    `${endpoint}: ${await response.text()}`,
  );
  return response.json();
}

export async function replay(
  page,
  datasetId,
  speed = "instant",
  observeArrivals = false,
) {
  await go(page, "/replay", "Detection replay");
  await expect(page.getByLabel("Dataset", { exact: true })).toBeEnabled();
  await page.getByLabel("Dataset", { exact: true }).selectOption(datasetId);
  await page.getByLabel("Replay speed").selectOption(speed);
  const run = await uiResponse(page, "/detections/replay", () =>
    page.getByRole("button", { name: "Start replay", exact: true }).click(),
  );
  if (observeArrivals) {
    await page
      .getByRole("heading", { name: "Event arrivals", exact: true })
      .scrollIntoViewIfNeeded();
    await expect(page.locator(".event-table tbody tr").first()).toBeVisible();
  }
  await expect(
    page.getByText("Replay completed. All counts above are final API results."),
  ).toBeVisible({
    timeout: speed === "realtime" ? 90_000 : 30_000,
  });
  const final = await api("/detections/replay/" + run.id);
  assert.equal(final.status, "completed");
  assert.equal(final.processed_events, final.total_events);
  await expect(
    page.getByRole("progressbar", { name: "Replay progress" }),
  ).toHaveAttribute("value", String(final.processed_events));
  return final;
}

export async function testDetection(page, datasetId, ruleId = "AUTH-001") {
  await go(page, "/testing", "Detection testing");
  await expect(page.getByLabel("Dataset", { exact: true })).toBeEnabled();
  await page.getByLabel("Dataset", { exact: true }).selectOption(datasetId);
  await page.getByLabel("Detection", { exact: true }).selectOption(ruleId);
  const report = await uiResponse(page, "/detections/validate", () =>
    page.getByRole("button", { name: "Run validation", exact: true }).click(),
  );
  assert.equal(report.status, "passed");
  await expect(
    page.getByRole("heading", { name: "Validation results", exact: true }),
  ).toBeVisible();
  await page.locator(".validation-result > summary").first().click();
  await expect(
    page.getByRole("heading", { name: /Observed detections/ }),
  ).toBeVisible();
  return report;
}

export async function openAlert(page, runId, ruleId) {
  const list = await api(`/alerts?run_id=${runId}&rule_id=${ruleId}`);
  assert.ok(list.items.length, `No ${ruleId} alert for run ${runId}`);
  const alert = list.items[0];
  await go(page, "/alerts/" + alert.id, alert.rule_name, runId);
  await expect(
    page.getByRole("heading", { name: "Triggering evidence", exact: true }),
  ).toBeVisible();
  const detail = await api("/alerts/" + alert.id);
  assert.equal(detail.event_count, detail.evidence.length);
  assert.equal(detail.evidence_ids.length, detail.event_count);
  await page
    .getByRole("button", {
      name: `Show raw event ${detail.evidence[0].event.id}`,
      exact: true,
    })
    .click();
  await expect(
    page.getByLabel(`Raw event ${detail.evidence[0].event.id}`, {
      exact: true,
    }),
  ).toBeVisible();
  return detail;
}

export async function loadSigma(page) {
  await go(page, "/sigma", "Sigma workbench");
  const samples = await api("/sigma/samples");
  const sample = samples.items.find(
    (item) => item.dataset_id === "sigma-download",
  );
  assert.ok(sample);
  await expect(page.getByLabel("Pinned sample")).toBeEnabled();
  await page.getByLabel("Pinned sample").selectOption(sample.id);
  await page.getByRole("button", { name: "Load sample", exact: true }).click();
  await expect(page.getByLabel("Sigma YAML", { exact: true })).toHaveValue(
    sample.yaml,
  );
  return sample;
}

export async function compileSigma(page) {
  const compiled = await uiResponse(page, "/sigma/compile", () =>
    page.getByRole("button", { name: "Compile rule", exact: true }).click(),
  );
  await expect(
    page.getByRole("heading", { name: "Compilation result", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByLabel("Compiled rule JSON", { exact: true }),
  ).toContainText(compiled.rule.id);
  assert.equal(
    compiled.rule.provenance.author,
    "Florian Roth (Nextron Systems)",
  );
  return compiled;
}

export async function testSigma(page, negative = false) {
  await page
    .getByRole("button", {
      name: negative ? "Use negative fixture" : "Use positive fixture",
      exact: true,
    })
    .click();
  const report = await uiResponse(page, "/sigma/test", () =>
    page.getByRole("button", { name: "Run Sigma test", exact: true }).click(),
  );
  assert.equal(report.status, "passed");
  assert.equal(report.results[0].actual.length, negative ? 0 : 1);
  await expect(
    page.getByRole("heading", { name: "Validation results", exact: true }),
  ).toBeVisible();
  await page.locator(".validation-result > summary").first().click();
  return report;
}

export async function noHorizontalOverflow(page) {
  await page.waitForTimeout(200);
  const result = await page.evaluate(() => ({
    viewport: window.innerWidth,
    document: document.documentElement.scrollWidth,
    heading: document.querySelector("h1")?.textContent,
  }));
  assert.ok(
    result.document <= result.viewport + 1,
    `Page overflows horizontally: ${JSON.stringify(result)}`,
  );
  return result;
}
