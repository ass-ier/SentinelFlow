import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);
const args = process.argv.slice(2);
const serve = args.includes("--serve");
const rehearse = args.includes("--rehearse");
assert.ok(!(serve && rehearse));
const valueAfter = (flag) => {
  const index = args.indexOf(flag);
  return index < 0 ? undefined : args[index + 1];
};
const label = new Date().toISOString().replaceAll(/[:.]/g, "-");
const output = path.resolve(
  root,
  valueAfter("--output") || `artifacts/linkedin-trailer/${label}`,
);
assert.ok(
  output.startsWith(path.join(root, "artifacts/linkedin-trailer") + path.sep),
);
await mkdir(path.dirname(output), { recursive: true, mode: 0o700 });
await mkdir(output, { recursive: false, mode: 0o700 });
const python =
  process.env.SENTINELFLOW_PYTHON ||
  path.join(root, ".runtime/venv/bin/python");
const ffprobe =
  process.env.SENTINEL_FFPROBE ||
  path.join(root, ".runtime/recording/bin/ffprobe");
await access(python);
await access(ffprobe);
await access(path.join(root, "frontend/dist/index.html"));
process.env.SENTINELFLOW_PYTHON = python;
delete process.env.SENTINEL_API_TOKEN;
const fingerprint = () =>
  execFileSync(
    python,
    [
      "-c",
      "from app.core.evidence import source_fingerprint; print(source_fingerprint())",
    ],
    { cwd: root, encoding: "utf8" },
  ).trim();
const sourceFingerprint = fingerprint();
const release = JSON.parse(
  await readFile(path.join(root, "docs/results/security/final/summary.json")),
);
assert.equal(release.status, "PASS");
assert.equal(
  release.source_fingerprint,
  sourceFingerprint,
  "Current release evidence is stale",
);
assert.equal(
  release.validation.backend.passed + release.validation.frontend.passed,
  946,
);
assert.equal(release.validation.detections.passed, 50);
const browserChecks = release.rehearsals.checks.reduce(
  (total, item) =>
    total +
    (item.name.includes("browser") ? item.checks : item.browser_checks || 0),
  0,
);
assert.equal(browserChecks, 127);
const originalVideo = path.join(root, "recordings/sentinelflow-final-demo.mp4");
const originalHash = createHash("sha256")
  .update(await readFile(originalVideo))
  .digest("hex");

const reserve = net.createServer();
await new Promise((resolve, reject) => {
  reserve.once("error", reject);
  reserve.listen(0, "127.0.0.1", resolve);
});
const port = reserve.address().port;
await new Promise((resolve) => reserve.close(resolve));
assert.ok(![5173, 8765, 18875, 18881].includes(port));
const base = `http://127.0.0.1:${port}`;
const environment = {
  PATH: process.env.PATH,
  HOME: process.env.HOME,
  TMPDIR: process.env.TMPDIR,
  LANG: "en_US.UTF-8",
  PYTHONPATH: path.join(root, "backend"),
  PYTHON_DOTENV_DISABLED: "1",
  PYTHONDONTWRITEBYTECODE: "1",
  SENTINEL_DATABASE_URL: `sqlite:///${path.join(output, "sentinelflow-demo.sqlite3")}`,
  SENTINEL_API_TOKEN: "",
  SENTINEL_PUBLIC_DEMO: "false",
  SENTINEL_ALLOWED_HOSTS: "127.0.0.1",
  SENTINEL_ALLOWED_ORIGINS: base,
  SENTINEL_ENABLED: "false",
  GRAPH_ENABLED: "false",
  WINDOWS_COLLECTOR_ENABLED: "false",
  NOTIFICATIONS_ENABLED: "false",
};
const serverLog = createWriteStream(path.join(output, "server.log"), {
  mode: 0o600,
});
const server = spawn(
  python,
  [
    "-m",
    "uvicorn",
    "app.main:app",
    "--host",
    "127.0.0.1",
    "--port",
    String(port),
    "--no-access-log",
  ],
  { cwd: root, env: environment, stdio: ["ignore", "pipe", "pipe"] },
);
server.stdout.pipe(serverLog);
server.stderr.pipe(serverLog);
let spawnError;
server.on("error", (error) => {
  spawnError = error;
});
const stopped = new Promise((resolve) => server.once("exit", resolve));
const pause = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));
let browser;
let context;
const receipt = {
  status: "running",
  mode: serve ? "preview" : rehearse ? "rehearsal" : "capture",
  created_at: new Date().toISOString(),
  source_fingerprint: sourceFingerprint,
  release_receipt: "docs/results/security/final/summary.json",
  base,
  capture: { width: 1920, height: 1080, browser_zoom: 1.2, audio: "none" },
  setup: {},
  scenes: [],
  page_errors: [],
  failed_responses: [],
  external_browser_requests: [],
  live_integrations_tested: false,
  notifications_sent: 0,
};
const api = async (endpoint, body, method) => {
  const response = await fetch(base + "/api" + endpoint, {
    method: method || (body === undefined ? "GET" : "POST"),
    headers: { "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(15_000),
  });
  assert.ok(
    response.ok,
    `${endpoint}: HTTP ${response.status}: ${await response.clone().text()}`,
  );
  return response.json();
};
try {
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (spawnError) throw spawnError;
    assert.equal(
      server.exitCode,
      null,
      "Owned recording server exited during startup",
    );
    try {
      const response = await fetch(base + "/health", {
        signal: AbortSignal.timeout(500),
      });
      if (response.ok) {
        const health = await response.json();
        assert.equal(health.public_demo, undefined);
        assert.equal(health.auth_required, false);
        ready = true;
        break;
      }
    } catch (error) {
      if (!(error instanceof TypeError) && error.name !== "TimeoutError")
        throw error;
    }
    await pause(100);
  }
  assert.ok(ready, "Owned loopback server did not become ready");
  const seed = await api("/events", {
    name: "Synthetic SOC workspace",
    format: "jsonl",
    content: await readFile(
      path.join(root, "test-data/mixed/incident_timeline.jsonl"),
      "utf8",
    ),
  });
  assert.equal(seed.events_stored, 56);
  assert.equal(seed.alerts_created, 7);
  const graph = await api(
    "/integrations/connectors/graph-default",
    {
      name: "Microsoft Graph / Entra",
      type: "microsoft_graph",
      mode: "demo",
      enabled: false,
      tenant_id: null,
      client_id: null,
      workspace_id: null,
      secret_ref: "GRAPH_CLIENT_SECRET",
      profiles: [{ id: "signins", enabled: true, interval_seconds: 60 }],
    },
    "PATCH",
  );
  const destination = await api("/notifications/destinations", {
    name: "Power Automate-compatible workflow",
    type: "power_automate",
    mode: "demo",
    enabled: false,
    url_ref: null,
    authentication: "none",
    auth_ref: null,
  });
  const policy = await api("/notifications/policies", {
    name: "AUTH-001 investigation workflow",
    enabled: false,
    destinations: [destination.id],
    severities: ["high"],
    rule_ids: ["AUTH-001"],
    include_replays: false,
  });
  assert.equal((await api("/integrations")).external_enabled, false);
  assert.equal((await api("/notifications/deliveries?limit=1")).total, 0);
  receipt.setup = {
    seed_run_id: seed.run.id,
    graph_id: graph.id,
    destination_id: destination.id,
    policy_id: policy.id,
  };
  await writeFile(
    path.join(output, "preview.json"),
    JSON.stringify({ base, output, ...receipt.setup }, null, 2),
  );
  console.log(`READY ${base}`);
  if (serve) {
    await new Promise((resolve) => {
      process.once("SIGINT", resolve);
      process.once("SIGTERM", resolve);
    });
    receipt.status = "preview-finished";
  } else {
    process.env.SENTINEL_UI_URL = base;
    process.env.SENTINEL_API_URL = base;
    const { launch, contextFor, go, expect, uiResponse } = await import(
      "../../scripts/browser_workflows.mjs"
    );
    browser = await launch();
    receipt.browser = browser.version();
    await mkdir(path.join(output, "raw"), { mode: 0o700 });
    context = await contextFor(browser, {
      viewport: { width: 1920, height: 1080 },
      deviceScaleFactor: 1,
      recordVideo: {
        dir: path.join(output, "raw"),
        size: { width: 1920, height: 1080 },
      },
    });
    await context.route("**/*", async (route) => {
      const url = new URL(route.request().url());
      if (url.origin !== base && !["data:", "blob:"].includes(url.protocol)) {
        receipt.external_browser_requests.push(url.origin);
        await route.abort("blockedbyclient");
        return;
      }
      await route.continue();
    });
    await context.addInitScript(() => {
      document.addEventListener(
        "DOMContentLoaded",
        () => {
          document.documentElement.style.zoom = "1.2";
        },
        { once: true },
      );
    });
    const smoothScroll = async (page, locator, margin = 145) => {
      await locator.evaluate((element, offset) => {
        window.scrollTo({
          top: window.scrollY + element.getBoundingClientRect().top - offset,
          behavior: "smooth",
        });
      }, margin);
      await page.waitForTimeout(650);
    };
    async function scene(id, title, subtitle, duration, prepare, perform) {
      console.log(`SCENE ${id}: ${title}`);
      const page = await context.newPage();
      page.on("pageerror", (error) => receipt.page_errors.push(error.message));
      page.on("response", (response) => {
        if (response.status() >= 400)
          receipt.failed_responses.push({
            path: new URL(response.url()).pathname,
            status: response.status(),
          });
      });
      const video = page.video();
      assert.ok(video);
      await prepare(page);
      await page.evaluate(() => document.fonts.ready);
      await page.waitForTimeout(350);
      const cleanStart = performance.now();
      const record = {
        id,
        title,
        subtitle,
        duration,
        route: new URL(page.url()).pathname,
      };
      const at = async (seconds) => {
        if (!rehearse)
          await page.waitForTimeout(
            Math.max(0, seconds * 1000 - (performance.now() - cleanStart)),
          );
      };
      await perform(
        page,
        at,
        record,
        () => (performance.now() - cleanStart) / 1000,
      );
      if (!rehearse) {
        assert.ok(
          (performance.now() - cleanStart) / 1000 < duration - 0.5,
          `${id}: actions exceeded planned section`,
        );
        await at(duration);
      } else {
        record.duration = (performance.now() - cleanStart) / 1000;
      }
      await page.screenshot({ path: path.join(output, `${id}.png`) });
      const visibleText = await page.evaluate(() => {
        const walker = document.createTreeWalker(
          document.body,
          NodeFilter.SHOW_TEXT,
        );
        const result = [];
        for (let node = walker.nextNode(); node; node = walker.nextNode()) {
          if (!node.textContent?.trim()) continue;
          const parent = node.parentElement;
          if (
            !parent?.checkVisibility({
              checkOpacity: true,
              checkVisibilityCSS: true,
            })
          )
            continue;
          const closed = parent.closest("details:not([open])");
          if (closed && !closed.querySelector("summary")?.contains(parent))
            continue;
          const range = document.createRange();
          range.selectNode(node);
          const rect = range.getBoundingClientRect();
          let top = Math.max(0, rect.top);
          let bottom = Math.min(innerHeight, rect.bottom);
          let left = Math.max(0, rect.left);
          let right = Math.min(innerWidth, rect.right);
          for (
            let ancestor = parent;
            ancestor;
            ancestor = ancestor.parentElement
          ) {
            const style = getComputedStyle(ancestor);
            const box = ancestor.getBoundingClientRect();
            if (style.overflowY !== "visible") {
              top = Math.max(top, box.top);
              bottom = Math.min(bottom, box.bottom);
            }
            if (style.overflowX !== "visible") {
              left = Math.max(left, box.left);
              right = Math.min(right, box.right);
            }
          }
          if (rect.width && rect.height && bottom > top && right > left) {
            result.push(node.textContent.trim());
          }
        }
        return result.join("\n");
      });
      assert.ok(
        !/Bearer\s+[A-Za-z0-9._-]{20,}|mock-token-not-live|synthetic-oauth-placeholder|\/Users\/|\/private\/var\//.test(
          visibleText,
        ),
        `${id}: credential-like text or a local execution path would be visible`,
      );
      await writeFile(path.join(output, `${id}-visible.txt`), visibleText);
      await page.waitForTimeout(1000);
      const afterCleanSeconds = (performance.now() - cleanStart) / 1000;
      await page.close();
      const raw = await video.path();
      const metadata = JSON.parse(
        execFileSync(
          ffprobe,
          [
            "-v",
            "error",
            "-show_entries",
            "format=duration:stream=width,height,codec_name",
            "-of",
            "json",
            raw,
          ],
          { encoding: "utf8" },
        ),
      );
      assert.equal(metadata.streams[0].width, 1920);
      assert.equal(metadata.streams[0].height, 1080);
      record.raw = path.relative(root, raw);
      record.raw_duration = Number(metadata.format.duration);
      record.trim_start = Math.max(0, record.raw_duration - afterCleanSeconds);
      record.screenshot = path.relative(root, path.join(output, `${id}.png`));
      assert.ok(
        record.raw_duration > record.duration + record.trim_start,
        `${id}: incomplete capture`,
      );
      receipt.scenes.push(record);
      await writeFile(
        path.join(output, "capture.json"),
        JSON.stringify(receipt, null, 2) + "\n",
      );
    }
    let imported;
    let replay;
    let alert;

    await scene(
      "01-dashboard",
      "SENTINELFLOW",
      "Detection Engineering & Security Analytics Platform",
      6,
      async (page) => {
        await go(page, "/", "Overview");
        await expect(page.locator(".metrics-strip dd").first()).toHaveText(
          "56",
        );
      },
      async () => {},
    );

    await scene(
      "02-ingestion",
      "SECURITY TELEMETRY",
      "Ingest and normalize security events.",
      10,
      (page) => go(page, "/events?import=1", "Event explorer"),
      async (page, at, record) => {
        await at(0.8);
        await page
          .getByLabel("Telemetry file")
          .setInputFiles(
            path.join(root, "test-data/authentication/brute_force.jsonl"),
          );
        await page
          .getByLabel("Import name", { exact: true })
          .fill("Failed-login telemetry");
        await expect(page.getByLabel("Event content")).toHaveValue(
          /auth-brute-000/,
        );
        await at(2.8);
        imported = await uiResponse(page, "/events", () =>
          page
            .getByRole("button", { name: "Ingest events", exact: true })
            .click(),
        );
        assert.equal(imported.events_stored, 25);
        assert.equal(imported.alerts_created, 1);
        await expect(
          page.getByText("Import completed", { exact: true }),
        ).toBeVisible();
        await smoothScroll(
          page,
          page.getByText("Import completed", { exact: true }),
        );
        await at(6.5);
        await page
          .getByRole("button", { name: "Close import", exact: true })
          .click();
        await page.evaluate(() =>
          window.scrollTo({ top: 0, behavior: "smooth" }),
        );
        record.result = {
          run_id: imported.run.id,
          events: imported.events_stored,
        };
      },
    );

    await scene(
      "03-rules",
      "DETECTION ENGINEERING",
      "YAML-driven rules identify suspicious activity.",
      10,
      (page) => go(page, "/rules/AUTH-001", "Brute force authentication"),
      async (page, at, record) => {
        const rule = await api("/rules/AUTH-001");
        assert.equal(rule.enabled, true);
        assert.ok(rule.mitre_attack.includes("T1110"));
        await expect(
          page.getByRole("heading", { name: "Match criteria", exact: true }),
        ).toBeVisible();
        await at(4);
        await smoothScroll(
          page,
          page.getByRole("heading", {
            name: "Current definition",
            exact: true,
          }),
          110,
        );
        record.result = {
          rule_id: rule.id,
          severity: rule.severity,
          threshold: rule.threshold,
          mitre: rule.mitre_attack,
        };
      },
    );

    await scene(
      "04-detection",
      "DETECTION IN ACTION",
      "Telemetry is evaluated against active detection rules.",
      12,
      async (page) => {
        await go(page, "/replay", "Detection replay");
        await page
          .getByLabel("Dataset", { exact: true })
          .selectOption("auth-brute-force");
        await page.getByLabel("Replay speed").selectOption("10x");
      },
      async (page, at, record, elapsed) => {
        await at(1);
        const started = await uiResponse(page, "/detections/replay", () =>
          page
            .getByRole("button", { name: "Start replay", exact: true })
            .click(),
        );
        await expect(
          page.getByText(
            "Replay completed. All counts above are final API results.",
          ),
        ).toBeVisible({ timeout: 15_000 });
        replay = await api("/detections/replay/" + started.id);
        assert.equal(replay.status, "completed");
        assert.equal(replay.processed_events, 25);
        assert.equal(replay.alerts_created, 1);
        const alerts = await api(
          `/alerts?run_id=${replay.id}&rule_id=AUTH-001`,
        );
        assert.equal(alerts.total, 1);
        alert = await api(`/alerts/${alerts.items[0].id}`);
        assert.equal(alert.event_count, 25);
        record.alert_at = elapsed();
        await smoothScroll(
          page,
          page.getByRole("heading", {
            name: "Detections in this replay",
            exact: true,
          }),
        );
        record.result = {
          run_id: replay.id,
          alert_id: alert.id,
          events: 25,
          alerts: 1,
          rule_id: "AUTH-001",
        };
      },
    );

    await scene(
      "05-investigation",
      "ALERT INVESTIGATION",
      "Move from detection to actionable security context.",
      10,
      (page) => go(page, `/alerts/${alert.id}`, alert.rule_name, replay.id),
      async (page, at, record) => {
        await at(1);
        await page.getByLabel("Set alert status").selectOption("investigating");
        await at(2);
        const updated = await uiResponse(
          page,
          `/alerts/${alert.id}/status`,
          () =>
            page
              .getByRole("button", { name: "Save status", exact: true })
              .click(),
          { method: "PATCH" },
        );
        assert.equal(updated.status, "investigating");
        await expect(
          page.getByText("Investigation status saved.", { exact: true }),
        ).toBeVisible();
        await page.evaluate(() =>
          window.scrollTo({ top: 0, behavior: "smooth" }),
        );
        record.result = {
          alert_id: alert.id,
          status: updated.status,
          source: alert.source_entities,
          affected: alert.affected_entities,
        };
      },
    );

    await scene(
      "06-evidence",
      "EVIDENCE",
      "Investigate the telemetry behind every detection.",
      10,
      async (page) => {
        await go(page, `/alerts/${alert.id}`, alert.rule_name, replay.id);
        await smoothScroll(
          page,
          page.getByRole("heading", {
            name: "Triggering evidence",
            exact: true,
          }),
        );
      },
      async (page, at, record) => {
        await at(1);
        const id = alert.evidence[0].event.id;
        await page
          .getByRole("button", { name: `Show raw event ${id}`, exact: true })
          .click();
        const raw = page.getByLabel(`Raw event ${id}`, { exact: true });
        await expect(raw).toBeVisible();
        await smoothScroll(page, raw, 210);
        assert.equal(JSON.parse(await raw.innerText()).event.id, id);
        record.result = {
          alert_id: alert.id,
          event_id: id,
          expanded_records: 1,
        };
      },
    );

    await scene(
      "07-mitre",
      "MITRE ATT&CK",
      "Map detections to adversary techniques.",
      7,
      async (page) => {
        await go(page, `/alerts/${alert.id}`, alert.rule_name, replay.id);
        await smoothScroll(page, page.locator(".investigation-summary"), 145);
      },
      async (page, at, record) => {
        await at(1);
        const technique = page
          .locator(".investigation-summary")
          .getByRole("link", { name: "T1110", exact: true });
        await expect(technique).toBeVisible();
        await technique.hover();
        record.result = {
          alert_id: alert.id,
          technique: "T1110",
          name: "Brute Force",
          external_navigation: false,
        };
      },
    );

    await scene(
      "08-search",
      "SECURITY INVESTIGATION",
      "Search security telemetry during an investigation.",
      8,
      (page) => go(page, "/events", "Event explorer", replay.id),
      async (page, at, record) => {
        await at(0.8);
        await page
          .getByLabel("Search events", { exact: true })
          .pressSequentially("gateway-01", { delay: rehearse ? 1 : 70 });
        await at(2.5);
        const waiting = page.waitForResponse(
          (response) =>
            new URL(response.url()).pathname === "/api/events/search" &&
            new URL(response.url()).searchParams.get("q") === "gateway-01",
        );
        await page.getByRole("button", { name: "Search", exact: true }).click();
        const response = await waiting;
        assert.equal(response.status(), 200);
        const result = await response.json();
        assert.equal(result.total, 25);
        assert.ok(
          result.items.every((event) => event.host.name === "gateway-01"),
        );
        record.result = {
          run_id: replay.id,
          query: "gateway-01",
          results: result.total,
        };
      },
    );

    await scene(
      "09-integrations",
      "MICROSOFT SECURITY INTEGRATION",
      "Graph / Entra connector implemented. Live tenant not tested.",
      9,
      async (page) => {
        await go(page, "/integrations", "Integrations");
        const row = page
          .getByRole("table", { name: "Telemetry connectors" })
          .getByRole("row")
          .filter({ has: page.getByText("graph-default", { exact: true }) });
        await row.getByRole("button", { name: "Edit", exact: true }).click();
        await expect(
          page.getByRole("heading", { name: "Edit connector", exact: true }),
        ).toBeVisible();
        await smoothScroll(
          page,
          page.getByRole("heading", { name: "Edit connector", exact: true }),
          120,
        );
      },
      async (page, _at, record) => {
        await expect(page.getByLabel("Telemetry provider")).toHaveValue(
          "microsoft_graph",
        );
        await expect(page.getByLabel("Connector mode")).toHaveValue("demo");
        assert.equal(
          await page.getByLabel("Tenant ID", { exact: true }).count(),
          0,
        );
        assert.equal(
          await page.getByLabel("Client ID", { exact: true }).count(),
          0,
        );
        assert.equal(
          await page
            .getByLabel("Client secret environment reference", { exact: true })
            .count(),
          0,
        );
        record.result = {
          connector: graph.id,
          mode: "demo",
          enabled: false,
          credentials_visible: false,
          live_tested: false,
        };
      },
    );

    await scene(
      "10-notifications",
      "SECURITY NOTIFICATIONS",
      "Power Automate-compatible routing. No external delivery performed.",
      9,
      async (page) => {
        await go(page, "/notifications", "Notifications");
        const row = page
          .getByRole("table", { name: "Notification destinations" })
          .getByRole("row")
          .filter({ hasText: "Power Automate-compatible workflow" });
        await row.getByRole("button", { name: "Edit", exact: true }).click();
        await expect(
          page.getByRole("heading", { name: "Edit destination", exact: true }),
        ).toBeVisible();
        await smoothScroll(
          page,
          page.getByRole("heading", { name: "Edit destination", exact: true }),
          120,
        );
      },
      async (page, _at, record) => {
        await expect(page.getByLabel("Destination type")).toHaveValue(
          "power_automate",
        );
        await expect(page.getByLabel("Delivery mode")).toHaveValue("demo");
        assert.equal(
          await page.getByLabel("URL environment reference").count(),
          0,
        );
        assert.equal((await api("/notifications/deliveries?limit=1")).total, 0);
        record.result = {
          destination_id: destination.id,
          mode: "demo",
          enabled: false,
          deliveries: 0,
          live_tested: false,
        };
      },
    );

    await scene(
      "11-security",
      "SECURITY ENGINEERING",
      "Hardened and tested against common application-security threats.",
      8,
      async (page) => {
        await go(page, "/evidence", "Project evidence");
        await page.evaluate(() => {
          document.documentElement.style.zoom = "1.35";
          window.scrollTo(0, 0);
        });
        await expect(
          page.getByRole("table", { name: "Comprehensive validation counts" }),
        ).toBeVisible();
      },
      async (page, _at, record) => {
        const evidence = await api("/project/evidence");
        assert.equal(evidence.validation.is_current, true);
        assert.equal(evidence.validation.total_tests_passed, 946);
        assert.equal(evidence.validation.detections.passed, 50);
        const log = await page
          .getByLabel("Actual validation command output")
          .boundingBox();
        assert.ok(
          log && log.y >= 1080,
          "Terminal output would be visible in the security section",
        );
        record.result = {
          automated_tests: 946,
          detection_scenarios: 50,
          browser_checks: 127,
          live_log_shown: false,
          source_fingerprint: sourceFingerprint,
        };
      },
    );

    await scene(
      "12-finale",
      "DETECT \u2192 INVESTIGATE \u2192 RESPOND",
      "SentinelFlow",
      5,
      (page) => go(page, "/", "Overview"),
      async (_page, _at, record) => {
        record.result = {
          stack: "FastAPI / React / TypeScript",
          mapping: "MITRE ATT&CK",
        };
      },
    );

    assert.equal(receipt.scenes.length, 12);
    assert.deepEqual(receipt.page_errors, []);
    assert.deepEqual(receipt.failed_responses, []);
    assert.deepEqual(receipt.external_browser_requests, []);
    assert.equal((await api("/notifications/deliveries?limit=1")).total, 0);
    assert.equal((await api("/integrations")).external_enabled, false);
    const proof = await api(`/alerts/${alert.id}`);
    assert.equal(proof.status, "investigating");
    assert.equal(proof.evidence.length, 25);
    receipt.story = {
      fixture: "test-data/authentication/brute_force.jsonl",
      imported_run_id: imported.run.id,
      replay_run_id: replay.id,
      alert_id: alert.id,
      rule_id: "AUTH-001",
      host: "gateway-01",
      technique: "T1110",
      evidence_count: 25,
    };
    receipt.status = rehearse ? "rehearsed" : "captured";
  }
} catch (error) {
  receipt.status = "failed";
  receipt.error = error.stack || String(error);
  console.error(receipt.error);
  process.exitCode = 1;
} finally {
  if (context) await context.close();
  if (browser) await browser.close();
  if (server.exitCode === null) {
    server.kill("SIGTERM");
    await Promise.race([stopped, pause(5000)]);
    if (server.exitCode === null) {
      server.kill("SIGKILL");
      await stopped;
    }
  }
  serverLog.end();
  receipt.completed_at = new Date().toISOString();
  receipt.source_unchanged = fingerprint() === sourceFingerprint;
  receipt.original_recording_unchanged =
    createHash("sha256")
      .update(await readFile(originalVideo))
      .digest("hex") === originalHash;
  receipt.owned_server_stopped =
    server.exitCode !== null || server.signalCode !== null;
  await writeFile(
    path.join(output, "capture.json"),
    JSON.stringify(receipt, null, 2) + "\n",
  );
}
assert.ok(receipt.source_unchanged);
assert.ok(receipt.original_recording_unchanged);
assert.ok(receipt.owned_server_stopped);
if (receipt.status === "failed") process.exitCode = 1;
else
  console.log(`${receipt.status.toUpperCase()} ${path.relative(root, output)}`);
