"""Owned-process browser, collector and production-image security rehearsals."""

import argparse
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_tools import ROOT
from verify_deployment import request, stop, wait_ready

from app.core.evidence import source_fingerprint


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def main() -> None:
    if sys.flags.optimize:
        raise RuntimeError("Security rehearsals require enabled assertions")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--backend-image", required=True)
    parser.add_argument("--application-image", required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts/security"):
        raise ValueError("Use an owned directory under artifacts/security")
    output.mkdir(parents=True, exist_ok=False)
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(
            ("SENTINEL_", "GRAPH_", "WINDOWS_", "NOTIFICATIONS_", "VITE_", "RENDER_")
        )
        and key not in {"PORT", "PUBLIC_BASE_URL"}
    }
    owner, scoped, collector_token = (secrets.token_urlsafe(36) for _ in range(3))
    environment.update(
        {
            "SENTINELFLOW_PYTHON": sys.executable,
            "SENTINEL_PUBLIC_DEMO": "false",
            "SENTINEL_ENABLED": "false",
            "GRAPH_ENABLED": "false",
            "WINDOWS_COLLECTOR_ENABLED": "false",
            "NOTIFICATIONS_ENABLED": "false",
            "SENTINEL_INTEGRATION_WORKER": "true",
            "SENTINEL_INTEGRATION_LOCAL_TEST": "false",
            "SENTINEL_WEBHOOK_ALLOWED_NETWORKS": "",
            "PUBLIC_BASE_URL": "",
            "SENTINEL_API_TOKEN": owner,
            "SENTINEL_INTEGRATION_BROWSER": scoped,
            "SENTINEL_INTEGRATION_RELEASE_COLLECTOR": collector_token,
            "SENTINEL_DATABASE_URL": f"sqlite:///{output / 'private.sqlite3'}",
            "SENTINEL_ALLOWED_HOSTS": "127.0.0.1,localhost",
            "SENTINEL_ALLOWED_ORIGINS": base,
            "SENTINEL_UI_URL": base,
            "SENTINEL_API_URL": base,
            "SENTINEL_INTEGRATION_ARTIFACTS": str(output / "integration-browser"),
            "SENTINEL_SECURITY_ARTIFACTS": str(output / "security-browser"),
        }
    )
    report: dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "source_fingerprint": source_fingerprint(),
        "checks": [],
        "commands": [],
    }

    def record(name: str, **details: Any) -> None:
        report["checks"].append({"name": name, "status": "passed", **details})
        print("PASS", name, flush=True)

    def command(
        name: str,
        arguments: list[str],
        *,
        env: dict[str, str] | None = None,
        expected: int = 0,
        timeout: int = 600,
    ) -> str:
        started = datetime.now(UTC).isoformat()
        result = subprocess.run(
            arguments,
            cwd=ROOT,
            env=env or environment,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        (output / f"{name}.log").write_text(result.stdout + result.stderr)
        report["commands"].append(
            {
                "name": name,
                "command": arguments,
                "started_at": started,
                "exit_code": result.returncode,
                "expected_exit_code": expected,
            }
        )
        if result.returncode != expected:
            raise RuntimeError(f"{name} exited {result.returncode}; expected {expected}")
        return result.stdout

    def api(
        path: str, body: dict | None = None, *, method: str | None = None, status: int = 200
    ) -> Any:
        return request(
            base + "/api" + path,
            body,
            method=method,
            headers={"Authorization": f"Bearer {owner}"},
            status=status,
        )

    backend: subprocess.Popen[str] | None = None
    try:
        with ExitStack() as stack:
            log = stack.enter_context((output / "private-server.log").open("w"))

            def start_backend() -> None:
                nonlocal backend
                backend = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "uvicorn",
                        "app.main:app",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(port),
                        "--no-access-log",
                        "--no-proxy-headers",
                        "--no-server-header",
                    ],
                    cwd=ROOT,
                    env=environment,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                wait_ready(backend, base + "/health")

            def stop_backend() -> None:
                if backend is not None:
                    stop(backend)

            stack.callback(stop_backend)
            start_backend()
            assert api("/health")["auth_required"]
            command(
                "analyst-browser",
                ["node", "scripts/browser_verify.mjs", "--no-capture", "--preserve-database"],
            )
            shutil.copyfile(
                ROOT / "artifacts/browser-results.json", output / "analyst-browser.json"
            )
            command("integration-browser", ["node", "scripts/browser_integrations.mjs"])
            command("security-browser", ["node", "scripts/browser_security.mjs"])
            for name, path in (
                ("Analyst browser", output / "analyst-browser.json"),
                ("Integration browser", output / "integration-browser/browser-results.json"),
                ("Security browser", output / "security-browser/browser.json"),
            ):
                value = json.loads(path.read_text())
                assert (
                    value["status"] == "passed"
                    and value["source_fingerprint"] == source_fingerprint()
                )
                record(name, checks=len(value["checks"]), receipt=str(path.relative_to(output)))

            connector = api(
                "/integrations/connectors",
                {
                    "name": "Collector CLI security fixture",
                    "type": "windows_wef",
                    "mode": "demo",
                    "enabled": True,
                },
                status=201,
            )
            api(
                "/integrations/credentials",
                {
                    "name": "Collector CLI",
                    "token_ref": "SENTINEL_INTEGRATION_RELEASE_COLLECTOR",
                    "scopes": ["windows:ingest"],
                    "connector_id": connector["id"],
                },
                status=201,
            )
            spool = output / "collector.sqlite3"
            collector_env = {
                **environment,
                "SENTINEL_COLLECTOR_URL": base + "/api/ingest/windows",
                "SENTINEL_COLLECTOR_ID": connector["id"],
                "SENTINEL_COLLECTOR_TOKEN": collector_token,
            }
            collector = [
                sys.executable,
                "collector/windows/collect.py",
                "--once",
                "--local-test",
                "--spool",
                str(spool),
                "--fixture",
                "test-data/integrations/microsoft-windows.json",
                "--batch-size",
                "200",
            ]
            stop_backend()
            pending = json.loads(
                command("collector-outage", collector, env=collector_env, expected=2)
            )
            assert pending == {"pending": 36, "blocked": 0, "status": "pending"}
            record("Actual collector CLI durably spools all 36 events during a real TCP outage")
            start_backend()
            time.sleep(2.2)
            recovered = json.loads(command("collector-recovery", collector, env=collector_env))
            assert recovered == {"pending": 0, "blocked": 0, "status": "delivered"}
            state = next(
                item
                for item in api("/integrations/connectors")["items"]
                if item["id"] == connector["id"]
            )
            assert state["events_processed"] == 36
            alerts = api("/alerts?run_id=" + state["run_id"])["items"]
            assert len(alerts) == 7
            record(
                "Collector restart drains its real spool through scoped HTTP ingestion",
                events=36,
                alerts=7,
            )
            assert (
                json.loads(command("collector-repeat", collector, env=collector_env)) == recovered
            )
            assert api("/events?run_id=" + state["run_id"])["total"] == 36
            record("Repeated bookmark after process restart does not duplicate collector events")

            destinations = [
                api(
                    "/notifications/destinations",
                    {
                        "name": f"Independent replay destination {number}",
                        "type": "webhook",
                        "mode": "demo",
                        "enabled": True,
                    },
                    status=201,
                )["id"]
                for number in (1, 2)
            ]
            for _ in range(3):
                api(
                    f"/alerts/{alerts[0]['id']}/notify",
                    {"destination_ids": destinations},
                    status=202,
                )
            rows = [
                row
                for row in api("/notifications/deliveries?alert_id=" + alerts[0]["id"])["items"]
                if row["destination_id"] in destinations
            ]
            assert len(rows) == 2
            keys = {row["idempotency_key"] for row in rows}
            assert len(keys) == 2
            stop_backend()
            start_backend()
            api(f"/alerts/{alerts[0]['id']}/notify", {"destination_ids": destinations}, status=202)
            restored = [
                row
                for row in api("/notifications/deliveries?alert_id=" + alerts[0]["id"])["items"]
                if row["destination_id"] in destinations
            ]
            assert {row["id"] for row in restored} == {row["id"] for row in rows}
            record(
                "Same alert/destination is idempotent across restart; "
                "different destinations remain independent"
            )

        for engine in ("native", "docker"):
            label = "security-" + engine + "-" + secrets.token_hex(4)
            arguments = [
                sys.executable,
                "scripts/verify_deployment.py",
                "--label",
                label,
                "--backend-port",
                str(free_port()),
                "--frontend-port",
                str(free_port()),
            ]
            if engine == "docker":
                arguments.extend(["--docker", "--image-id", args.backend_image])
            command("deployment-" + engine, arguments, timeout=900)
            source = ROOT / "artifacts/deployment" / label
            shutil.copytree(source, output / ("deployment-" + engine))
            receipt = json.loads((source / "report.json").read_text())
            assert receipt["status"] == "passed"
            record(
                f"{engine} public deployment rehearsal",
                checks=len(receipt["checks"]),
                browser_checks=len(json.loads((source / "browser.json").read_text())["checks"]),
            )
        container = "sentinelflow-security-private-" + secrets.token_hex(6)
        volume = container + "-data"
        image_env = {
            **environment,
            "SENTINEL_DATABASE_URL": "sqlite:////srv/sentinelflow/data/private.sqlite3",
        }
        command("private-volume", ["docker", "volume", "create", volume])
        try:
            command(
                "private-image-start",
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    container,
                    "--network",
                    "none",
                    "--platform",
                    "linux/amd64",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--memory",
                    "768m",
                    "--cpus",
                    "2",
                    "--pids-limit",
                    "128",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,size=64m",  # noqa: S108
                    "--mount",
                    f"type=volume,source={volume},target=/srv/sentinelflow/data",
                    "--env",
                    "SENTINEL_API_TOKEN",
                    "--env",
                    "SENTINEL_DATABASE_URL",
                    "--env",
                    "SENTINEL_PUBLIC_DEMO=false",
                    args.application_image,
                ],
                env=image_env,
            )
            command(
                "private-image-ready",
                [
                    "docker",
                    "exec",
                    container,
                    "python",
                    "-c",
                    "import time,urllib.request\n"
                    "for attempt in range(60):\n"
                    " try:\n"
                    "  urllib.request.urlopen('http://127.0.0.1:8765/health',timeout=1); break\n"
                    " except OSError:\n"
                    "  time.sleep(0.5)\n"
                    "else: raise SystemExit('container did not become ready')\n",
                ],
            )
            data = json.loads(
                command(
                    "private-image-probe",
                    ["docker", "exec", container, "python", "scripts/container_security_probe.py"],
                )
            )
            assert data["status"] == "passed"
            report["private_container"] = data
            record(
                "Network-isolated image enforces kernel boundaries and exact integration flows",
                image=args.application_image,
                checks=data["checks"],
            )
        finally:
            command("private-image-cleanup", ["docker", "rm", "-f", container])
            command("private-volume-cleanup", ["docker", "volume", "rm", volume])
        assert report["source_fingerprint"] == source_fingerprint()
        report["status"] = "passed"
    except (OSError, ValueError, RuntimeError, AssertionError, subprocess.SubprocessError) as exc:
        report["status"], report["error"] = "failed", str(exc)
        raise
    finally:
        report["finished_at"] = datetime.now(UTC).isoformat()
        (output / "rehearsals.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
