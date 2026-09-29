"""Local production rehearsal; never contacts a deployment provider or the existing demo."""

import argparse
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.config import PUBLIC_DEMO_FILENAME, ROOT
from app.core.evidence import source_fingerprint


def command(
    args: list[str], log: Path, *, env: dict[str, str] | None = None, timeout: float = 600
) -> str:
    with log.open("a+") as handle:
        handle.write("$ " + " ".join(args) + "\n")
        handle.flush()
        start = handle.tell()
        result = subprocess.run(
            args,
            cwd=ROOT,
            env=env,
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        handle.seek(start)
        output = handle.read()
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}); inspect {log.relative_to(ROOT)}")
    return output.strip()


def available_port(port: int) -> None:
    if not 1024 <= port <= 65535:
        raise ValueError("Rehearsal ports must be between 1024 and 65535")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", port))


def request(
    url: str,
    body: dict[str, Any] | None = None,
    *,
    method: str | None = None,
    headers: dict[str, str] | None = None,
    status: int = 200,
    timeout: float = 60,
) -> Any:
    req = urllib.request.Request(  # noqa: S310 - only local, constructed rehearsal URLs.
        url,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", **(headers or {})},
        method=method or ("POST" if body is not None else "GET"),
    )
    try:
        response = urllib.request.urlopen(req, timeout=timeout)  # noqa: S310
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        content = response.read()
        if response.status != status:
            raise RuntimeError(f"{url}: HTTP {response.status}; expected {status}")
        if "application/json" in response.headers.get("Content-Type", ""):
            return json.loads(content)
        return content.decode()


def wait_ready(process: subprocess.Popen[str], url: str) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Rehearsal process exited during startup; inspect its log")
        try:
            request(url, timeout=2)
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            time.sleep(0.15)
        else:
            return
    raise TimeoutError(f"Rehearsal startup did not become ready: {url}")


def stop(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def main() -> None:
    if sys.flags.optimize:
        raise RuntimeError("Deployment verification requires enabled Python assertions")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--label", required=True, help="A new lowercase name under artifacts/deployment"
    )
    parser.add_argument("--backend-port", type=int, default=18865)
    parser.add_argument("--frontend-port", type=int, default=18875)
    parser.add_argument(
        "--docker", action="store_true", help="Actually build/run Dockerfile.backend"
    )
    parser.add_argument(
        "--image-id", help="Reuse an immutable, source-labeled local security image"
    )
    parser.add_argument(
        "--keep-running",
        action="store_true",
        help="Keep verified servers attached until interrupted",
    )
    args = parser.parse_args()
    if args.image_id and (
        not args.docker or not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image_id)
    ):
        raise ValueError("--image-id requires --docker and an immutable SHA-256 image ID")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,48}", args.label):
        raise ValueError("Use a lowercase alphanumeric rehearsal label with optional hyphens")
    available_port(args.backend_port)
    available_port(args.frontend_port)
    if args.backend_port == args.frontend_port:
        raise ValueError("Backend and frontend ports must be different")
    fingerprint = source_fingerprint()
    validation = json.loads((ROOT / "artifacts/validation.json").read_text())
    if (
        validation.get("status") != "validated"
        or validation.get("source_fingerprint") != fingerprint
    ):
        raise RuntimeError("Run make validate for the current source before production rehearsal")
    output = ROOT / "artifacts" / "deployment" / args.label
    output.mkdir(parents=True, exist_ok=False)
    log = output / "commands.log"
    base, ui = f"http://127.0.0.1:{args.backend_port}", f"http://127.0.0.1:{args.frontend_port}"
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("SENTINEL_", "VITE_", "RENDER_")) and key not in {"PORT", "VERCEL"}
    }
    owner = secrets.token_urlsafe(32)
    backend_env = {
        **env,
        "PORT": str(args.backend_port),
        "SENTINEL_PUBLIC_DEMO": "true",
        "SENTINEL_DATABASE_URL": f"sqlite:///{output / 'database' / PUBLIC_DEMO_FILENAME}",
        "SENTINEL_ALLOWED_HOSTS": "127.0.0.1,localhost",
        "SENTINEL_ALLOWED_ORIGINS": ui,
        "SENTINEL_API_TOKEN": owner,
    }
    checks: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "status": "failed",
        "started_at": datetime.now(UTC).isoformat(),
        "source_fingerprint": fingerprint,
        "engine": "docker" if args.docker else "native",
        "ui": ui,
        "api": base,
        "checks": checks,
        "external_deployment": "Not attempted or verified",
    }

    def record(name: str, **details: Any) -> None:
        checks.append({"name": name, "status": "passed", **details})
        print("PASS", name, flush=True)

    docker = ["docker"]
    container = "sentinelflow-check-" + secrets.token_hex(6)
    volume = container + "-data"
    image = args.image_id or "sentinelflow-deployment:" + args.label
    backend_command = [sys.executable, "scripts/serve.py"]
    process: subprocess.Popen[str] | None = None
    created_volume = False
    stop_event = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())

    try:
        command(
            [
                "npm",
                "--prefix",
                "frontend",
                "run",
                "build",
                "--",
                "--outDir",
                str(output / "frontend"),
            ],
            log,
            env={**env, "VITE_API_BASE_URL": base},
        )
        record("Production frontend built with an explicit independent API origin")
        if args.docker:
            if os.getenv("DOCKER_HOST") and not os.environ["DOCKER_HOST"].startswith("unix://"):
                raise RuntimeError("Refusing a non-local Docker endpoint")
            endpoint = command(
                [
                    "docker",
                    "context",
                    "inspect",
                    "--format",
                    "{{json .Endpoints.docker.Host}}",
                ],
                log,
            )
            if not json.loads(endpoint).startswith("unix://"):
                raise RuntimeError("Refusing a non-local Docker endpoint")
            if args.image_id:
                bound = command(
                    docker
                    + [
                        "image",
                        "inspect",
                        image,
                        "--format",
                        '{{index .Config.Labels "org.sentinelflow.source-fingerprint"}}',
                    ],
                    log,
                )
                if bound != fingerprint:
                    raise RuntimeError("The supplied image was not built from the validated source")
            else:
                command(
                    docker
                    + [
                        "build",
                        "--platform",
                        "linux/amd64",
                        "-f",
                        "Dockerfile.backend",
                        "-t",
                        image,
                        ".",
                    ],
                    log,
                )
            report["image_id"] = command(
                docker + ["image", "inspect", image, "--format", "{{.Id}}"], log
            )
            command(
                docker
                + ["volume", "create", "--label", "sentinelflow.local-verification=true", volume],
                log,
            )
            created_volume = True
            backend_env["SENTINEL_DATABASE_URL"] = (
                "sqlite:////srv/sentinelflow/data/" + PUBLIC_DEMO_FILENAME
            )
            backend_command = docker + [
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "--name",
                container,
                "--label",
                "sentinelflow.local-verification=true",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=64m",  # noqa: S108 - isolated container tmpfs, not host storage.
                "--tmpfs",
                "/srv/sentinelflow/artifacts:rw,noexec,nosuid,uid=10001,gid=10001,size=32m",
                "--pids-limit",
                "128",
                "--memory",
                "768m",
                "--cpus",
                "2",
                "-p",
                f"127.0.0.1:{args.backend_port}:{args.backend_port}",
                "-v",
                f"{volume}:/srv/sentinelflow/data",
            ]
            for key in (
                "PORT",
                "SENTINEL_PUBLIC_DEMO",
                "SENTINEL_DATABASE_URL",
                "SENTINEL_ALLOWED_HOSTS",
                "SENTINEL_ALLOWED_ORIGINS",
                "SENTINEL_API_TOKEN",
            ):
                backend_command.extend(["--env", key])
            backend_command.append(image)
            record(
                "Validated immutable backend image selected"
                if args.image_id
                else "Backend Docker image actually built",
                image_id=report["image_id"],
                platform="linux/amd64",
            )

        with ExitStack() as stack:
            backend_log = stack.enter_context((output / "backend.log").open("a"))
            frontend_log = stack.enter_context((output / "frontend.log").open("a"))

            def start_backend() -> subprocess.Popen[str]:
                nonlocal process
                process = subprocess.Popen(
                    backend_command,
                    cwd=ROOT,
                    env=backend_env,
                    text=True,
                    stdout=backend_log,
                    stderr=subprocess.STDOUT,
                )
                wait_ready(process, base + "/health")
                return process

            def stop_backend() -> None:
                if process is not None and process.poll() is None:
                    if args.docker:
                        command(docker + ["stop", "--time", "15", container], log)
                        process.wait(timeout=20)
                    else:
                        stop(process)

            stack.callback(stop_backend)
            process = start_backend()
            health = request(base + "/health")
            assert health["public_demo"] and not health["auth_required"]
            record(
                "Production backend starts on PORT with a credential-free health endpoint",
                health=health,
            )
            dashboard = request(base + "/api/dashboard")
            assert (
                dashboard["events_processed"],
                dashboard["total_alerts"],
                dashboard["runs"],
            ) == (56, 7, 1)
            record(
                "Runtime schema initialization and exact deterministic seed", events=56, alerts=7
            )
            assert "SwaggerUIBundle" in request(base + "/docs")
            assert request(base + "/openapi.json")["info"]["title"] == "SentinelFlow"
            assert "<svg" in request(base + "/favicon.svg")
            record("Backend-only Swagger, OpenAPI, and favicon respond")
            request(
                base + "/api/detections/validate",
                {"dataset_id": "auth-normal-failures"},
                headers={"Origin": "https://untrusted.example.test"},
                status=403,
            )
            request(base + "/health", headers={"Host": "untrusted.example.test"}, status=400)
            preflight = urllib.request.Request(  # noqa: S310 - constructed loopback URL.
                base + "/api/detections/validate",
                method="OPTIONS",
                headers={
                    "Origin": ui,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type",
                },
            )
            with urllib.request.urlopen(preflight, timeout=10) as response:  # noqa: S310
                assert response.headers["Access-Control-Allow-Origin"] == ui
            record("Explicit cross-origin preflight succeeds; wrong origins and hosts are rejected")
            public_validation = request(base + "/api/detections/validate", {})
            assert (
                public_validation["passed"],
                public_validation["failed"],
                public_validation["total"],
            ) == (49, 0, 49)
            assert (public_validation["benign_passed"], public_validation["benign_total"]) == (
                14,
                14,
            )
            record(
                "Public validation executes every synthetic scenario in isolation",
                scenarios=49,
                benign=14,
            )
            frontend = subprocess.Popen(
                [
                    shutil.which("node") or "node",
                    "frontend/node_modules/vite/bin/vite.js",
                    "preview",
                    "--config",
                    "frontend/vite.config.ts",
                    "--outDir",
                    str(output / "frontend"),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(args.frontend_port),
                ],
                cwd=ROOT,
                env={**env, "VITE_API_BASE_URL": base},
                stdout=frontend_log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            stack.callback(stop, frontend)
            wait_ready(frontend, ui + "/")
            print(f"PRODUCTION PREVIEW {ui} API {base}", flush=True)
            command(
                ["node", "scripts/browser_deployment.mjs"],
                log,
                timeout=180,
                env={
                    **env,
                    "SENTINEL_UI_URL": ui,
                    "SENTINEL_API_URL": base,
                    "SENTINEL_DEPLOYMENT_ARTIFACTS": str(output),
                },
            )
            browser = json.loads((output / "browser.json").read_text())
            assert browser["status"] == "passed"
            record(
                "Real production-build desktop/mobile browser workflows",
                checks=len(browser["checks"]),
            )
            before = request(base + "/dashboard")
            runs_before = request(base + "/runs")
            assert (before["events_processed"], before["total_alerts"], before["runs"]) == (
                89,
                10,
                4,
            )
            evidence_id = request(base + "/alerts")["items"][0]["id"]
            evidence_before = request(base + "/alerts/" + evidence_id)
            stop_backend()
            process = start_backend()
            after = request(base + "/dashboard")
            for key in ("events_processed", "total_alerts", "runs", "detection_rules"):
                assert after[key] == before[key]
            assert request(base + "/runs") == runs_before
            assert request(base + "/alerts/" + evidence_id) == evidence_before
            record(
                "Restart preserves events, alerts, run IDs, and exact evidence",
                events=after["events_processed"],
                alerts=after["total_alerts"],
                runs=after["runs"],
            )
            reset_body = {"confirmation": "RESET DEMO", "seed": True}
            rejected = request(base + "/admin/demo-reset", reset_body, status=403)
            assert rejected["error"]["code"] == "public_demo_restricted"
            request(
                base + "/admin/demo-reset", reset_body, headers={"Authorization": "Bearer " + owner}
            )
            reset = request(base + "/dashboard")
            assert (reset["events_processed"], reset["total_alerts"], reset["runs"]) == (56, 7, 1)
            record(
                "Visitor reset denied; operator reset restores the known demo state",
                events=56,
                alerts=7,
            )
            if args.docker:
                user = command(docker + ["exec", container, "id", "-u"], log)
                assert user == "10001"
                runtime = json.loads(
                    command(
                        docker + ["inspect", container, "--format", "{{json .HostConfig}}"], log
                    )
                )
                assert runtime["ReadonlyRootfs"]
                assert runtime["CapDrop"] == ["ALL"]
                assert runtime["PidsLimit"] == 128
                assert runtime["Memory"] == 768 * 1024 * 1024
                assert runtime["NanoCpus"] == 2_000_000_000
                assert not runtime["Privileged"]
                assert runtime["NetworkMode"] != "host"
                assert all("/docker.sock" not in value for value in runtime.get("Binds", []))
                record(
                    "Container enforces read-only root, dropped capabilities and resource bounds",
                    host_config=runtime,
                )
                deadline = time.monotonic() + 35
                state = ""
                while state != "healthy" and time.monotonic() < deadline:
                    state = command(
                        docker + ["inspect", container, "--format", "{{.State.Health.Status}}"], log
                    )
                    if state != "healthy":
                        time.sleep(1)
                assert state == "healthy"
                record("Container runs non-root and passes its actual Docker healthcheck", uid=user)
            else:
                backend_log.flush()
                assert (
                    f"Uvicorn running on http://0.0.0.0:{args.backend_port}"
                    in (output / "backend.log").read_text()
                )
                record("Live ASGI startup confirms 0.0.0.0 binding on the selected PORT")
            if source_fingerprint() != fingerprint:
                raise RuntimeError("Source changed during rehearsal; rerun with a fresh label")
            report["status"] = "passed"
            report["completed_at"] = datetime.now(UTC).isoformat()
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            print(
                json.dumps(
                    {"status": "passed", "report": str(output.relative_to(ROOT) / "report.json")}
                ),
                flush=True,
            )
            if args.keep_running:
                print(
                    "Verified servers remain attached; "
                    "interrupt this verifier to stop only its processes.",
                    flush=True,
                )
                stop_event.wait()
    finally:
        if sys.exc_info()[0] is not None:
            report["status"] = "failed"
        try:
            if created_volume:
                command(docker + ["volume", "rm", volume], log)
        finally:
            if sys.exc_info()[0] is not None:
                report["status"] = "failed"
            report.setdefault("completed_at", datetime.now(UTC).isoformat())
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
