import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]


def require_free(port: int) -> None:
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as exc:
            raise RuntimeError(
                f"Port {port} is occupied. Set SENTINEL_BACKEND_PORT/SENTINEL_FRONTEND_PORT; "
                "no existing process will be stopped."
            ) from exc


def main() -> int:
    load_dotenv(ROOT / ".env")
    backend = int(os.getenv("SENTINEL_BACKEND_PORT", "8765"))
    frontend = int(os.getenv("SENTINEL_FRONTEND_PORT", "5173"))
    require_free(backend)
    require_free(frontend)
    node = shutil.which("node")
    if node is None:
        raise RuntimeError("Node.js is missing; install Node 24.21+ LTS")
    vite = ROOT / "frontend" / "node_modules" / "vite" / "bin" / "vite.js"
    if not vite.exists():
        raise RuntimeError("Frontend dependencies are missing; run make install")
    commands = [
        (
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(backend),
                "--reload",
                "--reload-dir",
                "backend",
            ],
            ROOT,
        ),
        (
            [node, str(vite), "--host", "127.0.0.1", "--port", str(frontend), "--strictPort"],
            ROOT / "frontend",
        ),
    ]
    children: list[subprocess.Popen[bytes]] = []

    def interrupt(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    try:
        for command, cwd in commands:
            children.append(subprocess.Popen(command, cwd=cwd))
        print(
            f"SentinelFlow: http://127.0.0.1:{frontend} | API: http://127.0.0.1:{backend}",
            flush=True,
        )
        while all(child.poll() is None for child in children):
            time.sleep(0.2)
        return next((child.returncode for child in children if child.returncode), 1)
    except KeyboardInterrupt:
        return 0
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == "__main__":
    raise SystemExit(main())
