"""Make-free entrypoint. Every failing child command produces a failing exit status."""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def run(command: list[str]) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelFlow project commands")
    parser.add_argument("command", choices=["install", "dev", "test", "lint", "format", "validate"])
    args = parser.parse_args()
    npm = shutil.which("npm")
    if npm is None:
        raise RuntimeError("npm is required; install Node 20.19+")
    if args.command == "install":
        if not PYTHON.exists():
            run([sys.executable, "-m", "venv", str(ROOT / ".venv")])
        run([str(PYTHON), "-m", "pip", "install", "--require-hashes", "-r", "requirements.lock"])
        run([str(PYTHON), "-m", "pip", "install", "--no-deps", "--no-build-isolation", "-e", "."])
        run([npm, "--prefix", "frontend", "ci"])
        return
    if not PYTHON.exists():
        raise RuntimeError("Virtual environment missing; run python3 scripts/manage.py install")
    if args.command in {"dev", "validate"}:
        run([str(PYTHON), f"scripts/{args.command}.py"])
    elif args.command == "test":
        run([str(PYTHON), "-m", "pytest"])
        run([npm, "--prefix", "frontend", "test"])
    elif args.command == "lint":
        run([str(PYTHON), "-m", "ruff", "check", "backend", "scripts"])
        run([str(PYTHON), "-m", "ruff", "format", "--check", "backend", "scripts"])
        run([str(PYTHON), "-m", "mypy", "backend/app"])
        run([npm, "--prefix", "frontend", "run", "lint"])
        run([npm, "--prefix", "frontend", "run", "format:check"])
        run([npm, "--prefix", "frontend", "run", "typecheck"])
    else:
        run([str(PYTHON), "-m", "ruff", "check", "--select", "I", "--fix", "backend", "scripts"])
        run([str(PYTHON), "-m", "ruff", "format", "backend", "scripts"])
        run([npm, "--prefix", "frontend", "run", "format"])


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode) from exc
