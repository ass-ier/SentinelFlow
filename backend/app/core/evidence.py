import hashlib
import os
from pathlib import Path

from app.core.config import ROOT


def source_fingerprint(root: Path = ROOT) -> str:
    paths: list[Path] = []
    for directory in (
        "backend",
        "scripts",
        "rules",
        "test-data",
        "frontend",
        "collector",
        "security",
        ".github",
    ):
        for parent, directories, files in os.walk(root / directory):
            directories[:] = [
                name
                for name in directories
                if not name.endswith(".egg-info")
                and name
                not in {
                    "node_modules",
                    "dist",
                    "__pycache__",
                    "coverage",
                    ".pytest_cache",
                    "test-results",
                    "playwright-report",
                }
            ]
            for name in files:
                path = Path(parent) / name
                if path.suffix not in {".pyc", ".log", ".webm", ".mp4"}:
                    paths.append(path)
    paths.extend(
        root / name
        for name in (
            "pyproject.toml",
            "requirements.lock",
            "requirements-runtime.lock",
            ".python-version",
            ".nvmrc",
            ".semgrepignore",
            "Makefile",
            "Dockerfile",
            "Dockerfile.backend",
            "docker-compose.yml",
            "render.yaml",
            ".env.example",
            ".env.public-demo.example",
            ".dockerignore",
            ".gitignore",
        )
    )
    digest = hashlib.sha256()
    for path in sorted(paths):
        if path.is_file():
            digest.update(str(path.relative_to(root)).encode())
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
    return digest.hexdigest()
