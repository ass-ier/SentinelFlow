"""Install repository-pinned local scanners; no source is sent to hosted analysis services."""

import hashlib
import json
import os
import platform
import subprocess
import sys
import tarfile
import urllib.request
import venv
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "artifacts/security/tools"
PYTHON_TOOLS = TOOLS / "python-release"


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def download(url: str, target: Path, *, limit: int = 256 * 1024 * 1024) -> None:
    if not url.startswith(
        (
            "https://github.com/",
            "https://semgrep.dev/c/p/",
            "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/",
        )
    ):
        raise ValueError("Scanner downloads must use an approved HTTPS publisher")
    staging = target.with_name(target.name + ".partial")
    try:
        with urllib.request.urlopen(url, timeout=120) as response, staging.open("wb") as stream:  # noqa: S310
            size = 0
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > limit:
                    raise RuntimeError("Scanner download exceeded its size limit")
                stream.write(chunk)
        staging.replace(target)
    finally:
        staging.unlink(missing_ok=True)


def install() -> None:
    if sys.version_info < (3, 13, 15):
        raise RuntimeError("Use patched Python 3.13.15+ for security tooling")
    spec = json.loads((ROOT / "security/tools.json").read_text())
    platform_key = f"{platform.system()}-{platform.machine().lower()}"
    if platform_key not in {"Darwin-arm64", "Linux-x86_64"}:
        raise RuntimeError(
            f"Pinned native scanner assets are not configured for {platform_key}; "
            "use a supported macOS ARM64 or Linux x86_64 assessment host"
        )
    TOOLS.mkdir(parents=True, exist_ok=True)
    downloads = TOOLS / "downloads"
    downloads.mkdir(exist_ok=True)
    receipt = {
        "created_at": datetime.now(UTC).isoformat(),
        "platform": platform_key,
        "python_runtime": sys.version,
        "python_lock_sha256": sha256(ROOT / "security/requirements.lock"),
        "native": [],
    }
    for name, details in spec["native"].items():
        asset, expected = details["assets"][platform_key]
        archive = downloads / asset
        url = (
            f"https://github.com/{details['repository']}/releases/download/"
            f"v{details['version']}/{asset}"
        )
        if not archive.exists():
            download(url, archive)
        if sha256(archive) != expected:
            raise RuntimeError(f"Checksum mismatch for {name}; refusing to execute the download")
        if asset.endswith(".tar.gz"):
            with tarfile.open(archive) as package:
                members = [
                    member
                    for member in package.getmembers()
                    if member.isfile() and Path(member.name).name == name
                ]
                if len(members) != 1:
                    raise RuntimeError(f"Expected exactly one {name} executable")
                member = package.extractfile(members[0])
                if member is None:
                    raise RuntimeError(f"Missing executable bytes for {name}")
                with member:
                    binary = member.read(256 * 1024 * 1024 + 1)
        else:
            binary = archive.read_bytes()
        if len(binary) > 256 * 1024 * 1024:
            raise RuntimeError(f"Executable size limit exceeded for {name}")
        destination = TOOLS / name
        destination.write_bytes(binary)
        destination.chmod(0o755)
        receipt["native"].append(
            {
                "name": name,
                "version": details["version"],
                "publisher_url": url,
                "download_sha256": expected,
                "binary_sha256": sha256(destination),
            }
        )
    python = PYTHON_TOOLS / "bin/python"
    if not python.exists():
        venv.EnvBuilder(with_pip=True).create(PYTHON_TOOLS)
    environment = {
        **os.environ,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_INDEX_URL": "https://pypi.org/simple",
        "PIP_EXTRA_INDEX_URL": "",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_NO_INPUT": "1",
    }
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--quiet",
            "--require-hashes",
            "-r",
            str(ROOT / "security/requirements.lock"),
        ],
        check=True,
        env=environment,
        timeout=600,
    )
    subprocess.run([str(python), "-m", "pip", "check"], check=True, timeout=60)
    (TOOLS / "provenance.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"Pinned local scanners installed in {TOOLS.relative_to(ROOT)}")


if __name__ == "__main__":
    install()
