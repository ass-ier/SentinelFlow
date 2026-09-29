"""Networked local scans with raw receipts, explicit coverage, and fail-closed decisions."""

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import time
import tomllib
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_tools import PYTHON_TOOLS, ROOT, TOOLS, download, sha256

from app.core.evidence import source_fingerprint

CODE_SUFFIXES = {".py", ".js", ".mjs", ".ts", ".tsx", ".jsx"}
SWAGGER_VENDOR = "backend/app/static/swagger"


def save(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n")


def read(path: Path) -> Any:
    if not path.is_file() or not path.stat().st_size:
        raise RuntimeError(f"Required scanner output is missing or empty: {path}")
    return json.loads(path.read_text())


def normalized_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def lock_pins(path: Path) -> dict[str, str]:
    return {
        normalized_name(name): version
        for name, version in re.findall(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", path.read_text(), re.M)
    }


def artifact_manifest(output: Path) -> list[dict[str, Any]]:
    return [
        {
            "path": str(path.relative_to(output)),
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        for path in sorted(output.rglob("*"))
        if path.is_file()
        and "source" not in path.relative_to(output).parts
        and path.name not in {"manifest.json", "summary.json"}
    ]


def audit_python(
    data: dict[str, Any], expected: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    dependencies = data.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise RuntimeError("Python audit did not report a nonempty dependency set")
    actual = {normalized_name(package["name"]): package.get("version") for package in dependencies}
    if expected and any(actual.get(name) != version for name, version in expected.items()):
        raise RuntimeError("Python audit did not cover the exact expected lock versions")
    findings = []
    for package in dependencies:
        if package.get("skip_reason") and package["name"] != "sentinelflow":
            raise RuntimeError(f"Python audit skipped {package['name']}")
        for advisory in package.get("vulns", []):
            findings.append({"package": package["name"], "version": package["version"], **advisory})
    return findings


def audit_node(data: dict[str, Any]) -> list[dict[str, Any]]:
    if data.get("error") or not data.get("metadata", {}).get("dependencies", {}).get("total"):
        raise RuntimeError("npm audit failed or did not report dependency coverage")
    if "vulnerabilities" not in data:
        raise RuntimeError("npm audit response has no vulnerability result")
    return list(data["vulnerabilities"].values())


def audit_osv(data: dict[str, Any]) -> list[dict[str, Any]]:
    results = data.get("results", [])
    if not results or any(not result.get("packages") for result in results):
        raise RuntimeError("OSV did not report packages for every supplied lockfile")
    return [
        {
            "source": result["source"],
            "package": package["package"],
            "advisories": package["vulnerabilities"],
        }
        for result in results
        for package in result["packages"]
        if package.get("vulnerabilities")
    ]


def trivy_findings(data: dict[str, Any], *, require_os: bool = False) -> list[dict[str, Any]]:
    results = data.get("Results", [])
    if not results or not any(result.get("Packages") for result in results):
        raise RuntimeError("Trivy did not identify a nonempty package set")
    if require_os and not any(result.get("Class") == "os-pkgs" for result in results):
        raise RuntimeError("Container OS package coverage is missing")
    return [
        {"target": result["Target"], "class": result.get("Class"), **finding}
        for result in results
        for finding in result.get("Vulnerabilities", [])
    ]


def sast_key(tool: str, rule: str, path: str, code: str) -> str:
    return hashlib.sha256(f"{tool}\0{rule}\0{path}\0{code}".encode()).hexdigest()


def triage_sast(
    tool: str, data: dict[str, Any], snapshot: Path, reviews: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    if data.get("errors"):
        raise RuntimeError(f"{tool} reported parsing or scan errors")
    classified = []
    for finding in data.get("results", []):
        raw_path = Path(finding["filename"] if tool == "bandit" else finding["path"])
        path = raw_path.relative_to(snapshot) if raw_path.is_absolute() else raw_path
        relative = path.as_posix()
        source = snapshot / path
        if not source.is_file():
            raise RuntimeError(f"Cannot bind {tool} finding to source: {relative}")
        line = finding["line_number"] if tool == "bandit" else finding["start"]["line"]
        rule = finding["test_id"] if tool == "bandit" else finding["check_id"]
        severity = finding["issue_severity"] if tool == "bandit" else finding["extra"]["severity"]
        source_hash = sha256(source)
        key = sast_key(tool, rule, relative, source_hash)
        approved = reviews.get(key)
        if tool == "bandit" and rule == "B101" and relative.startswith("backend/tests/"):
            status, reason = (
                "Not applicable",
                (
                    "Pytest assertion, not production authorization. Tests are executed "
                    "without optimization; the release gate rejects disabled assertions."
                ),
            )
        elif approved and approved.get("status") in {"False positive", "Not applicable"}:
            status, reason = approved["status"], approved["reason"]
        else:
            status, reason = "Release blocker", "Requires source-bound technical review"
        classified.append(
            {
                "id": key,
                "scanner": tool,
                "rule": rule,
                "path": relative,
                "line": line,
                "severity": severity,
                "source_sha256": source_hash,
                "status": status,
                "reason": reason,
            }
        )
    return classified


def published_python_key(finding: dict[str, Any], *, history: bool, source_root: Path) -> bool:
    paths = {
        "backend/tests/security/test_release_gate.py",
        "docs/results/security/baseline/image-history.jsonl",
        "docs/results/security/baseline/image-inspect.json",
        "docs/results/security/baseline/container-trivy.json",
        "docs/results/security/final/image-backend.json",
        "docs/results/security/final/image-application.json",
        "docs/results/security/final/container-backend.json",
        "docs/results/security/final/container-application.json",
    }
    path = Path(finding.get("File", ""))
    if path.is_absolute():
        if history or not path.is_relative_to(source_root):
            return False
        path = path.relative_to(source_root)
    relative = path.as_posix()
    if (
        relative not in paths
        or finding.get("RuleID") != "generic-api-key"
        or finding.get("Match") != 'GPG_KEY=REDACTED"'
        or finding.get("StartLine") != finding.get("EndLine")
    ):
        return False
    if history:
        commit = finding.get("Commit", "")
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            return False
        text = subprocess.check_output(["git", "show", f"{commit}:{relative}"], cwd=ROOT, text=True)
    else:
        text = (source_root / relative).read_text()
    line = finding["StartLine"]
    lines = text.splitlines()
    if not 1 <= line <= len(lines):
        return False
    values = re.findall(r'GPG_KEY=([^"\\\s]+)', lines[line - 1])
    return bool(values) and set(values) == {"7169605F62C751356D054A26A821E680E5FA6305"}


def secret_triage(
    data: Any, *, history: bool, source_root: Path | None = None
) -> list[dict[str, Any]]:
    if not isinstance(data, list):
        raise RuntimeError("Gitleaks returned an invalid report")
    verified_commits = {
        "f658159093bf68572720608e033229ad47186fc8",
        "ae65f0707dc882c05d5ffd99ecff898c35c11269",
        "27d1d39bb5fb6a14baf089f7e91ba727bcd152d7",
    }
    result = []
    for finding in data:
        status, reason = "Release blocker", "Unreviewed potential credential"
        if (
            history
            and finding.get("Commit") in verified_commits
            and finding.get("File") == ".env.example"
            and finding.get("RuleID") == "generic-api-key"
            and finding.get("StartLine") == 31
            and finding.get("EndLine") == 32
        ):
            text = subprocess.check_output(
                ["git", "show", f"{finding['Commit']}:.env.example"], cwd=ROOT, text=True
            )
            lines = text.splitlines()
            if (
                lines[30] in {"SENTINEL_CLIENT_SECRET=", 'SENTINEL_CLIENT_SECRET=""'}
                and lines[31] == "SENTINEL_POLL_INTERVAL_SECONDS=60"
            ):
                status, reason = (
                    "False positive",
                    (
                        "Verified empty secret assignment followed by a numeric poll interval. "
                        "The generic rule matched across lines; no credential value is present."
                    ),
                )
        if published_python_key(finding, history=history, source_root=source_root or ROOT):
            status, reason = (
                "False positive",
                "Published CPython release-signing public-key fingerprint in image metadata "
                "or its focused regression fixture, verified against Dockerfile blob "
                "1977444e32bbbda7db8fe9dc960da1be182db7bc. Not a private key or API credential.",
            )
        result.append(
            {
                "id": finding["Fingerprint"],
                "path": finding["File"],
                "line": finding["StartLine"],
                "commit": finding.get("Commit"),
                "status": status,
                "reason": reason,
            }
        )
    return result


class Assessment:
    def __init__(self, output: Path) -> None:
        self.output = output
        self.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.started = time.monotonic()
        self.report: dict[str, Any] = {
            "status": "RUNNING",
            "started_at": datetime.now(UTC).isoformat(),
            "source_fingerprint": source_fingerprint(),
            "commit": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip(),
            "worktree_changes": subprocess.check_output(
                ["git", "status", "--porcelain"], cwd=ROOT, text=True
            ).splitlines(),
            "commands": [],
            "checks": [],
            "blockers": [],
            "dependency_findings": [],
            "live_integrations": "Not tested",
        }
        self.environment = {
            **os.environ,
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "SEMGREP_APP_TOKEN": "",
            "SEMGREP_SETTINGS_FILE": str(TOOLS / "semgrep-settings.yml"),
            "DO_NOT_TRACK": "1",
            "SYFT_CHECK_FOR_APP_UPDATE": "false",
            "NO_COLOR": "1",
            "CI": "true",
            "SENTINELFLOW_PYTHON": sys.executable,
        }
        save(self.output / "summary.json", self.report)

    def run(
        self,
        name: str,
        command: list[str],
        *,
        acceptable: tuple[int, ...] = (0,),
        json_stdout: bool = False,
        cwd: Path = ROOT,
        timeout: int = 600,
    ) -> Path:
        stdout = self.output / f"{name}.{'json' if json_stdout else 'log'}"
        stderr = self.output / f"{name}.stderr.log"
        receipt: dict[str, Any] = {
            "name": name,
            "command": command,
            "cwd": str(cwd),
            "started_at": datetime.now(UTC).isoformat(),
        }
        print(f"SECURITY {name}", flush=True)
        started = time.monotonic()
        try:
            with stdout.open("w") as output, stderr.open("w") as errors:
                process = subprocess.run(
                    command,
                    cwd=cwd,
                    env=self.environment,
                    stdout=output,
                    stderr=errors,
                    timeout=timeout,
                )
            receipt["exit_code"] = process.returncode
            if process.returncode not in acceptable:
                raise RuntimeError(f"{name} exited {process.returncode}; see {stdout.name}")
            return stdout
        except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
            receipt["error"] = str(exc)
            self.report["blockers"].append(f"{name}: {exc}")
            raise
        finally:
            receipt["finished_at"] = datetime.now(UTC).isoformat()
            receipt["duration_seconds"] = time.monotonic() - started
            receipt["stdout"] = stdout.name
            receipt["stderr"] = stderr.name
            receipt["stdout_sha256"] = sha256(stdout) if stdout.exists() else None
            self.report["commands"].append(receipt)
            save(self.output / "summary.json", self.report)

    def check(self, name: str, passed: bool, details: Any) -> None:
        self.report["checks"].append({"name": name, "passed": passed, "details": details})
        if not passed:
            self.report["blockers"].append(name)

    def snapshot(self) -> Path:
        snapshot = self.output / "source"
        snapshot.mkdir(mode=0o700)
        raw = subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
        )
        names = sorted(set(raw.decode().split("\0")) - {""})
        # Ignored real environment files are scanned locally too, never included in scan output.
        names.extend(
            path.name for path in ROOT.glob(".env*") if path.is_file() and path.name not in names
        )
        files = []
        for name in names:
            source = ROOT / name
            if not source.exists():
                continue
            if source.is_symlink() or not source.resolve().is_relative_to(ROOT):
                raise RuntimeError(f"Review source symlink before scanning: {name}")
            destination = snapshot / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            files.append({"path": name, "sha256": sha256(source), "bytes": source.stat().st_size})
        save(self.output / "source-scope.json", files)
        return snapshot

    def inventory(self) -> None:
        manifest = tomllib.loads((ROOT / "pyproject.toml").read_text())
        full = lock_pins(ROOT / "requirements.lock")
        runtime = lock_pins(ROOT / "requirements-runtime.lock")
        packages = [
            {
                "name": package.metadata["Name"],
                "version": package.version,
                "requires": package.requires or [],
                "scope": "runtime"
                if normalized_name(package.metadata["Name"]) in runtime
                else "development",
            }
            for package in importlib.metadata.distributions()
        ]
        installed = {normalized_name(item["name"]): item["version"] for item in packages}
        mismatches = {
            name: {"locked": version, "installed": installed.get(name)}
            for name, version in full.items()
            if installed.get(name) != version
        }
        extra = sorted(set(installed) - set(full) - {"sentinelflow"})
        self.check(
            "Installed Python environment exactly matches the lock",
            not mismatches and not extra,
            {"mismatches": mismatches, "extra": extra},
        )
        self.check(
            "Runtime lock is a version-consistent subset",
            bool(runtime) and all(full.get(name) == version for name, version in runtime.items()),
            {"runtime_packages": len(runtime), "all_packages": len(full)},
        )
        node = read(ROOT / "frontend/package-lock.json")
        node_manifest = read(ROOT / "frontend/package.json")
        node_packages = [
            {"path": path, **value} for path, value in node["packages"].items() if path
        ]
        unexpected_urls = [
            item["path"]
            for item in node_packages
            if item.get("resolved")
            and not item["resolved"].startswith("https://registry.npmjs.org/")
        ]
        self.check(
            "npm package artifacts use the reviewed registry", not unexpected_urls, unexpected_urls
        )
        value = {
            "python_version": sys.version,
            "python_executable": sys.executable,
            "python_direct_runtime": manifest["project"]["dependencies"],
            "python_direct_development": manifest["project"]["optional-dependencies"]["dev"],
            "python_lock": full,
            "python_runtime_lock": runtime,
            "python_installed": packages,
            "node_direct_runtime": node_manifest["dependencies"],
            "node_direct_development": node_manifest["devDependencies"],
            "node_packages": node_packages,
            "node_install_hooks": [item for item in node_packages if item.get("hasInstallScript")],
            "input_hashes": {
                path: sha256(ROOT / path)
                for path in (
                    "pyproject.toml",
                    "requirements.lock",
                    "requirements-runtime.lock",
                    "frontend/package.json",
                    "frontend/package-lock.json",
                    "security/requirements.lock",
                    "security/tools.json",
                    "Dockerfile",
                    "Dockerfile.backend",
                    ".python-version",
                    ".nvmrc",
                )
            },
        }
        recording = ROOT / ".runtime/recording/conda-meta"
        value["optional_recording_runtime"] = {
            "status": "installed" if recording.is_dir() else "not installed",
            "scope": "Optional development-only recording; absent from production images",
            "packages": [
                {
                    name: package.get(name)
                    for name in (
                        "name",
                        "version",
                        "build",
                        "channel",
                        "subdir",
                        "license",
                        "sha256",
                        "md5",
                    )
                }
                for path in sorted(recording.glob("*.json"))
                for package in [read(path)]
            ],
        }
        save(self.output / "dependency-inventory.json", value)

    def scans(self) -> None:
        self.inventory()
        self.bundled_javascript()
        spec = read(ROOT / "security/tools.json")
        versions = {}
        for name, expected in {
            **spec["python"],
            **{name: value["version"] for name, value in spec["native"].items()},
        }.items():
            executable = PYTHON_TOOLS / "bin" / name if name in spec["python"] else TOOLS / name
            flag = "version" if name == "gitleaks" else "--version"
            output = self.run(f"version-{name}", [str(executable), flag])
            versions[name] = {
                "expected": expected,
                "output": output.read_text(),
                "binary_sha256": sha256(executable),
            }
            self.check(f"Pinned {name} version", expected in output.read_text(), versions[name])
        save(self.output / "tool-versions.json", versions)
        self.run("node-version", ["node", "--version"])
        self.run("npm-version", ["npm", "--version"])
        self.run("pip-check", [sys.executable, "-m", "pip", "check"])
        pip_audit = str(PYTHON_TOOLS / "bin/pip-audit")
        for name, args in (
            ("python-lock", ["-r", "requirements.lock", "--disable-pip", "--require-hashes"]),
            (
                "python-runtime",
                ["-r", "requirements-runtime.lock", "--disable-pip", "--require-hashes"],
            ),
            ("python-installed", ["--path", sysconfig.get_paths()["purelib"]]),
            (
                "python-scanners",
                ["-r", "security/requirements.lock", "--disable-pip", "--require-hashes"],
            ),
        ):
            target = self.output / f"{name}.json"
            self.run(
                name,
                [pip_audit, *args, "--progress-spinner", "off", "-f", "json", "-o", str(target)],
                acceptable=(0, 1),
            )
            lockfile = (
                "requirements-runtime.lock"
                if name == "python-runtime"
                else "security/requirements.lock"
                if name == "python-scanners"
                else "requirements.lock"
            )
            findings = audit_python(read(target), lock_pins(ROOT / lockfile))
            self.check(f"{name}: zero known dependency findings", not findings, findings)
            self.report["dependency_findings"].extend(
                {"scanner": name, **item} for item in findings
            )
        for name, args in (("node-all", []), ("node-production", ["--omit=dev"])):
            target = self.run(
                name,
                ["npm", "audit", "--package-lock-only", "--json", *args],
                cwd=ROOT / "frontend",
                json_stdout=True,
                acceptable=(0, 1),
            )
            findings = audit_node(read(target))
            self.check(f"{name}: zero known dependency findings", not findings, findings)
            self.report["dependency_findings"].extend(
                {"scanner": name, **item} for item in findings
            )
        osv = self.output / "osv.json"
        self.run(
            "osv",
            [
                str(TOOLS / "osv-scanner"),
                "scan",
                "source",
                "--lockfile=requirements.txt:requirements.lock",
                "--lockfile=requirements.txt:requirements-runtime.lock",
                "--lockfile=frontend/package-lock.json",
                "--all-packages",
                "--all-vulns",
                "--format=json",
                f"--output-file={osv}",
            ],
            acceptable=(0, 1),
        )
        osv_findings = audit_osv(read(osv))
        self.check("OSV: zero known release dependency findings", not osv_findings, osv_findings)
        self.report["dependency_findings"].extend(
            {"scanner": "osv", **item} for item in osv_findings
        )
        snapshot = self.snapshot()
        secrets = []
        for name, arguments in (
            ("secrets-history", ["git", str(ROOT), "--log-opts=--all"]),
            ("secrets-working-tree", ["dir", str(snapshot)]),
        ):
            target = self.output / f"{name}.json"
            self.run(
                name,
                [
                    str(TOOLS / "gitleaks"),
                    *arguments,
                    "--redact=100",
                    "--ignore-gitleaks-allow",
                    "--no-banner",
                    "--report-format=json",
                    f"--report-path={target}",
                ],
                acceptable=(0, 1),
            )
            classified = secret_triage(
                read(target), history=name == "secrets-history", source_root=snapshot
            )
            secrets.extend(classified)
            self.check(
                f"{name}: no confirmed or unreviewed secret",
                all(item["status"] == "False positive" for item in classified),
                classified,
            )
        save(self.output / "secrets-triage.json", secrets)
        bandit = self.output / "bandit.json"
        self.run(
            "bandit",
            [
                str(PYTHON_TOOLS / "bin/bandit"),
                "-r",
                "backend",
                "scripts",
                "collector",
                "--ignore-nosec",
                "-f",
                "json",
                "-o",
                str(bandit),
            ],
            cwd=snapshot,
            acceptable=(0, 1),
        )
        python_paths = {
            str(path.relative_to(snapshot))
            for directory in ("backend", "scripts", "collector")
            for path in (snapshot / directory).rglob("*.py")
            if path.stat().st_size
        }
        measured = {str(Path(name)) for name in read(bandit).get("metrics", {})}
        self.check(
            "Bandit covers every nonempty first-party Python file",
            not (python_paths - measured),
            {"expected": len(python_paths), "missing": sorted(python_paths - measured)},
        )
        rules = self.output / "semgrep-rules"
        rules.mkdir()
        config_args = []
        for name in spec["semgrep_packs"]:
            target = rules / f"{name}.yaml"
            download(f"https://semgrep.dev/c/p/{name}", target, limit=16 * 1024 * 1024)
            config_args.extend(["--config", str(target)])
        semgrep = self.output / "semgrep.json"
        self.run(
            "semgrep",
            [
                str(PYTHON_TOOLS / "bin/semgrep"),
                "scan",
                "--metrics=off",
                "--disable-version-check",
                "--oss-only",
                "--no-git-ignore",
                "--disable-nosem",
                "--no-rewrite-rule-ids",
                "--exclude",
                SWAGGER_VENDOR,
                "--strict",
                "--error",
                *config_args,
                "--json",
                "--output",
                str(semgrep),
                "backend",
                "scripts",
                "collector",
                "frontend",
            ],
            cwd=snapshot,
            acceptable=(0, 1),
        )
        expected = {
            str(path.relative_to(snapshot))
            for directory in ("backend", "scripts", "collector", "frontend")
            for path in (snapshot / directory).rglob("*")
            if path.is_file()
            and path.suffix in CODE_SUFFIXES
            and path.stat().st_size
            and not path.is_relative_to(snapshot / SWAGGER_VENDOR)
        }
        scanned = set(read(semgrep).get("paths", {}).get("scanned", []))
        self.check(
            "Semgrep covers every nonempty first-party code file",
            not (expected - scanned),
            {
                "expected": len(expected),
                "scanned": len(scanned),
                "missing": sorted(expected - scanned),
            },
        )
        review_items = read(ROOT / "security/sast-reviews.json")["reviews"]
        reviews = {
            sast_key(item["scanner"], rule, item["path"], item["source_sha256"]): item
            for item in review_items
            for rule in item["rules"]
        }
        findings = []
        for name, target in (("bandit", bandit), ("semgrep", semgrep)):
            classified = triage_sast(name, read(target), snapshot, reviews)
            findings.extend(classified)
            self.check(
                f"{name}: no confirmed or unreviewed finding",
                all(item["status"] != "Release blocker" for item in classified),
                {
                    "raw": len(classified),
                    "statuses": dict(Counter(item["status"] for item in classified)),
                },
            )
        save(self.output / "sast-triage.json", findings)
        fs = self.output / "filesystem-trivy.json"
        self.run(
            "filesystem-trivy",
            [
                str(TOOLS / "trivy"),
                "fs",
                "--quiet",
                "--cache-dir",
                str(TOOLS / "trivy-cache"),
                "--scanners",
                "vuln,misconfig",
                "--include-dev-deps",
                "--format",
                "json",
                "--output",
                str(fs),
                str(snapshot),
            ],
        )
        file_findings = trivy_findings(read(fs))
        self.check(
            "Filesystem dependency scan: zero known findings", not file_findings, file_findings
        )
        misconfigurations = [
            {"target": result["Target"], **finding}
            for result in read(fs).get("Results", [])
            for finding in result.get("Misconfigurations", [])
        ]
        self.check(
            "No unresolved filesystem misconfiguration", not misconfigurations, misconfigurations
        )
        self.sbom_and_images()

    def bundled_javascript(self) -> None:
        self.run("swagger-integrity", [sys.executable, "scripts/vendor_swagger.py", "--check"])
        scanner = ROOT / "frontend/node_modules/retire/lib/cli.js"
        version = self.run("version-retire", ["node", str(scanner), "--version"])
        expected = read(ROOT / "security/tools.json")["node"]["retire"]
        self.check(
            "Pinned Retire.js version",
            version.read_text().strip() == expected,
            version.read_text().strip(),
        )
        repository = self.output / "retire-advisories.json"
        url = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json"
        download(url, repository, limit=16 * 1024 * 1024)
        save(
            self.output / "retire-database.json",
            {
                "source": url,
                "retrieved_at": datetime.now(UTC).isoformat(),
                "sha256": sha256(repository),
            },
        )
        identified = []
        for name, directory in (
            ("retire-swagger", ROOT / SWAGGER_VENDOR),
            ("retire-frontend", ROOT / "frontend/dist"),
        ):
            if not directory.is_dir() or not list(directory.rglob("*.js")):
                raise RuntimeError(f"No shipped JavaScript to scan: {directory}")
            target = self.output / f"{name}.json"
            self.run(
                name,
                [
                    "node",
                    str(scanner),
                    "--path",
                    str(directory),
                    "--jsrepo",
                    str(repository),
                    "--nocache",
                    "--verbose",
                    "--deep",
                    "--outputformat",
                    "json",
                    "--outputpath",
                    str(target),
                    "--exitwith",
                    "1",
                ],
                acceptable=(0, 1),
            )
            data = read(target)
            if data.get("errors"):
                raise RuntimeError(f"{name} did not complete: {data['errors']}")
            results = [
                {"file": row["file"], **result}
                for row in data.get("data", [])
                for result in row.get("results", [])
            ]
            findings = [result for result in results if result.get("vulnerabilities")]
            self.check(f"{name}: zero known bundled JavaScript findings", not findings, findings)
            self.report["dependency_findings"].extend(
                {"scanner": name, **item} for item in findings
            )
            identified.extend(results)
        self.check(
            "Retire.js identifies the bundled HTML sanitizer",
            any(item["component"] == "DOMPurify" for item in identified),
            {"identified": len(identified)},
        )
        self.report["bundled_components"] = identified

    def sbom_and_images(self) -> None:
        trivy = [
            str(TOOLS / "trivy"),
            "image",
            "--quiet",
            "--cache-dir",
            str(TOOLS / "trivy-cache"),
            "--image-src",
            "docker",
            "--scanners",
            "vuln",
            "--format",
            "json",
        ]
        all_components: dict[str, dict[str, Any]] = {}
        node_sbom = self.run(
            "node-sbom",
            ["npm", "sbom", "--sbom-format", "cyclonedx", "--package-lock-only"],
            cwd=ROOT / "frontend",
            json_stdout=True,
        )
        python_sbom = self.output / "python-sbom.cdx.json"
        self.run(
            "python-sbom",
            [
                str(TOOLS / "syft"),
                "scan",
                "dir:" + sysconfig.get_paths()["purelib"],
                "--select-catalogers",
                "python",
                "-o",
                "cyclonedx-json=" + str(python_sbom),
            ],
        )
        sboms = [node_sbom, python_sbom]
        installed = self.output / "installed-sbom-trivy.json"
        self.run(
            "installed-sbom-trivy",
            [
                str(TOOLS / "trivy"),
                "sbom",
                "--quiet",
                "--cache-dir",
                str(TOOLS / "trivy-cache"),
                "--format",
                "json",
                "--output",
                str(installed),
                str(python_sbom),
            ],
        )
        installed_findings = trivy_findings(read(installed))
        self.check(
            "Installed-package SBOM scan: zero known findings",
            not installed_findings,
            installed_findings,
        )
        self.report["images"] = []
        if os.getenv("DOCKER_HOST") and not os.environ["DOCKER_HOST"].startswith("unix://"):
            raise RuntimeError("Refusing a non-local Docker endpoint")
        endpoint = self.run(
            "docker-endpoint",
            ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
            json_stdout=True,
        )
        if not read(endpoint).startswith("unix://"):
            raise RuntimeError("Refusing a non-local Docker context")
        for name, dockerfile in (("backend", "Dockerfile.backend"), ("application", "Dockerfile")):
            image = f"sentinelflow-security:{name}"
            self.run(
                f"build-{name}",
                [
                    "docker",
                    "build",
                    "--platform",
                    "linux/amd64",
                    "-f",
                    dockerfile,
                    "--label",
                    "org.opencontainers.image.revision=" + self.report["commit"],
                    "--label",
                    "org.sentinelflow.source-fingerprint=" + self.report["source_fingerprint"],
                    "-t",
                    image,
                    ".",
                ],
                timeout=1200,
            )
            inspection = self.run(
                f"image-{name}", ["docker", "image", "inspect", image], json_stdout=True
            )
            info = read(inspection)[0]
            self.report["images"].append(
                {
                    "name": image,
                    "id": info["Id"],
                    "architecture": info["Architecture"],
                    "source_fingerprint": self.report["source_fingerprint"],
                }
            )
            target = self.output / f"container-{name}.json"
            self.run(f"scan-{name}", [*trivy, "--output", str(target), info["Id"]])
            findings = trivy_findings(read(target), require_os=True)
            counts = Counter(item["Severity"] for item in findings)
            self.check(
                f"{name}: no known container dependency findings", not findings, dict(counts)
            )
            self.report["dependency_findings"].extend(
                {"scanner": f"container-{name}", **item} for item in findings
            )
            bom = self.output / f"container-{name}.cdx.json"
            self.run(
                f"sbom-{name}",
                [
                    str(TOOLS / "syft"),
                    "scan",
                    "docker:" + info["Id"],
                    "-o",
                    "cyclonedx-json=" + str(bom),
                ],
            )
            sboms.append(bom)
        for path in sboms:
            components = read(path).get("components", [])
            if not components:
                raise RuntimeError(f"SBOM component inventory is empty: {path.name}")
            for component in components:
                if component.get("type") == "file":
                    continue
                identifier = component.get("purl") or component.get("bom-ref")
                if not identifier:
                    raise RuntimeError("SBOM component lacks an identity")
                all_components[identifier] = {
                    **component,
                    "bom-ref": identifier,
                    "properties": [
                        *component.get("properties", []),
                        {"name": "sentinelflow:evidence", "value": path.name},
                    ],
                }
        for item in self.report.get("bundled_components", []):
            identifier = f"bundled:{item['component']}@{item['version']}"
            all_components[identifier] = {
                "type": "library",
                "bom-ref": identifier,
                "name": item["component"],
                "version": item["version"],
                "properties": [{"name": "sentinelflow:evidence", "value": "retire-*.json"}],
            }
        inventory = read(self.output / "dependency-inventory.json")
        for package in inventory["optional_recording_runtime"]["packages"]:
            identifier = f"recording:{package['name']}@{package['version']}:{package['build']}"
            all_components[identifier] = {
                "type": "library",
                "bom-ref": identifier,
                "name": package["name"],
                "version": package["version"],
                "properties": [
                    {"name": "sentinelflow:scope", "value": "optional-development-recording"},
                    {"name": "sentinelflow:evidence", "value": "dependency-inventory.json"},
                ],
            }
        save(
            self.output / "sbom.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "metadata": {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "component": {
                        "type": "application",
                        "name": "SentinelFlow",
                        "version": "0.1.0",
                        "properties": [
                            {
                                "name": "source_fingerprint",
                                "value": self.report["source_fingerprint"],
                            }
                        ],
                    },
                },
                "components": list(all_components.values()),
            },
        )
        metadata = read(TOOLS / "trivy-cache/db/metadata.json")
        updated = datetime.fromisoformat(metadata["UpdatedAt"].replace("Z", "+00:00"))
        self.check(
            "Trivy advisory database is no older than 48 hours",
            0 <= (datetime.now(UTC) - updated).total_seconds() <= 48 * 3600,
            metadata,
        )
        save(self.output / "advisory-database.json", metadata)

    def finish(self) -> dict[str, Any]:
        self.check(
            "Source unchanged during assessment",
            self.report["source_fingerprint"] == source_fingerprint(),
            source_fingerprint(),
        )
        self.report["finished_at"] = datetime.now(UTC).isoformat()
        self.report["duration_seconds"] = time.monotonic() - self.started
        self.report["status"] = "BLOCKED" if self.report["blockers"] else "PASS"
        save(self.output / "manifest.json", artifact_manifest(self.output))
        self.report["manifest_sha256"] = sha256(self.output / "manifest.json")
        save(self.output / "summary.json", self.report)
        print(self.report["status"], self.output / "summary.json", flush=True)
        return self.report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts/security"):
        raise ValueError("Assessment output must be a new directory under artifacts/security")
    if sys.flags.optimize:
        raise RuntimeError("Security checks require enabled Python assertions")
    assessment = Assessment(output)
    try:
        assessment.scans()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        assessment.report["blockers"].append(f"Incomplete scan: {exc}")
    assessment.report["scope"] = "Scans only; full release also requires security_release.py"
    return 0 if assessment.finish()["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
