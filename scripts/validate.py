"""Execute comprehensive validation, retain actual output, and never reuse stale receipts."""

import json
import os
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from defusedxml.ElementTree import parse

from app.core.config import ROOT
from app.core.evidence import source_fingerprint

ARTIFACTS = ROOT / "artifacts"


def save_json(path: Path, value: Any) -> None:
    staging = path.with_suffix(path.suffix + ".tmp")
    staging.write_text(json.dumps(value, indent=2) + "\n")
    staging.replace(path)


def acquire_lock() -> Path:
    lock = ARTIFACTS / "validation-running.json"
    if lock.exists():
        state = json.loads(lock.read_text())
        try:
            os.kill(state["pid"], 0)
        except ProcessLookupError:
            lock.unlink()
        else:
            raise RuntimeError("Another validation process is active")
    descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        json.dump({"pid": os.getpid(), "started_at": datetime.now(UTC).isoformat()}, handle)
    return lock


def execute(name: str, command: list[str], report: dict[str, Any], log: TextIO) -> None:
    heading = "\n" + "=" * 72 + f"\n{name}\n$ {' '.join(command)}\n" + "=" * 72 + "\n"
    print(heading, end="", flush=True)
    log.write(heading)
    log.flush()
    started = time.perf_counter()
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env={**os.environ, "NO_COLOR": "1", "CI": "true"},
    )
    assert process.stdout is not None
    for line in process.stdout:
        print(line, end="", flush=True)
        log.write(line)
        log.flush()
    code = process.wait()
    report["steps"].append(
        {
            "name": name,
            "command": command,
            "exit_code": code,
            "status": "passed" if code == 0 else "failed",
            "duration_seconds": time.perf_counter() - started,
        }
    )
    if code != 0:
        raise RuntimeError(f"{name} failed with exit status {code}")


def junit_results(path: Path) -> dict[str, Any]:
    root = parse(path, forbid_dtd=True, forbid_entities=True, forbid_external=True).getroot()
    cases = list(root.iter("testcase"))
    categories: dict[str, dict[str, int]] = {}
    failed = skipped = 0
    for case in cases:
        failure = case.find("failure") is not None or case.find("error") is not None
        skip = case.find("skipped") is not None
        failed += failure
        skipped += skip
        for property in case.findall("./properties/property"):
            if property.get("name") != "categories":
                continue
            for category in property.get("value", "").split(","):
                values = categories.setdefault(category, {"total": 0, "passed": 0, "failed": 0})
                values["total"] += 1
                values["failed"] += failure or skip
                values["passed"] += not (failure or skip)
    if not cases or failed or skipped:
        raise RuntimeError("Backend report is empty or contains failed/skipped tests")
    for required in (
        "unit",
        "parser",
        "detection",
        "negative",
        "integration",
        "replay",
        "sigma",
        "regression",
        "security",
        "connectors",
        "notifications",
        "migration",
        "end_to_end",
    ):
        if required not in categories or categories[required]["total"] == 0:
            raise RuntimeError(f"Required test category has no executed tests: {required}")
    return {
        "total": len(cases),
        "passed": len(cases) - failed - skipped,
        "failed": failed,
        "skipped": skipped,
        "categories": categories,
    }


def main() -> int:
    if sys.flags.optimize:
        raise RuntimeError("Validation requires enabled Python assertions")
    ARTIFACTS.mkdir(exist_ok=True)
    lock = acquire_lock()
    started = time.perf_counter()
    report: dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "steps": [],
        "source_fingerprint": source_fingerprint(),
    }
    receipts = [
        "validation.json",
        "backend-junit.xml",
        "frontend-tests.json",
        "coverage.json",
        "detection-validation.json",
        "detection-validation.txt",
        "sigma-validation.json",
        "benchmark.json",
        "integrations-validation.json",
    ]
    for name in receipts:
        (ARTIFACTS / name).unlink(missing_ok=True)
    code = 1
    try:
        npm = shutil.which("npm")
        node = shutil.which("node")
        if npm is None or node is None or sys.version_info < (3, 13, 15):
            raise RuntimeError("Python 3.13.15+ and Node 24.21+ LTS with npm are required")
        py = sys.executable
        with (ARTIFACTS / "validation.log").open("w", buffering=1) as log:
            commands = [
                (
                    "Environment",
                    [
                        node,
                        "-e",
                        "const [a,b]=process.versions.node.split('.').map(Number);"
                        "if(a!==24||b<21)process.exit(1);console.log(process.version)",
                    ],
                ),
                ("Pinned Python dependency consistency", [py, "-m", "pip", "check"]),
                ("Offline Swagger asset integrity", [py, "scripts/vendor_swagger.py", "--check"]),
                (
                    "Backend static checks",
                    [py, "-m", "ruff", "check", "backend", "scripts", "collector"],
                ),
                (
                    "Backend formatting",
                    [py, "-m", "ruff", "format", "--check", "backend", "scripts", "collector"],
                ),
                ("Backend strict types", [py, "-m", "mypy", "backend/app"]),
                ("Frontend lint", [npm, "--prefix", "frontend", "run", "lint"]),
                ("Frontend formatting", [npm, "--prefix", "frontend", "run", "format:check"]),
                (
                    "Frontend types and production build",
                    [npm, "--prefix", "frontend", "run", "build"],
                ),
                ("Browser workflow syntax", [node, "--check", "scripts/browser_workflows.mjs"]),
                ("Live verification syntax", [node, "--check", "scripts/browser_verify.mjs"]),
                ("Deployment browser syntax", [node, "--check", "scripts/browser_deployment.mjs"]),
                (
                    "Integration browser syntax",
                    [node, "--check", "scripts/browser_integrations.mjs"],
                ),
                ("Recording workflow syntax", [node, "--check", "scripts/record_demo.mjs"]),
                ("Saved fixture reproducibility", [py, "scripts/generate_test_data.py", "--check"]),
                (
                    "Integration fixture reproducibility",
                    [py, "scripts/generate_integration_data.py", "--check"],
                ),
                (
                    "Security fixture reproducibility",
                    [py, "scripts/generate_security_data.py", "--check"],
                ),
                (
                    "All backend tests",
                    [
                        py,
                        "-m",
                        "pytest",
                        "-q",
                        "--tb=short",
                        "--junitxml=" + str(ARTIFACTS / "backend-junit.xml"),
                        "--cov=app",
                        "--cov-report=json:" + str(ARTIFACTS / "coverage.json"),
                    ],
                ),
                (
                    "All frontend tests",
                    [
                        npm,
                        "--prefix",
                        "frontend",
                        "test",
                        "--",
                        "--reporter=json",
                        "--outputFile=" + str(ARTIFACTS / "frontend-tests.json"),
                    ],
                ),
                ("Exact detection validation", [py, "scripts/validate_detections.py"]),
                ("Licensed Sigma compatibility", [py, "scripts/validate_sigma.py"]),
                (
                    "Offline integration end-to-end validation",
                    [py, "scripts/validate_integrations.py"],
                ),
                ("Measured detection benchmark", [py, "scripts/benchmark_detection.py"]),
            ]
            for name, command in commands:
                execute(name, command, report, log)
            report["backend"] = junit_results(ARTIFACTS / "backend-junit.xml")
            coverage = json.loads((ARTIFACTS / "coverage.json").read_text())
            report["backend"]["coverage_percent"] = coverage["totals"]["percent_covered"]
            frontend = json.loads((ARTIFACTS / "frontend-tests.json").read_text())
            report["frontend"] = {
                "total": frontend["numTotalTests"],
                "passed": frontend["numPassedTests"],
                "failed": frontend["numFailedTests"],
                "skipped": frontend["numPendingTests"],
            }
            if (
                not frontend["success"]
                or frontend["numTotalTests"] == 0
                or frontend["numPendingTests"]
            ):
                raise RuntimeError("Frontend test report is empty, failed, or skipped")
            detections = json.loads((ARTIFACTS / "detection-validation.json").read_text())
            if detections["status"] != "passed" or detections["failed"]:
                raise RuntimeError("Detection validation did not pass")
            report["detections"] = {
                key: detections[key]
                for key in ("passed", "failed", "total", "benign_passed", "benign_total")
            }
            report["sigma"] = json.loads((ARTIFACTS / "sigma-validation.json").read_text())
            report["integrations"] = json.loads(
                (ARTIFACTS / "integrations-validation.json").read_text()
            )
            if report["integrations"]["status"] != "passed":
                raise RuntimeError("Integration end-to-end validation did not pass")
            if report["sigma"]["tests_failed"]:
                raise RuntimeError("Sigma compatibility did not pass")
            report["benchmark"] = json.loads((ARTIFACTS / "benchmark.json").read_text())
            if report["benchmark"]["status"] != "passed":
                raise RuntimeError("Benchmark did not satisfy the authored counts")
            if report["source_fingerprint"] != source_fingerprint():
                raise RuntimeError("Source changed during validation; run the full command again")
            report["total_tests_passed"] = (
                report["backend"]["passed"] + report["frontend"]["passed"]
            )
            summary = [
                "",
                "=" * 72,
                "SENTINELFLOW VALIDATION",
                f"Backend tests .............. {report['backend']['passed']} passed",
                f"Frontend tests ............. {report['frontend']['passed']} passed",
            ]
            for category in (
                "parser",
                "detection",
                "negative",
                "integration",
                "replay",
                "sigma",
                "regression",
                "security",
            ):
                count = report["backend"]["categories"][category]["passed"]
                summary.append(f"{category.capitalize():28} {count} passed (backend subset)")
            summary.extend(
                [
                    f"Detection scenarios ........ {detections['passed']} passed, "
                    f"{detections['failed']} failed",
                    f"Controlled benign cases .... "
                    f"{detections['benign_passed']}/{detections['benign_total']}",
                    f"Total unique test cases .... {report['total_tests_passed']} passed, 0 failed",
                    "STATUS: VALIDATED",
                    "=" * 72,
                ]
            )
            text = "\n".join(summary) + "\n"
            log.write(text)
            print(text)
            report["status"] = "validated"
            code = 0
    except (Exception, KeyboardInterrupt) as exc:
        report["status"] = "failed"
        report["error"] = str(exc) or "Validation interrupted"
        text = f"\nSTATUS: FAILED - {report['error']}\n"
        with (ARTIFACTS / "validation.log").open("a") as log:
            log.write(text)
        print(text, file=sys.stderr)
        code = 130 if isinstance(exc, KeyboardInterrupt) else 1
    finally:
        report["completed_at"] = datetime.now(UTC).isoformat()
        report["duration_seconds"] = time.perf_counter() - started
        save_json(ARTIFACTS / "validation.json", report)
        lock.unlink(missing_ok=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
