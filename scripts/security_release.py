"""Full fail-closed release gate; network access never targets live integrations."""

import argparse
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from security_scan import ROOT, Assessment, read

from app.core.evidence import source_fingerprint


def verify_receipt(path: Path, fingerprint: str, status: str) -> dict:
    receipt = read(path)
    if receipt.get("status") != status or receipt.get("source_fingerprint") != fingerprint:
        raise RuntimeError(f"Failed or stale evidence: {path}")
    return receipt


def main() -> int:
    if sys.flags.optimize:
        raise RuntimeError("Release validation requires enabled Python assertions")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = (
        args.output or ROOT / "artifacts/security" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    ).resolve()
    if not output.is_relative_to(ROOT / "artifacts/security"):
        raise ValueError("Use a new directory under artifacts/security")
    assessment = Assessment(output)
    assessment.report["scope"] = "Full security release"
    fingerprint = source_fingerprint()
    try:
        assessment.run("full-validation", [sys.executable, "scripts/validate.py"], timeout=1200)
        validation = verify_receipt(ROOT / "artifacts/validation.json", fingerprint, "validated")
        assessment.report["validation"] = {
            name: validation[name]
            for name in ("backend", "frontend", "detections", "sigma", "integrations", "benchmark")
        }
        for name in (
            "validation.json",
            "validation.log",
            "backend-junit.xml",
            "frontend-tests.json",
            "coverage.json",
            "detection-validation.json",
            "detection-validation.txt",
            "sigma-validation.json",
            "benchmark.json",
            "integrations-validation.json",
        ):
            shutil.copyfile(ROOT / "artifacts" / name, output / name)
        assessment.scans()
        images = {row["name"].rsplit(":", 1)[-1]: row["id"] for row in assessment.report["images"]}
        assessment.run(
            "rehearsals",
            [
                sys.executable,
                "scripts/security_rehearsal.py",
                "--output",
                str(output / "rehearsals"),
                "--backend-image",
                images["backend"],
                "--application-image",
                images["application"],
            ],
            timeout=1800,
        )
        rehearsals = verify_receipt(output / "rehearsals/rehearsals.json", fingerprint, "passed")
        assessment.report["rehearsals"] = rehearsals
        assessment.check(
            "Native and Docker/browser/collector rehearsals completed",
            bool(rehearsals["checks"]),
            {"checks": len(rehearsals["checks"])},
        )
        media = subprocess.check_output(
            ["git", "ls-tree", "-r", "--name-only", "HEAD", "screenshots", "recordings"],
            cwd=ROOT,
            text=True,
        ).splitlines()
        changed = []
        for name in media:
            if Path(name).suffix not in {".png", ".mp4"}:
                continue
            expected = subprocess.check_output(
                ["git", "rev-parse", "HEAD:" + name], cwd=ROOT, text=True
            ).strip()
            actual = subprocess.check_output(
                ["git", "hash-object", name], cwd=ROOT, text=True
            ).strip()
            if expected != actual:
                changed.append(name)
        assessment.check(
            "Previously finalized screenshots and recording are byte-identical",
            not changed,
            changed,
        )
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        assessment.report["blockers"].append(f"Incomplete release phase: {exc}")
    result = assessment.finish()
    print(
        json.dumps(
            {
                "status": result["status"],
                "report": str(output / "summary.json"),
                "blockers": result["blockers"],
            },
            indent=2,
        )
    )
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
