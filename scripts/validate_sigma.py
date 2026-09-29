import json
from pathlib import Path

from app.core.config import ROOT
from app.detection.engine import evaluate
from app.detection.sigma import compile_sigma, sigma_samples
from app.services.datasets import DatasetStore


def run(output: Path) -> dict[str, object]:
    results = []
    for sample in sigma_samples():
        rule = compile_sigma(sample["yaml"])
        for dataset, expected in [
            (sample["dataset_id"], 1),
            (sample["negative_dataset_id"], 0),
        ]:
            detections, metrics = evaluate(DatasetStore().events(dataset), [rule])
            passed = (
                len(detections) == expected
                and all(detection.rule.severity == rule.severity for detection in detections)
                and all(
                    detection.rule.provenance.author == sample["author"] for detection in detections
                )
                and all(len(detection.events) == 1 for detection in detections)
            )
            results.append(
                {
                    "rule_id": rule.id,
                    "dataset_id": dataset,
                    "expected_alerts": expected,
                    "observed_alerts": len(detections),
                    "severity": rule.severity,
                    "author": rule.provenance.author,
                    "source_url": rule.provenance.source_url,
                    "status": "passed" if passed else "failed",
                    "events_processed": metrics.events_processed,
                }
            )
    report: dict[str, object] = {
        "rules_imported": len(sigma_samples()),
        "rules_compiled": len(sigma_samples()),
        "rules_tested": len({result["rule_id"] for result in results}),
        "tests_passed": sum(result["status"] == "passed" for result in results),
        "tests_failed": sum(result["status"] == "failed" for result in results),
        "expected_detections": sum(int(result["expected_alerts"]) for result in results),
        "observed_detections": sum(int(result["observed_alerts"]) for result in results),
        "results": results,
    }
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    report = run(ROOT / "artifacts" / "sigma-validation.json")
    print(json.dumps(report, indent=2))
    raise SystemExit(1 if report["tests_failed"] else 0)
