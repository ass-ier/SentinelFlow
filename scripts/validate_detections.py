import argparse
import json
from pathlib import Path

from app.core.config import ROOT
from app.detection.rules import load_bundled_rules
from app.services.datasets import DatasetStore
from app.services.validation import human_report, validate_detections


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate exact saved detection contracts in isolation"
    )
    parser.add_argument("--dataset")
    parser.add_argument("--rule")
    parser.add_argument(
        "--output", type=Path, default=ROOT / "artifacts" / "detection-validation.json"
    )
    args = parser.parse_args()
    report = validate_detections(
        DatasetStore(),
        load_bundled_rules(ROOT / "rules"),
        dataset_id=args.dataset,
        rule_id=args.rule,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    text = human_report(report)
    args.output.with_suffix(".txt").write_text(text)
    print(text, end="")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
