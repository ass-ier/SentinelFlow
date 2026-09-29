import argparse
import hashlib
import json
import platform
import statistics
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import ROOT
from app.core.evidence import source_fingerprint
from app.detection.engine import evaluate
from app.detection.rules import load_bundled_rules
from app.parsers import parse_content


def benchmark(iterations: int = 3) -> dict[str, object]:
    expected = json.loads((ROOT / "test-data/expected-results/benchmark.json").read_text())
    data = ROOT / "test-data" / expected["file"]
    content = data.read_text()
    digest = hashlib.sha256(content.encode()).hexdigest()
    if digest != expected["sha256"]:
        raise ValueError("Benchmark fixture checksum differs")
    events = parse_content(content, "jsonl")
    rules = load_bundled_rules(ROOT / "rules")
    durations = []
    last_metrics = None
    for _ in range(iterations):
        detections, metrics = evaluate(events, rules, "benchmark")
        counts = dict(Counter(detection.rule.id for detection in detections))
        if metrics.events_processed != expected["events"] or len(detections) != expected["alerts"]:
            raise ValueError("Benchmark event or alert counts differ from the authored contract")
        if (
            counts != expected["rule_alert_counts"]
            or metrics.rules_evaluated != expected["rules_evaluated"]
        ):
            raise ValueError("Benchmark rule counts differ from the authored contract")
        durations.append(metrics.detection_seconds)
        last_metrics = metrics
    assert last_metrics is not None
    median = statistics.median(durations)
    return {
        "measured_at": datetime.now(UTC).isoformat(),
        "source_fingerprint": source_fingerprint(),
        "scope": (
            "Single-process engine-only; parsing/storage excluded. Not a production capacity claim."
        ),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "dataset": expected["file"],
        "dataset_sha256": digest,
        "iterations": iterations,
        "events_processed": last_metrics.events_processed,
        "events_per_second": last_metrics.events_processed / median,
        "detection_seconds": median,
        "sample_seconds": durations,
        "alerts_generated": last_metrics.alerts_generated,
        "rules_evaluated": last_metrics.rules_evaluated,
        "active_rules": len(rules),
        "expected_alerts": expected["alerts"],
        "rule_alert_counts": expected["rule_alert_counts"],
        "status": "passed",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure real included-event detection throughput")
    parser.add_argument("--iterations", type=int, choices=range(1, 11), default=3)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "benchmark.json")
    args = parser.parse_args()
    report = benchmark(args.iterations)
    args.output.parent.mkdir(exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
