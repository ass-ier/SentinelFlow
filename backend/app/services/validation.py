from time import perf_counter
from typing import Any

from app.core.errors import DomainError
from app.detection.engine import evaluate
from app.detection.rules import Rule
from app.services.datasets import DatasetStore


def canonical_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        alerts,
        key=lambda item: (
            item["rule_id"],
            item["severity"],
            item.get("branch", "default"),
            item["event_count"],
        ),
    )


def validate_detections(
    datasets: DatasetStore,
    rules: list[Rule],
    *,
    dataset_id: str | None = None,
    rule_id: str | None = None,
    expected_count: int | None = None,
    scope: str = "bundled",
    definition_test: bool = False,
) -> dict[str, Any]:
    started = perf_counter()
    if expected_count is not None and (dataset_id is None or rule_id is None):
        raise DomainError("A custom expected count requires a dataset and a rule")
    selected = [rule for rule in rules if rule_id is None or rule.id == rule_id]
    if rule_id and not selected:
        raise DomainError("Rule not found", 404, "not_found")
    if definition_test:
        selected = [rule.model_copy(update={"enabled": True}) for rule in selected]
    items = [datasets.get(dataset_id)] if dataset_id else datasets.catalog()
    results: list[dict[str, Any]] = []
    for item in items:
        scenario_started = perf_counter()
        events = datasets.events(item["id"])
        detections, metrics = evaluate(events, selected, run_id=f"validation:{item['id']}")
        actual = canonical_alerts(
            [
                {
                    "rule_id": detection.rule.id,
                    "severity": detection.rule.severity,
                    "event_count": len(detection.events),
                    "branch": detection.branch,
                }
                for detection in detections
            ]
        )
        expected = canonical_alerts(
            [entry for entry in item["expected"] if rule_id is None or entry["rule_id"] == rule_id]
        )
        errors = []
        status = "passed"
        known_rule = rule_id is None or any(
            rule.id == rule_id and rule.provenance.kind == "bundled" for rule in selected
        )
        if expected_count is not None:
            status = "passed" if len(actual) == expected_count else "failed"
            if status == "failed":
                errors.append(f"Expected {expected_count} alerts; observed {len(actual)}")
            expected_display: list[dict[str, Any]] | None = [
                {
                    "rule_id": rule_id,
                    "severity": selected[0].severity,
                    "event_count": None,
                    "branch": "any",
                }
                for _ in range(expected_count)
            ]
        elif not known_rule:
            status = "observed"
            expected_display = None
        else:
            expected_display = expected
            if actual != expected:
                status = "failed"
                errors.append("Exact rule, severity, branch, or evidence count differs")
        results.append(
            {
                "test_id": item["id"],
                "name": item["name"],
                "dataset_id": item["id"],
                "kind": item["kind"],
                "status": status,
                "expected": expected_display,
                "actual": actual,
                "events_processed": metrics.events_processed,
                "duplicates_ignored": metrics.duplicates_ignored,
                "duration_seconds": perf_counter() - scenario_started,
                "errors": errors,
                "metrics": metrics.to_dict(),
                "alerts": [
                    {
                        **detection.to_dict(),
                        "run_id": f"validation:{item['id']}",
                        "status": "new",
                        "created_at": detection.triggered_at.isoformat(),
                        "evidence": [event.model_dump(mode="json") for event in detection.events],
                    }
                    for detection in detections
                ],
            }
        )
    passed = sum(result["status"] == "passed" for result in results)
    failed = sum(result["status"] == "failed" for result in results)
    return {
        "status": "failed" if failed else ("passed" if passed == len(results) else "observed"),
        "passed": passed,
        "failed": failed,
        "total": len(results),
        "benign_passed": sum(
            result["kind"] == "benign" and result["status"] == "passed" for result in results
        ),
        "benign_total": sum(result["kind"] == "benign" for result in results),
        "duration_seconds": perf_counter() - started,
        "scope": scope
        + ("; isolated definition test (enable state unchanged)" if definition_test else ""),
        "results": results,
    }


def human_report(report: dict[str, Any]) -> str:
    lines = [
        "SENTINELFLOW DETECTION VALIDATION",
        f"Scope: {report['scope']}",
        "Each scenario uses fresh event-time correlation state.",
        "",
    ]
    for result in report["results"]:
        lines.append(
            f"{result['status'].upper():8} {result['test_id']:36} "
            f"events={result['events_processed']:4} alerts={len(result['actual']):2} "
            f"duplicates={result['duplicates_ignored']}"
        )
        lines.extend(f"         {error}" for error in result["errors"])
    lines.extend(
        [
            "",
            f"Scenarios: {report['passed']} passed, {report['failed']} failed, "
            f"{report['total']} total",
            f"Controlled benign scenarios: {report['benign_passed']} / "
            f"{report['benign_total']} passed",
            f"Duration: {report['duration_seconds']:.6f}s",
            f"STATUS: {report['status'].upper()}",
        ]
    )
    return "\n".join(lines) + "\n"
