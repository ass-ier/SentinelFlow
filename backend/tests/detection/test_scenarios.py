import json
from collections import Counter

import pytest

from app.core.config import ROOT
from app.detection.engine import evaluate
from app.detection.rules import Rule
from app.services.datasets import DatasetStore
from app.services.validation import canonical_alerts, validate_detections

MANIFEST = json.loads((ROOT / "test-data/manifest.json").read_text())


def parameters() -> list:
    result = []
    for item in MANIFEST:
        marks = [pytest.mark.detection]
        if item["kind"] == "benign":
            marks.append(pytest.mark.negative)
        if item["kind"] in {"boundary", "regression"}:
            marks.append(pytest.mark.regression)
        result.append(pytest.param(item, id=item["id"], marks=marks))
    return result


@pytest.mark.parametrize("item", parameters())
def test_saved_exact_detection_contracts(
    item: dict, datasets: DatasetStore, rules: list[Rule]
) -> None:
    events = datasets.events(item["id"])
    detections, metrics = evaluate(events, rules)
    observed = canonical_alerts(
        [
            {
                "rule_id": hit.rule.id,
                "severity": hit.rule.severity,
                "event_count": len(hit.events),
                "branch": hit.branch,
            }
            for hit in detections
        ]
    )
    assert observed == canonical_alerts(item["expected"])
    assert metrics.events_processed == len({event.event.id for event in events})
    assert metrics.rules_evaluated == metrics.events_processed * len(rules)
    for hit in detections:
        assert len({event.event.id for event in hit.events}) == len(hit.events)
        assert hit.first_seen == min(event.event.timestamp for event in hit.events)
        assert hit.last_seen == max(event.event.timestamp for event in hit.events)
        assert hit.first_seen <= hit.triggered_at <= hit.last_seen
        assert all(event.raw_event is not None for event in hit.events)
        assert hit.to_dict()["event_count"] == len(hit.to_dict()["evidence_ids"])
    counts = Counter(hit.rule.id for hit in detections)
    assert counts == Counter(entry["rule_id"] for entry in item["expected"])


def test_validation_has_fresh_state_for_every_scenario(
    datasets: DatasetStore, rules: list[Rule]
) -> None:
    first = validate_detections(datasets, rules)
    second = validate_detections(datasets, rules)
    assert first["status"] == second["status"] == "passed"
    assert first["total"] == len(MANIFEST)
    assert first["failed"] == 0
    assert [result["actual"] for result in first["results"]] == [
        result["actual"] for result in second["results"]
    ]
    assert first["benign_passed"] == first["benign_total"] >= 7


def test_disabled_current_rule_fails_saved_positive_expectation(
    datasets: DatasetStore, rules: list[Rule]
) -> None:
    for rule in rules:
        if rule.id == "AUTH-001":
            rule.enabled = False
    report = validate_detections(datasets, rules, dataset_id="auth-brute-force", scope="current")
    assert report["status"] == "failed"
    assert report["failed"] == 1
    assert report["results"][0]["actual"] == []


def test_no_fixture_specific_conditions(rules: list[Rule]) -> None:
    for rule in rules:
        text = rule.conditions.model_dump_json()
        assert "event.id" not in text
        assert "synthetic" not in text
        assert "dataset" not in text
