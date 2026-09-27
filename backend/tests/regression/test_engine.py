from datetime import timedelta

import pytest

from app.core.errors import DomainError
from app.detection.engine import evaluate
from app.detection.rules import Rule
from app.services.datasets import DatasetStore
from app.services.platform import Platform

pytestmark = pytest.mark.regression
FAMILIES = [
    ("AUTH-001", "auth-brute-force", "auth-normal-failures"),
    ("AUTH-002", "auth-lockout", "auth-normal-lockout"),
    ("PROC-001", "powershell-indicators", "powershell-admin"),
    ("PROC-002", "process-suspicious", "process-benign"),
    ("IAM-001", "iam-privileged-group", "iam-approved-maintenance"),
    ("DNS-001", "dns-long-label", "dns-normal"),
    ("NET-001", "net-unusual", "net-normal"),
]


@pytest.mark.parametrize(("rule_id", "positive", "benign"), FAMILIES)
def test_every_detection_regression_contract(
    datasets: DatasetStore, rules: list[Rule], rule_id: str, positive: str, benign: str
) -> None:
    rule = next(rule for rule in rules if rule.id == rule_id)
    events = datasets.events(positive)
    forward, _ = evaluate(events, [rule], "same-run")
    reversed_hits, _ = evaluate(list(reversed(events)), [rule], "same-run")
    duplicated_hits, metrics = evaluate(events + events, [rule], "same-run")
    assert [hit.to_dict() for hit in forward] == [hit.to_dict() for hit in reversed_hits]
    assert [hit.to_dict() for hit in forward] == [hit.to_dict() for hit in duplicated_hits]
    assert len(forward) == 1
    assert metrics.duplicates_ignored == len(events)
    assert evaluate(datasets.events(benign), [rule])[0] == []
    rule.enabled = False
    assert evaluate(events, [rule])[0] == []


def test_duplicate_ids_with_different_content_are_not_silently_dropped(
    datasets: DatasetStore, rules: list[Rule]
) -> None:
    first = datasets.events("auth-brute-force")[0]
    changed = first.model_copy(deep=True)
    changed.user.name = "different_operator"
    with pytest.raises(DomainError, match="different content"):
        evaluate([first, changed], rules)


def test_threshold_and_suppression_boundary_evidence(
    datasets: DatasetStore, rules: list[Rule]
) -> None:
    exact, _ = evaluate(datasets.events("auth-window-boundary"), rules)
    outside, _ = evaluate(datasets.events("auth-window-outside"), rules)
    assert len(exact) == 1
    assert (exact[0].last_seen - exact[0].first_seen).total_seconds() == 300
    assert outside == []
    episodes, metrics = evaluate(datasets.events("auth-suppression-boundary"), rules)
    assert [len(hit.events) for hit in episodes] == [15, 10]
    assert metrics.suppressed_matches == 5
    assert set(episodes[0].to_dict()["evidence_ids"]).isdisjoint(
        episodes[1].to_dict()["evidence_ids"]
    )


def test_group_separation_and_missing_entities(datasets: DatasetStore, rules: list[Rule]) -> None:
    hits, _ = evaluate(datasets.events("auth-group-separation"), rules)
    assert {hit.group["source.ip"] for hit in hits} == {"192.0.2.11", "192.0.2.12"}
    for hit in hits:
        assert {event.source.ip for event in hit.events} == {hit.group["source.ip"]}
    hits, metrics = evaluate(datasets.events("auth-missing-source"), rules)
    assert hits == []
    assert metrics.missing_group_matches == 10


def test_persisted_duplicates_and_late_batch_are_atomic(
    datasets: DatasetStore, service: Platform
) -> None:
    events = datasets.events("auth-brute-force")
    first = service.ingest(events)
    run = first["run"]["id"]
    second = service.ingest(events, run_id=run)
    assert second["events_stored"] == second["alerts_created"] == 0
    assert second["duplicates_ignored"] == 25
    late = events[0].model_copy(deep=True)
    late.event.id = "late-event"
    later = events[-1].model_copy(deep=True)
    later.event.id = "later-event"
    later.event.timestamp += timedelta(seconds=100)
    with pytest.raises(DomainError, match="watermark"):
        service.ingest([later, late], run_id=run)
    assert service.search_events({"run_id": run}, 0, 100)["total"] == 25
    assert service.alerts({"run_id": run}, 0, 100)["total"] == 1


def test_equal_timestamp_id_watermark_does_not_rewrite_past_alerts(
    datasets: DatasetStore, service: Platform
) -> None:
    events = datasets.events("auth-brute-force")
    result = service.ingest(events)
    candidate = events[-1].model_copy(deep=True)
    candidate.event.id = "000-earlier-sort-key"
    with pytest.raises(DomainError, match="watermark"):
        service.ingest([candidate], run_id=result["run"]["id"])
    assert service.alerts({}, 0, 100)["items"][0]["event_count"] == 25


def test_pinned_rule_definition_and_status_survive_append(
    datasets: DatasetStore, service: Platform
) -> None:
    events = datasets.events("auth-brute-force")
    result = service.ingest(events[:10])
    run = result["run"]["id"]
    hit = service.alerts({"run_id": run}, 0, 100)["items"][0]
    service.change_status(hit["id"], "investigating", "test")
    service.toggle_rule("AUTH-001", False, "test")
    service.ingest(events[10:], run_id=run)
    updated = service.alert(hit["id"])
    assert updated["status"] == "investigating"
    assert updated["event_count"] == len(updated["evidence"]) == 25
    assert updated["rule_snapshot"]["enabled"] is True
    new_run = service.ingest(events)
    assert new_run["alerts_created"] == 0


def test_suppression_evidence_counts_the_episode_not_only_the_initial_window(
    datasets: DatasetStore, service: Platform
) -> None:
    events = datasets.events("auth-brute-force")
    result = service.ingest(events)
    followup = events[-1].model_copy(deep=True)
    followup.event.id = "suppression-followup"
    followup.event.timestamp = events[0].event.timestamp + timedelta(seconds=600)
    service.ingest([followup], run_id=result["run"]["id"])
    hit = service.alerts({}, 0, 100)["items"][0]
    assert hit["event_count"] == 26
    assert hit["last_seen"] == followup.event.timestamp.isoformat()
    assert hit["triggered_at"] == events[9].event.timestamp.isoformat()
