import hashlib
import json
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from time import perf_counter
from typing import Any

from app.core.errors import DomainError
from app.detection.rules import Branch, Rule, matches
from app.schemas.events import NormalizedEvent, get_field


@dataclass
class Detection:
    id: str
    rule: Rule
    branch: str
    group: dict[str, Any]
    events: list[NormalizedEvent]
    triggered_at: datetime

    @property
    def first_seen(self) -> datetime:
        return self.events[0].event.timestamp

    @property
    def last_seen(self) -> datetime:
        return self.events[-1].event.timestamp

    def to_dict(self) -> dict[str, Any]:
        sources = sorted({event.source.ip for event in self.events if event.source.ip})
        hosts = sorted({event.host.name for event in self.events if event.host.name})
        users = sorted({event.user.name for event in self.events if event.user.name})
        destinations = sorted(
            {event.destination.ip for event in self.events if event.destination.ip}
        )
        return {
            "id": self.id,
            "rule_id": self.rule.id,
            "rule_name": self.rule.name,
            "severity": self.rule.severity,
            "description": self.rule.description,
            "branch": self.branch,
            "group": self.group,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "triggered_at": self.triggered_at.isoformat(),
            "event_count": len(self.events),
            "source_entities": {"ips": sources},
            "affected_entities": {"hosts": hosts, "users": users, "destination_ips": destinations},
            "mitre_attack": self.rule.mitre_attack,
            "provenance": self.rule.provenance.model_dump(mode="json", exclude={"original_yaml"}),
            "evidence_ids": [event.event.id for event in self.events],
        }


@dataclass
class Metrics:
    events_processed: int = 0
    duplicates_ignored: int = 0
    rules_evaluated: int = 0
    detections_triggered: int = 0
    alerts_generated: int = 0
    suppressed_matches: int = 0
    missing_group_matches: int = 0
    detection_seconds: float = 0.0
    events_per_second: float = 0.0

    def to_dict(self) -> dict[str, int | float]:
        return vars(self).copy()


@dataclass
class GroupState:
    candidates: deque[NormalizedEvent] = field(default_factory=deque)
    active: Detection | None = None
    suppression_end: datetime | None = None


def unique_chronological(events: list[NormalizedEvent]) -> tuple[list[NormalizedEvent], int]:
    unique: dict[str, NormalizedEvent] = {}
    duplicates = 0
    for event in events:
        existing = unique.get(event.event.id)
        if existing is not None:
            if existing != event:
                raise DomainError(
                    "An event ID was reused with different content", 409, "id_conflict"
                )
            duplicates += 1
        else:
            unique[event.event.id] = event
    return sorted(
        unique.values(), key=lambda event: (event.event.timestamp, event.event.id)
    ), duplicates


def evaluate(
    events: list[NormalizedEvent], rules: list[Rule], run_id: str = "isolated"
) -> tuple[list[Detection], Metrics]:
    started = perf_counter()
    ordered, duplicates = unique_chronological(events)
    metrics = Metrics(events_processed=len(ordered), duplicates_ignored=duplicates)
    detections: list[Detection] = []
    for rule in rules:
        if not rule.enabled:
            continue
        states: dict[tuple[str, str], GroupState] = {}
        branches = rule.branches or [
            Branch(
                name="default",
                conditions=rule.conditions,
                threshold=rule.threshold,
                group_by=rule.group_by,
            )
        ]
        for event in ordered:
            metrics.rules_evaluated += 1
            payload = event.model_dump(mode="json")
            if not matches(rule.conditions, payload):
                continue
            for branch in branches:
                if rule.branches and not matches(branch.conditions, payload):
                    continue
                group = {path: get_field(payload, path) for path in branch.group_by}
                if any(value is None for value in group.values()):
                    metrics.missing_group_matches += 1
                    continue
                if any(isinstance(value, dict | list) for value in group.values()):
                    raise DomainError("Group fields must contain scalar values")
                group_key = json.dumps(group, sort_keys=True, separators=(",", ":"))
                state = states.setdefault((branch.name, group_key), GroupState())
                timestamp = event.event.timestamp
                if (
                    state.active is not None
                    and state.suppression_end is not None
                    and timestamp < state.suppression_end
                ):
                    state.active.events.append(event)
                    metrics.suppressed_matches += 1
                    continue
                state.active = None
                lower_bound = timestamp - timedelta(seconds=branch.threshold.window_seconds)
                while state.candidates and state.candidates[0].event.timestamp < lower_bound:
                    state.candidates.popleft()
                state.candidates.append(event)
                if len(state.candidates) < branch.threshold.count:
                    continue
                identity = f"{run_id}:{rule.id}:{branch.name}:{group_key}:{event.event.id}"
                detection = Detection(
                    id=hashlib.sha256(identity.encode()).hexdigest()[:32],
                    rule=rule,
                    branch=branch.name,
                    group=group,
                    events=list(state.candidates),
                    triggered_at=timestamp,
                )
                detections.append(detection)
                state.candidates.clear()
                state.active = detection
                state.suppression_end = timestamp + timedelta(seconds=rule.suppression_seconds)
    metrics.detections_triggered = metrics.alerts_generated = len(detections)
    metrics.detection_seconds = perf_counter() - started
    metrics.events_per_second = (
        len(ordered) / metrics.detection_seconds if metrics.detection_seconds else 0.0
    )
    return detections, metrics
