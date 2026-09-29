from typing import Any

from app.detection.engine import Detection
from app.storage.models import AlertRecord


def retain_alert_identity(detection: Detection, previous: list[AlertRecord], used: set[str]) -> str:
    ids = {event.event.id for event in detection.events}
    for record in previous:
        if (
            record.id not in used
            and record.rule_id == detection.rule.id
            and record.payload["group"] == detection.group
            and record.payload["branch"] == detection.branch
            and ids.intersection(record.payload["evidence_ids"])
        ):
            return record.id
    return detection.id


def telemetry_sources(events: list[Any]) -> list[dict[str, Any]]:
    sources: dict[tuple[str, ...], dict[str, Any]] = {}
    fields = ("provider", "connector_id", "source_table", "source_channel", "source_host")
    for event in events:
        value = {field: event.metadata.get(field) for field in fields}
        value["provider"] = value["provider"] or "manual_upload"
        key = tuple(str(value[field]) for field in fields)
        sources[key] = value
    return [sources[key] for key in sorted(sources)]
