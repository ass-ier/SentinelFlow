import math
from collections import Counter
from copy import deepcopy
from typing import Any

from pydantic import ValidationError

from app.core.errors import DomainError
from app.schemas.events import NormalizedEvent, stable_event_id

FLAT_FIELDS = {
    "id": "event.id",
    "timestamp": "event.timestamp",
    "category": "event.category",
    "type": "event.type",
    "action": "event.action",
    "outcome": "event.outcome",
    "severity": "event.severity",
    "log_source": "event.source",
    "host": "host.name",
    "host_ip": "host.ip",
    "user": "user.name",
    "source_ip": "source.ip",
    "source_port": "source.port",
    "destination_ip": "destination.ip",
    "destination_port": "destination.port",
    "process_name": "process.name",
    "process_executable": "process.executable",
    "command_line": "process.command_line",
    "parent_process": "process.parent.name",
    "parent_executable": "process.parent.executable",
    "protocol": "network.protocol",
    "dns_query": "dns.query",
    "file_path": "file.path",
}


def set_path(target: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    for part in parts[:-1]:
        current = target.setdefault(part, {})
        if not isinstance(current, dict):
            raise DomainError(f"Conflicting field path: {path}")
        target = current
    if parts[-1] in target:
        raise DomainError(f"Conflicting field path: {path}")
    target[parts[-1]] = value


def normalize_record(
    record: dict[str, Any], parser: str, raw: dict[str, Any] | str | None = None
) -> NormalizedEvent:
    if "event" in record:
        data = deepcopy(record)
    else:
        data = {}
        for key, value in record.items():
            path = FLAT_FIELDS.get(key, key)
            if "." in path:
                set_path(data, path, value if value != "" else None)
            elif path in {
                "host",
                "user",
                "source",
                "destination",
                "process",
                "network",
                "dns",
                "file",
                "metadata",
                "raw_event",
            }:
                data[path] = value
            else:
                raise DomainError(f"Unsupported event field: {key[:80]}")
    event = data.setdefault("event", {})
    if not isinstance(event, dict):
        raise DomainError("event must be an object")
    evidence = raw if raw is not None else record.get("raw_event", record)
    event.setdefault("id", stable_event_id(evidence, parser))
    event.setdefault("source", parser)
    data["raw_event"] = evidence
    try:
        normalized = NormalizedEvent.model_validate(data)
    except ValidationError as exc:
        first = exc.errors(include_input=False)[0]
        location = ".".join(str(part) for part in first["loc"])
        raise DomainError(f"Invalid event field {location}: {first['msg']}") from exc
    if normalized.dns.query:
        labels = normalized.dns.query.lower().rstrip(".").split(".")
        entropy = [
            -sum(
                (count / len(label)) * math.log2(count / len(label))
                for count in Counter(label).values()
            )
            if label
            else 0.0
            for label in labels
        ]
        normalized.metadata = {
            **normalized.metadata,
            "dns_metrics": {
                "max_label_length": max(map(len, labels)),
                "max_label_entropy": round(max(entropy), 6),
                "label_count": len(labels),
                "base_domain": ".".join(labels[-2:]),
            },
        }
    return normalized
