import csv
import io
from typing import Any

from app.core.errors import DomainError
from app.core.safe import json_loads, utf8_bytes
from app.parsers.normalize import normalize_record
from app.parsers.syslog import parse_syslog
from app.parsers.wazuh import parse_wazuh
from app.parsers.windows import parse_windows
from app.schemas.events import LogFormat, NormalizedEvent


def parse_content(
    content: str,
    log_format: LogFormat,
    *,
    max_bytes: int = 5 * 1024 * 1024,
    max_events: int = 10_000,
    syslog_year: int = 2026,
) -> list[NormalizedEvent]:
    if len(utf8_bytes(content)) > max_bytes:
        raise DomainError("Upload exceeds the configured file size limit", 413, "size_limit")
    content = content.lstrip("\ufeff")
    if not content.strip():
        raise DomainError("Input contains no events")
    records: list[Any]
    if log_format in ("json", "windows", "wazuh"):
        parsed = json_loads(content)
        records = parsed if isinstance(parsed, list) else [parsed]
    elif log_format == "jsonl":
        records = [json_loads(line) for line in content.splitlines() if line.strip()]
    elif log_format == "csv":
        reader = csv.DictReader(io.StringIO(content))
        if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames):
            raise DomainError("CSV requires unique column names")
        try:
            records = list(reader)
        except csv.Error as exc:
            raise DomainError("Malformed CSV") from exc
        if any(None in row or any(value is None for value in row.values()) for row in records):
            raise DomainError("CSV rows must have the same number of fields as the header")
    elif log_format == "syslog":
        lines = [line for line in content.splitlines() if line.strip()]
        if len(lines) > max_events:
            raise DomainError("Too many events", 413, "event_limit")
        result = []
        for index, line in enumerate(lines, 1):
            try:
                result.append(parse_syslog(line, syslog_year))
            except DomainError as exc:
                raise DomainError(f"Line {index}: {exc.message}") from exc
        return result
    else:
        raise DomainError(f"Unsupported format: {log_format}")
    if not records:
        raise DomainError("Input contains no events")
    if len(records) > max_events:
        raise DomainError("Too many events", 413, "event_limit")
    events = []
    for index, record in enumerate(records, 1):
        if not isinstance(record, dict):
            raise DomainError(f"Record {index} must be an object")
        try:
            if log_format == "wazuh" or (
                isinstance(record.get("data"), dict) and isinstance(record["data"].get("win"), dict)
            ):
                events.append(parse_wazuh(record))
                continue
            windows = log_format == "windows" or "EventID" in record or "System" in record
            windows = windows or ("Event" in record and isinstance(record["Event"], dict))
            events.append(
                parse_windows(record) if windows else normalize_record(record, log_format)
            )
        except DomainError as exc:
            raise DomainError(f"Record {index}: {exc.message}") from exc
    return events
