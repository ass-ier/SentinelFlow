from typing import Any

from app.core.errors import DomainError
from app.parsers.syslog import parse_syslog
from app.parsers.windows import parse_windows
from app.schemas.events import NormalizedEvent, stable_event_id

WINDOWS_FIELDS = (
    "SubjectUserName",
    "TargetUserName",
    "MemberName",
    "IpAddress",
    "IpPort",
    "Image",
    "NewProcessName",
    "ParentProcessName",
    "ParentImage",
    "CommandLine",
    "ScriptBlockText",
    "SourceIp",
    "DestinationIp",
    "SourcePort",
    "DestinationPort",
    "Protocol",
    "QueryName",
    "User",
)


def parse_wazuh(record: dict[str, Any]) -> NormalizedEvent:
    data = record.get("data", {})
    win = data.get("win") if isinstance(data, dict) else None
    if isinstance(win, dict):
        system, fields = win.get("system"), win.get("eventdata")
        if not isinstance(system, dict) or not isinstance(fields, dict):
            raise DomainError("Wazuh win.system and win.eventdata must be objects")
        lookup = {key.casefold(): value for key, value in fields.items()}
        event = parse_windows(
            {
                "Event": {
                    "System": {
                        "EventID": system.get("eventID"),
                        "TimeCreated": {"SystemTime": system.get("systemTime")},
                        "Computer": system.get("computer"),
                        "Provider": {"Name": system.get("providerName", "windows")},
                        "Channel": system.get("channel"),
                    },
                    "EventData": {
                        key: lookup[key.casefold()]
                        for key in WINDOWS_FIELDS
                        if key.casefold() in lookup
                    },
                }
            }
        )
    elif isinstance(record.get("full_log"), str):
        event = parse_syslog(record["full_log"])
    else:
        raise DomainError(
            "Wazuh adapter supports Windows EventChannel and authentication full_log records"
        )
    event.raw_event = record
    event.event.id = stable_event_id(record, "wazuh")
    event.metadata = {**event.metadata, "provider": "wazuh", "agent": record.get("agent")}
    return event
