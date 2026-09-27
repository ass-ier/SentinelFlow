import ntpath
from typing import Any

from app.core.errors import DomainError
from app.parsers.normalize import normalize_record
from app.schemas.events import NormalizedEvent, stable_event_id

WINDOWS_ACTIONS: dict[int, tuple[str, str, str]] = {
    4624: ("authentication", "login", "success"),
    4625: ("authentication", "login", "failure"),
    4634: ("authentication", "logout", "success"),
    4723: ("authentication", "password_change", "unknown"),
    4740: ("authentication", "account_lockout", "failure"),
    4688: ("process", "process_created", "success"),
    1: ("process", "process_created", "success"),
    4104: ("process", "powershell_execution", "unknown"),
    4728: ("identity", "group_member_added", "success"),
    4732: ("identity", "group_member_added", "success"),
    4756: ("identity", "group_member_added", "success"),
    4729: ("identity", "group_member_removed", "success"),
    4733: ("identity", "group_member_removed", "success"),
    4757: ("identity", "group_member_removed", "success"),
    4720: ("identity", "account_created", "success"),
    4672: ("identity", "privilege_assigned", "success"),
    3: ("network", "connection", "success"),
    22: ("network", "dns_query", "unknown"),
}


def optional(value: Any) -> Any:
    return None if value in (None, "", "-") else value


def parse_windows(record: dict[str, Any]) -> NormalizedEvent:
    root = record.get("Event", record)
    if not isinstance(root, dict):
        raise DomainError("Windows Event must be an object")
    system = root.get("System", root)
    data = root.get("EventData", root.get("data", {}))
    if not isinstance(system, dict) or not isinstance(data, dict):
        raise DomainError("Windows System and EventData must be objects")
    event_id = system.get("EventID", root.get("EventID"))
    if isinstance(event_id, dict):
        event_id = event_id.get("#text")
    if isinstance(event_id, bool) or not isinstance(event_id, str | int):
        raise DomainError("Windows EventID must be an integer")
    try:
        code = int(event_id)
    except (ValueError, TypeError) as exc:
        raise DomainError("Windows EventID must be an integer") from exc
    if code not in WINDOWS_ACTIONS:
        raise DomainError(f"Unsupported Windows EventID {code}")
    category, action, outcome = WINDOWS_ACTIONS[code]
    created = system.get("TimeCreated", root.get("timestamp"))
    timestamp = created.get("SystemTime") if isinstance(created, dict) else created
    image = optional(data.get("NewProcessName", data.get("Image")))
    parent = optional(data.get("ParentProcessName", data.get("ParentImage")))
    provider = system.get("Provider", "windows")
    provider_name = provider.get("Name", "windows") if isinstance(provider, dict) else provider
    if code in {1, 3, 22} and str(provider_name).casefold() not in {
        "microsoft-windows-sysmon",
        "sysmon",
    }:
        raise DomainError("EventID 1, 3 and 22 require an explicit Sysmon provider")
    fields = {
        "event": {
            "id": stable_event_id(record, "windows"),
            "timestamp": timestamp,
            "source": str(provider_name),
            "category": category,
            "type": "start" if category == "process" else "info",
            "action": action,
            "outcome": outcome,
        },
        "host": {"name": system.get("Computer", root.get("host"))},
        "user": {
            "name": optional(
                data.get("SubjectUserName")
                if category == "identity"
                else data.get("TargetUserName", data.get("User"))
            )
        },
        "source": {
            "ip": optional(data.get("IpAddress", data.get("SourceIp"))),
            "port": optional(data.get("IpPort", data.get("SourcePort"))),
        },
        "destination": {
            "ip": optional(data.get("DestinationIp")),
            "port": optional(data.get("DestinationPort")),
        },
        "process": {
            "name": ntpath.basename(image)
            if isinstance(image, str)
            else ("powershell.exe" if code == 4104 else None),
            "executable": image,
            "command_line": optional(data.get("CommandLine", data.get("ScriptBlockText"))),
            "parent": {
                "name": ntpath.basename(parent) if isinstance(parent, str) else None,
                "executable": parent,
            },
        },
        "network": {"protocol": optional(data.get("Protocol"))},
        "dns": {"query": optional(data.get("QueryName"))},
        "metadata": {
            "product": "windows",
            "windows_event_id": code,
            "windows_record_id": system.get("EventRecordID"),
            "group_name": data.get("TargetUserName")
            if code in {4728, 4729, 4732, 4733, 4756, 4757}
            else None,
            "target_user": data.get("MemberName", data.get("TargetUserName")),
            "privileged": code == 4672,
        },
    }
    return normalize_record(fields, "windows", raw=record)
