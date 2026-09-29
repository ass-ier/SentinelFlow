import hashlib
import ntpath
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from app.core.errors import DomainError
from app.core.safe import check_tree, json_loads
from app.integrations.profiles import QueryProfile
from app.parsers.normalize import normalize_record
from app.parsers.syslog import parse_syslog
from app.parsers.windows import parse_windows
from app.parsers.windows_xml import event_data
from app.schemas.events import NormalizedEvent


class ProviderDataError(DomainError):
    def __init__(self, received: int) -> None:
        super().__init__(
            "Provider batch contains invalid telemetry; checkpoint was retained",
            422,
            "invalid_telemetry",
        )
        self.received = received


def normalize_batch(
    rows: list[dict[str, Any]], profile: QueryProfile, provider: str, connector_id: str
) -> list[NormalizedEvent]:
    try:
        return [normalize_provider(row, profile, provider, connector_id) for row in rows]
    except (DomainError, ValidationError) as exc:
        raise ProviderDataError(len(rows)) from exc


def mapping(value: Any) -> dict[str, Any]:
    if value in (None, ""):
        return {}
    if isinstance(value, str):
        value = json_loads(value)
    if not isinstance(value, dict):
        raise DomainError("Expected a provider object")
    return value


def sequence(value: Any) -> list[dict[str, Any]]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        value = json_loads(value)
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise DomainError("Expected a provider object array")
    return value


def present(*values: Any) -> Any:
    return next((value for value in values if value is not None and value not in ("", "-")), None)


def stamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise DomainError("Provider event timestamp is required")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DomainError("Provider timestamp is invalid") from exc
    if result.tzinfo is None or not 1970 <= result.year <= 2100:
        raise DomainError("Provider timestamp must include a supported UTC offset")
    return result.astimezone(UTC)


def attribution(
    event: NormalizedEvent,
    raw: dict[str, Any],
    provider: str,
    connector_id: str,
    table: str,
) -> NormalizedEvent:
    import json

    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    identity = raw.get("id") if provider == "microsoft_graph" else None
    event.event.id = hashlib.sha256(
        f"{connector_id}:{table}:{identity or canonical}".encode()
    ).hexdigest()[:32]
    root = raw.get("Event", raw)
    system = root.get("System", {}) if isinstance(root, dict) else {}
    event.raw_event = raw
    if provider == "windows_wef" and isinstance(root, dict):
        data = root.get("EventData", {})
        if isinstance(data, dict):
            event.metadata = {
                **event.metadata,
                "identity": {
                    "domain": present(data.get("TargetDomainName"), data.get("SubjectDomainName")),
                    "sid": present(data.get("TargetUserSid"), data.get("SubjectUserSid")),
                },
            }
            for target, field in (
                (event.process, "NewProcessId"),
                (event.process.parent, "ProcessId"),
            ):
                value = data.get(field)
                if isinstance(value, str) and value not in {"", "-"}:
                    try:
                        target.pid = int(value, 16 if value.lower().startswith("0x") else 10)
                    except ValueError as exc:
                        raise DomainError("Windows process identifier is invalid") from exc
    event.metadata = {
        **event.metadata,
        "provider": provider,
        "connector_id": connector_id,
        "source_table": table,
        "source_channel": system.get("Channel") if isinstance(system, dict) else None,
        "source_host": event.host.name,
        "original_timestamp": event.event.timestamp.isoformat(),
    }
    return event


def signin(row: dict[str, Any], profile: QueryProfile) -> dict[str, Any]:
    status = mapping(row.get("status"))
    code = present(status.get("errorCode"), row.get("ResultType"))
    if code is None or isinstance(code, bool) or not str(code).lstrip("-").isdigit():
        raise DomainError("Sign-in result code is required")
    device = mapping(row.get("deviceDetail", row.get("DeviceDetail")))
    return {
        "event": {
            "timestamp": stamp(row.get(profile.timestamp)),
            "category": "authentication",
            "action": "account_lockout" if str(code) == "50053" else "login",
            "outcome": "success" if int(code) == 0 else "failure",
        },
        "host": {"name": present(device.get("displayName"))},
        "user": {"name": present(row.get("userPrincipalName"), row.get("UserPrincipalName"))},
        "source": {"ip": present(row.get("ipAddress"), row.get("IPAddress"))},
        "metadata": {
            "identity": {
                "id": present(row.get("userId"), row.get("UserId")),
                "email": present(row.get("userPrincipalName"), row.get("UserPrincipalName")),
            },
            "authentication": {
                "result_code": str(code),
                "method": present(
                    row.get("authenticationRequirement"), row.get("AuthenticationRequirement")
                ),
            },
            "source_geo": row.get("location", row.get("LocationDetails")),
            "application": present(row.get("appDisplayName"), row.get("AppDisplayName")),
        },
    }


def audit(row: dict[str, Any], profile: QueryProfile) -> dict[str, Any]:
    initiator = mapping(row.get("initiatedBy", row.get("InitiatedBy")))
    user = mapping(initiator.get("user"))
    app = mapping(initiator.get("app"))
    targets = sequence(row.get("targetResources", row.get("TargetResources")))
    details = sequence(row.get("additionalDetails", row.get("AdditionalDetails")))
    explicit_host = next(
        (item.get("value") for item in details if item.get("key") in {"Computer", "DeviceName"}),
        None,
    )
    group = next((item for item in targets if item.get("type") == "Group"), {})
    activity = present(row.get("activityDisplayName"), row.get("OperationName"))
    if not isinstance(activity, str):
        raise DomainError("Directory audit activity name is required")
    actions = {
        "Add member to group": "group_member_added",
        "Remove member from group": "group_member_removed",
        "Add user": "account_created",
        "Delete user": "account_deleted",
        "Update user": "account_modified",
    }
    result = str(present(row.get("result"), row.get("Result"), "unknown")).lower()
    return {
        "event": {
            "timestamp": stamp(row.get(profile.timestamp)),
            "category": "identity",
            "action": actions.get(activity, "directory_audit"),
            "outcome": result if result in {"success", "failure"} else "unknown",
        },
        "host": {"name": present(row.get("Computer"), explicit_host)},
        "user": {"name": present(user.get("userPrincipalName"), app.get("displayName"))},
        "source": {"ip": present(user.get("ipAddress"))},
        "metadata": {
            "group_name": group.get("displayName"),
            "activity": activity,
            "targets": targets,
            "identity": {"id": user.get("id")},
        },
    }


def sentinel_windows(row: dict[str, Any]) -> NormalizedEvent:
    data = row.get("EventData", {})
    data = (
        event_data(data)
        if isinstance(data, str) and data.lstrip().startswith("<")
        else mapping(data)
    )
    fields = (
        "SubjectUserName",
        "TargetUserName",
        "MemberName",
        "IpAddress",
        "IpPort",
        "NewProcessName",
        "ParentProcessName",
        "CommandLine",
        "TargetDomainName",
        "TargetUserSid",
        "SubjectUserSid",
        "NewProcessId",
    )
    data = {**{key: row[key] for key in fields if key in row}, **data}
    return parse_windows(
        {
            "Event": {
                "System": {
                    "EventID": row.get("EventID"),
                    "TimeCreated": {"SystemTime": row.get("TimeGenerated")},
                    "Computer": row.get("Computer"),
                    "Channel": "Security",
                    "Provider": {
                        "Name": row.get("EventSourceName", "Microsoft-Windows-Security-Auditing")
                    },
                },
                "EventData": data,
            }
        }
    )


def device(row: dict[str, Any], profile: QueryProfile) -> dict[str, Any]:
    process = profile.normalizer == "device_process"
    network = profile.normalizer in {"device_network", "cef"}
    logon = profile.normalizer == "device_logon"
    additional = mapping(row.get("AdditionalFields"))
    dns = profile.normalizer == "device_event" and row.get("ActionType") == "DnsQueryResponse"
    image = present(row.get("FileName"), row.get("ProcessName"))
    parent = row.get("InitiatingProcessFileName")
    action = (
        "process_created"
        if process
        else "dns_query"
        if dns
        else "connection"
        if network
        else "login"
        if logon
        else "device_event"
    )
    category = (
        "process"
        if process
        else "network"
        if network or dns
        else "authentication"
        if logon
        else "system"
    )
    result = row.get("ActionType")
    return {
        "event": {
            "timestamp": stamp(row.get(profile.timestamp)),
            "category": category,
            "action": action,
            "outcome": "failure"
            if result == "LogonFailed"
            else "success"
            if result == "LogonSuccess"
            else "unknown",
        },
        "host": {"name": present(row.get("DeviceName"), row.get("Computer"))},
        "user": {
            "name": present(
                row.get("AccountName"),
                row.get("InitiatingProcessAccountName"),
                row.get("SourceUserName"),
            )
        },
        "source": {
            "ip": present(
                row.get("LocalIP"), row.get("SourceIP"), row.get("RemoteIP") if logon else None
            ),
            "port": present(row.get("LocalPort"), row.get("SourcePort")),
        },
        "destination": {
            "ip": present(row.get("RemoteIP") if not logon else None, row.get("DestinationIP")),
            "port": present(row.get("RemotePort"), row.get("DestinationPort")),
        },
        "process": {
            "name": ntpath.basename(image) if isinstance(image, str) else None,
            "command_line": row.get("ProcessCommandLine"),
            "parent": {"name": parent},
        },
        "network": {"protocol": present(row.get("Protocol"))},
        "dns": {
            "query": present(additional.get("QueryName"), additional.get("DnsQuery"))
            if dns
            else None
        },
        "metadata": {"provider_action": result, "additional_fields": additional},
    }


def normalize_provider(
    row: dict[str, Any], profile: QueryProfile, provider: str, connector_id: str
) -> NormalizedEvent:
    check_tree(row)
    if provider == "windows_wef":
        event = parse_windows(row)
    elif profile.normalizer == "windows":
        event = sentinel_windows(row)
    elif profile.normalizer == "syslog":
        message = row.get("SyslogMessage")
        if not isinstance(message, str):
            raise DomainError("SyslogMessage is required")
        header = (
            f"{stamp(row.get(profile.timestamp)).isoformat()} {row.get('Computer', 'unknown')} "
        )
        event = parse_syslog(header + str(row.get("ProcessName", "syslog")) + ": " + message)
    else:
        if profile.normalizer == "signin":
            fields = signin(row, profile)
        elif profile.normalizer == "audit":
            fields = audit(row, profile)
        elif profile.normalizer == "azure_activity":
            fields = {
                "event": {
                    "timestamp": stamp(row.get(profile.timestamp)),
                    "category": "identity",
                    "action": "azure_activity",
                    "outcome": "unknown",
                },
                "user": {"name": present(row.get("Caller"))},
                "source": {"ip": present(row.get("CallerIpAddress"))},
                "metadata": {"operation": row.get("OperationNameValue")},
            }
        else:
            fields = device(row, profile)
        fields["event"]["source"] = provider
        event = normalize_record(fields, provider, raw=row)
    return attribution(event, row, provider, connector_id, profile.table)
