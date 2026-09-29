from dataclasses import dataclass

from app.core.errors import DomainError
from app.integrations.schemas import ConnectorConfig


@dataclass(frozen=True)
class QueryProfile:
    id: str
    table: str
    timestamp: str
    normalizer: str


SENTINEL_PROFILES = (
    QueryProfile("signin_logs", "SigninLogs", "TimeGenerated", "signin"),
    QueryProfile("directory_audit", "AuditLogs", "TimeGenerated", "audit"),
    QueryProfile("windows_security", "SecurityEvent", "TimeGenerated", "windows"),
    QueryProfile("syslog", "Syslog", "TimeGenerated", "syslog"),
    QueryProfile("common_security", "CommonSecurityLog", "TimeGenerated", "cef"),
    QueryProfile("azure_activity", "AzureActivity", "TimeGenerated", "azure_activity"),
    QueryProfile("defender_device_events", "DeviceEvents", "Timestamp", "device_event"),
    QueryProfile("defender_process", "DeviceProcessEvents", "Timestamp", "device_process"),
    QueryProfile("defender_network", "DeviceNetworkEvents", "Timestamp", "device_network"),
    QueryProfile("defender_logon", "DeviceLogonEvents", "Timestamp", "device_logon"),
)
GRAPH_PROFILES = (
    QueryProfile("signins", "signIns", "createdDateTime", "signin"),
    QueryProfile("directory_audits", "directoryAudits", "activityDateTime", "audit"),
)


def profiles_for(config: ConnectorConfig) -> dict[str, QueryProfile]:
    profiles = (
        SENTINEL_PROFILES
        if config.type == "microsoft_sentinel"
        else GRAPH_PROFILES
        if config.type == "microsoft_graph"
        else ()
    )
    catalog = {profile.id: profile for profile in profiles}
    if any(profile.id not in catalog for profile in config.profiles):
        raise DomainError("Unsupported query profile for this connector", 422, "query_profile")
    return catalog
