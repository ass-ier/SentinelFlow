from typing import Any, Literal
from urllib.parse import quote

from pydantic import Field

from app.schemas.events import Severity, StrictModel
from app.storage.models import AlertRecord


class AlertSummary(StrictModel):
    id: str
    severity: Severity
    title: str
    rule: str
    status: str
    timestamp: str
    mitre_attack: list[str]


class NotificationPayload(StrictModel):
    event: Literal["security_alert", "notification_test"]
    version: Literal["1.0"] = "1.0"
    alert: AlertSummary | None = None
    source: dict[str, Any] = Field(default_factory=dict)
    detection: dict[str, str] = Field(default_factory=dict)
    investigation: dict[str, str | None] = Field(default_factory=dict)
    mock: bool = False


def alert_payload(alert: AlertRecord, base_url: str) -> dict[str, Any]:
    data = alert.payload
    sources = data.get("telemetry_sources", [])
    providers = sorted({item["provider"] for item in sources})
    connectors = sorted({item["connector_id"] for item in sources if item.get("connector_id")})
    payload = NotificationPayload(
        event="security_alert",
        alert=AlertSummary(
            id=alert.id,
            severity=alert.severity,
            title=data["rule_name"],
            rule=alert.rule_id,
            status=alert.status,
            timestamp=data["triggered_at"],
            mitre_attack=data["mitre_attack"],
        ),
        source={
            "provider": providers[0]
            if len(providers) == 1
            else "multiple"
            if providers
            else "manual_upload",
            "connector_id": connectors[0] if len(connectors) == 1 else None,
            "hosts": data["affected_entities"]["hosts"],
            "users": data["affected_entities"]["users"],
            "ips": data["source_entities"]["ips"],
            "provenance": sources,
        },
        detection={"name": data["rule_name"], "description": data["description"]},
        investigation={
            "url": f"{base_url}/alerts/{quote(alert.id, safe='')}" if base_url else None
        },
    )
    return payload.model_dump(mode="json")
