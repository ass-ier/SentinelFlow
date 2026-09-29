from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import AwareDatetime, Field, field_validator, model_validator

from app.core.safe import check_tree
from app.integrations.settings import REFERENCE_PATTERN
from app.schemas.events import Severity, StrictModel

ConnectorType = Literal["microsoft_sentinel", "microsoft_graph", "windows_wef"]
IntegrationMode = Literal["live", "demo"]
DeliveryStatus = Literal[
    "pending", "processing", "delivered", "failed", "suppressed", "dead_letter"
]
ScopeName = Literal["alerts:read", "alerts:notify", "notifications:test", "windows:ingest"]
GUID = r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"


class QuerySelection(StrictModel):
    id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z_]+$")
    enabled: bool = True
    interval_seconds: int = Field(default=60, ge=30, le=86400)


class ConnectorConfig(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    type: ConnectorType
    mode: IntegrationMode = "live"
    enabled: bool = False
    tenant_id: str | None = Field(default=None, pattern=GUID)
    client_id: str | None = Field(default=None, pattern=GUID)
    workspace_id: str | None = Field(default=None, pattern=GUID)
    secret_ref: str | None = Field(default=None, pattern=REFERENCE_PATTERN)
    profiles: list[QuerySelection] = Field(default_factory=list, max_length=12)
    overlap_seconds: int = Field(default=120, ge=0, le=3600)
    lookback_seconds: int = Field(default=900, ge=60, le=86400)
    page_size: int = Field(default=200, ge=1, le=500)
    max_pages: int = Field(default=5, ge=1, le=10)

    @model_validator(mode="after")
    def unique_profiles(self) -> "ConnectorConfig":
        if len({p.id for p in self.profiles}) != len(self.profiles):
            raise ValueError("Query profiles must be unique")
        return self


class EnabledUpdate(StrictModel):
    enabled: bool


class DestinationConfig(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    type: Literal["power_automate", "webhook"]
    enabled: bool = False
    mode: IntegrationMode = "live"
    url_ref: str | None = Field(default=None, pattern=REFERENCE_PATTERN)
    authentication: Literal["none", "bearer", "hmac"] = "none"
    auth_ref: str | None = Field(default=None, pattern=REFERENCE_PATTERN)
    timeout_seconds: int = Field(default=5, ge=1, le=15)
    max_attempts: int = Field(default=3, ge=1, le=5)
    retry_seconds: int = Field(default=5, ge=1, le=300)

    @model_validator(mode="after")
    def credentials(self) -> "DestinationConfig":
        if self.mode == "live" and not self.url_ref:
            raise ValueError("Live destinations require a server-side URL reference")
        if self.authentication != "none" and not self.auth_ref:
            raise ValueError("Authenticated destinations require a server-side secret reference")
        if self.mode == "demo" and (self.url_ref or self.auth_ref):
            raise ValueError("Mock destinations cannot use live secret references")
        return self


class NotificationPolicy(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    enabled: bool = True
    destinations: list[str] = Field(min_length=1, max_length=20)
    severities: list[Severity] = Field(default_factory=list, max_length=5)
    rule_ids: list[str] = Field(default_factory=list, max_length=100)
    providers: list[str] = Field(default_factory=list, max_length=10)
    mitre_techniques: list[str] = Field(default_factory=list, max_length=30)
    hosts: list[str] = Field(default_factory=list, max_length=50)
    users: list[str] = Field(default_factory=list, max_length=50)
    statuses: list[Literal["new", "investigating", "resolved", "false_positive", "suppressed"]] = (
        Field(default=["new"], min_length=1, max_length=5)
    )
    include_replays: bool = False

    @field_validator("destinations", "rule_ids", "providers", "mitre_techniques", "hosts", "users")
    @classmethod
    def bounded_values(cls, values: list[str]) -> list[str]:
        if any(not value or len(value) > 255 for value in values):
            raise ValueError("Filter values must contain 1-255 characters")
        return list(dict.fromkeys(values))


class CredentialConfig(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    token_ref: str = Field(pattern=r"^SENTINEL_INTEGRATION_[A-Z0-9_]{1,80}$")
    scopes: list[ScopeName] = Field(min_length=1, max_length=4)
    connector_id: str | None = Field(default=None, max_length=64)
    enabled: bool = True
    expires_at: AwareDatetime | None = None

    @field_validator("expires_at")
    @classmethod
    def utc_expiration(cls, value: datetime | None) -> datetime | None:
        return value.astimezone(UTC) if value is not None else None

    @model_validator(mode="after")
    def collector_binding(self) -> "CredentialConfig":
        if "windows:ingest" in self.scopes and not self.connector_id:
            raise ValueError("Collector credentials must be bound to one Windows connector")
        return self


class WindowsBatch(StrictModel):
    connector_id: str = Field(min_length=1, max_length=64)
    events: list[dict[str, Any]] = Field(min_length=1, max_length=200)

    @field_validator("events")
    @classmethod
    def bounded_tree(cls, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        check_tree(events)
        return events


class NotifyRequest(StrictModel):
    destination_ids: list[str] = Field(min_length=1, max_length=20)


class TestNotificationRequest(StrictModel):
    destination_id: str = Field(min_length=1, max_length=64)


class DemoRequest(StrictModel):
    source: ConnectorType = "microsoft_sentinel"
