import hashlib
import json
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["informational", "low", "medium", "high", "critical"]
Category = Literal["authentication", "process", "network", "identity", "file"]
Outcome = Literal["success", "failure", "unknown"]
LogFormat = Literal["json", "jsonl", "csv", "syslog", "windows"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_max_length=16_384, validate_assignment=True)


class EventInfo(StrictModel):
    id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    timestamp: datetime
    source: str = Field(min_length=1, max_length=100)
    category: Category
    type: str = Field(default="info", min_length=1, max_length=100)
    action: str = Field(min_length=1, max_length=100)
    outcome: Outcome = "unknown"
    severity: Severity = "informational"

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timestamp requires an explicit timezone")
        if not 1970 <= value.year <= 2100:
            raise ValueError("Timestamp year must be between 1970 and 2100")
        return value.astimezone(UTC)


class Host(StrictModel):
    name: str | None = Field(default=None, max_length=255)
    ip: str | None = None

    @field_validator("ip")
    @classmethod
    def valid_ip(cls, value: str | None) -> str | None:
        return str(ip_address(value)) if value is not None else None


class User(StrictModel):
    name: str | None = Field(default=None, max_length=255)


class Endpoint(StrictModel):
    ip: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)

    @field_validator("ip")
    @classmethod
    def valid_ip(cls, value: str | None) -> str | None:
        return str(ip_address(value)) if value is not None else None


class ParentProcess(StrictModel):
    name: str | None = Field(default=None, max_length=255)
    executable: str | None = Field(default=None, max_length=4096)
    pid: int | None = Field(default=None, ge=0)


class Process(StrictModel):
    name: str | None = Field(default=None, max_length=255)
    executable: str | None = Field(default=None, max_length=4096)
    command_line: str | None = None
    pid: int | None = Field(default=None, ge=0)
    parent: ParentProcess = Field(default_factory=ParentProcess)


class Network(StrictModel):
    protocol: str | None = Field(default=None, max_length=32)


class DNS(StrictModel):
    query: str | None = Field(default=None, max_length=253)


class File(StrictModel):
    path: str | None = Field(default=None, max_length=4096)


class NormalizedEvent(StrictModel):
    event: EventInfo
    host: Host = Field(default_factory=Host)
    user: User = Field(default_factory=User)
    source: Endpoint = Field(default_factory=Endpoint)
    destination: Endpoint = Field(default_factory=Endpoint)
    process: Process = Field(default_factory=Process)
    network: Network = Field(default_factory=Network)
    dns: DNS = Field(default_factory=DNS)
    file: File = Field(default_factory=File)
    raw_event: dict[str, Any] | str
    metadata: dict[str, Any] = Field(default_factory=dict)


def stable_event_id(raw: dict[str, Any] | str, parser: str) -> str:
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(f"{parser}:{canonical}".encode()).hexdigest()[:32]


def get_field(data: dict[str, Any], path: str) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current
