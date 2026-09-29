from datetime import UTC, datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.schemas.events import Category, LogFormat, Outcome, Severity, StrictModel

AlertStatus = Literal["new", "investigating", "resolved", "false_positive", "suppressed"]
Speed = Literal["instant", "realtime", "10x"]


class IngestRequest(StrictModel):
    format: LogFormat
    content: str = Field(min_length=1, max_length=5 * 1024 * 1024)
    name: str = Field(default="Local import", min_length=1, max_length=255)
    run_id: str | None = Field(default=None, max_length=64)
    syslog_year: int = Field(default=2026, ge=1970, le=2100)


class EventFilters(StrictModel):
    q: str | None = Field(default=None, max_length=100)
    source_ip: str | None = Field(default=None, max_length=45)
    user_name: str | None = Field(default=None, max_length=255)
    category: Category | None = None
    action: str | None = Field(default=None, max_length=100)
    outcome: Outcome | None = None
    host_name: str | None = Field(default=None, max_length=255)
    process_name: str | None = Field(default=None, max_length=255)
    severity: Severity | None = None
    event_type: str | None = Field(default=None, max_length=100)
    event_source: str | None = Field(default=None, max_length=100)
    timestamp_from: datetime | None = None
    timestamp_to: datetime | None = None
    run_id: str | None = Field(default=None, max_length=64)
    offset: int = Field(default=0, ge=0, le=100_000)
    limit: int = Field(default=50, ge=1, le=100)

    @field_validator("timestamp_from", "timestamp_to")
    @classmethod
    def aware_time(cls, value: datetime | None) -> datetime | None:
        if value is not None:
            if value.tzinfo is None:
                raise ValueError("Time ranges require timezone-aware timestamps")
            return value.astimezone(UTC)
        return value

    @model_validator(mode="after")
    def ordered_times(self) -> "EventFilters":
        if self.timestamp_from and self.timestamp_to and self.timestamp_from > self.timestamp_to:
            raise ValueError("The start of the time range must precede its end")
        return self


class AlertFilters(StrictModel):
    q: str | None = Field(default=None, max_length=100)
    run_id: str | None = Field(default=None, max_length=64)
    severity: Severity | None = None
    status: AlertStatus | None = None
    rule_id: str | None = Field(default=None, max_length=128)
    offset: int = Field(default=0, ge=0, le=100_000)
    limit: int = Field(default=50, ge=1, le=100)


class RuleUpdate(StrictModel):
    enabled: bool


class RuleImport(StrictModel):
    yaml: str = Field(min_length=1, max_length=65_536)


class StatusUpdate(StrictModel):
    status: AlertStatus
    note: str = Field(default="", max_length=2000)


class ReplayRequest(StrictModel):
    dataset_id: str = Field(min_length=1, max_length=128)
    speed: Speed = "instant"


class ValidationRequest(StrictModel):
    dataset_id: str | None = Field(default=None, max_length=128)
    rule_id: str | None = Field(default=None, max_length=128)
    scope: Literal["bundled", "current"] = "bundled"


class TestRequest(StrictModel):
    dataset_id: str = Field(min_length=1, max_length=128)
    expected_alerts: int | None = Field(default=None, ge=0, le=10_000)


class SigmaRequest(StrictModel):
    yaml: str = Field(min_length=1, max_length=65_536)
    source_url: str | None = Field(default=None, max_length=2048)
    license: str | None = Field(default=None, max_length=128)
    license_url: str | None = Field(default=None, max_length=2048)


class SigmaImport(SigmaRequest):
    enabled: bool = False


class SigmaTest(SigmaRequest):
    dataset_id: str = Field(min_length=1, max_length=128)
    expected_alerts: int = Field(ge=0, le=10_000)


class ResetRequest(StrictModel):
    confirmation: Literal["RESET DEMO"]
    seed: bool = False
