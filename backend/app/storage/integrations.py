from typing import Any

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.storage.models import Base, utcnow


class SchemaRevision(Base):
    __tablename__ = "schema_revisions"
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    applied_at: Mapped[str] = mapped_column(String(40), default=utcnow)


class ConnectorRecord(Base):
    __tablename__ = "connectors"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    definition: Mapped[dict[str, Any]] = mapped_column(JSON)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("runs.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(40), default="disabled")
    last_success: Mapped[str | None] = mapped_column(String(40))
    last_failure: Mapped[str | None] = mapped_column(String(40))
    last_error: Mapped[str | None] = mapped_column(String(100))
    last_event_time: Mapped[str | None] = mapped_column(String(40))
    events_received: Mapped[int] = mapped_column(Integer, default=0)
    events_processed: Mapped[int] = mapped_column(Integer, default=0)
    events_failed: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_events: Mapped[int] = mapped_column(Integer, default=0)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[str] = mapped_column(String(40), default=utcnow)
    updated_at: Mapped[str] = mapped_column(String(40), default=utcnow)


class CheckpointRecord(Base):
    __tablename__ = "connector_checkpoints"
    connector_id: Mapped[str] = mapped_column(
        ForeignKey("connectors.id", ondelete="CASCADE"), primary_key=True
    )
    profile: Mapped[str] = mapped_column(String(64), primary_key=True)
    state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    next_poll: Mapped[float] = mapped_column(Float, default=0, index=True)
    last_error: Mapped[str | None] = mapped_column(String(100))


class ConnectorEventRecord(Base):
    __tablename__ = "connector_events"
    connector_id: Mapped[str] = mapped_column(
        ForeignKey("connectors.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64))


class DestinationRecord(Base):
    __tablename__ = "notification_destinations"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    definition: Mapped[dict[str, Any]] = mapped_column(JSON)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[str] = mapped_column(String(40), default=utcnow)
    updated_at: Mapped[str] = mapped_column(String(40), default=utcnow)


class PolicyRecord(Base):
    __tablename__ = "notification_policies"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    definition: Mapped[dict[str, Any]] = mapped_column(JSON)
    updated_at: Mapped[str] = mapped_column(String(40), default=utcnow)


class DeliveryRecord(Base):
    __tablename__ = "notification_deliveries"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    alert_id: Mapped[str | None] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), index=True
    )
    destination_id: Mapped[str] = mapped_column(
        ForeignKey("notification_destinations.id"), index=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(64), unique=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[float] = mapped_column(Float, default=0)
    claimed_until: Mapped[float] = mapped_column(Float, default=0)
    claim: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[str] = mapped_column(String(40), default=utcnow)
    last_attempt_at: Mapped[str | None] = mapped_column(String(40))
    delivered_at: Mapped[str | None] = mapped_column(String(40))
    http_status: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(String(100))
    __table_args__ = (
        UniqueConstraint("alert_id", "destination_id"),
        Index("ix_delivery_due", "status", "next_attempt_at"),
    )


class DeliveryAttemptRecord(Base):
    __tablename__ = "notification_attempts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    delivery_id: Mapped[str] = mapped_column(
        ForeignKey("notification_deliveries.id", ondelete="CASCADE"), index=True
    )
    number: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[str] = mapped_column(String(40), default=utcnow)
    http_status: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(String(100))


class CredentialRecord(Base):
    __tablename__ = "integration_credentials"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    definition: Mapped[dict[str, Any]] = mapped_column(JSON)
    updated_at: Mapped[str] = mapped_column(String(40), default=utcnow)


class LeaseRecord(Base):
    __tablename__ = "integration_leases"
    name: Mapped[str] = mapped_column(String(100), primary_key=True)
    owner: Mapped[str] = mapped_column(String(64), default="")
    expires_at: Mapped[float] = mapped_column(Float, default=0)


INTEGRATION_MODELS = (
    ConnectorRecord,
    CheckpointRecord,
    ConnectorEventRecord,
    DestinationRecord,
    PolicyRecord,
    DeliveryRecord,
    DeliveryAttemptRecord,
    CredentialRecord,
    LeaseRecord,
)
