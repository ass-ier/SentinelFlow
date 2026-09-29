from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> str:
    return datetime.now(UTC).isoformat()


class Base(DeclarativeBase):
    pass


class RuleRecord(Base):
    __tablename__ = "rules"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    definition: Mapped[dict[str, Any]] = mapped_column(JSON)
    yaml_text: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[str] = mapped_column(String(40), default=utcnow)


class RunRecord(Base):
    __tablename__ = "runs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(32))
    dataset_id: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), default="running")
    created_at: Mapped[str] = mapped_column(String(40), default=utcnow)
    completed_at: Mapped[str | None] = mapped_column(String(40))
    watermark: Mapped[str | None] = mapped_column(String(40))
    watermark_event_id: Mapped[str | None] = mapped_column(String(128))
    total_events: Mapped[int] = mapped_column(Integer, default=0)
    processed_events: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_events: Mapped[int] = mapped_column(Integer, default=0)
    alerts_created: Mapped[int] = mapped_column(Integer, default=0)
    speed: Mapped[str] = mapped_column(String(16), default="instant")
    error: Mapped[str | None] = mapped_column(Text)
    rules_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class EventRecord(Base):
    __tablename__ = "events"
    storage_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    event_id: Mapped[str] = mapped_column(String(128), index=True)
    timestamp: Mapped[str] = mapped_column(String(40), index=True)
    category: Mapped[str] = mapped_column(String(32), index=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    outcome: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(32))
    event_type: Mapped[str] = mapped_column(String(100))
    event_source: Mapped[str] = mapped_column(String(100))
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    host_name: Mapped[str | None] = mapped_column(String(255), index=True)
    user_name: Mapped[str | None] = mapped_column(String(255), index=True)
    process_name: Mapped[str | None] = mapped_column(String(255))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    __table_args__ = (
        UniqueConstraint("run_id", "event_id"),
        Index("ix_events_run_timestamp", "run_id", "timestamp"),
    )


class AlertRecord(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    created_at: Mapped[str] = mapped_column(String(40), default=utcnow)
    first_seen: Mapped[str] = mapped_column(String(40))
    last_seen: Mapped[str] = mapped_column(String(40))
    event_count: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    rule_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)


class EvidenceRecord(Base):
    __tablename__ = "alert_evidence"
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    event_storage_id: Mapped[str] = mapped_column(
        ForeignKey("events.storage_id", ondelete="CASCADE"), primary_key=True
    )


class AuditRecord(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[str] = mapped_column(String(40), default=utcnow)
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(100))
    target: Mapped[str] = mapped_column(String(128))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
