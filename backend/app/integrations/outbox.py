import hashlib
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.integrations.payloads import alert_payload
from app.integrations.schemas import DestinationConfig, NotificationPolicy
from app.integrations.settings import IntegrationSettings
from app.storage.integrations import DeliveryRecord, DestinationRecord, PolicyRecord
from app.storage.models import AlertRecord, RunRecord


def policy_matches(policy: NotificationPolicy, alert: AlertRecord, run: RunRecord) -> bool:
    data = alert.payload
    actual = (
        (policy.severities, [alert.severity]),
        (policy.rule_ids, [alert.rule_id]),
        (policy.statuses, [alert.status]),
        (
            policy.providers,
            [s["provider"] for s in data.get("telemetry_sources", [])] or ["manual_upload"],
        ),
        (policy.mitre_techniques, data["mitre_attack"]),
        (policy.hosts, data["affected_entities"]["hosts"]),
        (policy.users, data["affected_entities"]["users"]),
    )
    return (
        policy.enabled
        and (run.kind != "replay" or policy.include_replays)
        and all(not wanted or set(wanted).intersection(values) for wanted, values in actual)
    )


def enqueue_alert(
    session: Session,
    alert: AlertRecord,
    run: RunRecord,
    settings: IntegrationSettings,
    destinations: list[str] | None = None,
) -> list[DeliveryRecord]:
    selected = set(destinations or [])
    if destinations is None:
        for record in session.scalars(select(PolicyRecord)):
            policy = NotificationPolicy.model_validate(record.definition)
            if policy_matches(policy, alert, run):
                selected.update(policy.destinations)
    records: list[DeliveryRecord] = []
    for destination_id in sorted(selected):
        destination = session.get(DestinationRecord, destination_id)
        if destination is None or destination.deleted:
            continue
        existing = session.scalar(
            select(DeliveryRecord).where(
                DeliveryRecord.alert_id == alert.id, DeliveryRecord.destination_id == destination_id
            )
        )
        if existing:
            records.append(existing)
            continue
        config = DestinationConfig.model_validate(destination.definition)
        reason = (
            "destination_disabled"
            if not config.enabled
            else "external_notifications_disabled"
            if config.mode == "live" and not settings.notifications_enabled
            else "alert_suppressed"
            if alert.status == "suppressed"
            else None
        )
        payload = alert_payload(alert, settings.public_base_url)
        payload["mock"] = config.mode == "demo"
        delivery = DeliveryRecord(
            id=uuid.uuid4().hex,
            alert_id=alert.id,
            destination_id=destination_id,
            idempotency_key=hashlib.sha256(f"{alert.id}:{destination_id}".encode()).hexdigest(),
            status="suppressed" if reason else "pending",
            error=reason,
            payload=payload,
        )
        session.add(delivery)
        records.append(delivery)
    session.flush()
    return records


def delivery_response(row: DeliveryRecord) -> dict[str, Any]:
    return {
        "id": row.id,
        "alert_id": row.alert_id,
        "destination_id": row.destination_id,
        "status": row.status,
        "attempt_count": row.attempt_count,
        "created_at": row.created_at,
        "last_attempt_at": row.last_attempt_at,
        "delivered_at": row.delivered_at,
        "http_status": row.http_status,
        "error": row.error,
        "idempotency_key": row.idempotency_key,
        "next_attempt_at": row.next_attempt_at if row.status == "failed" else None,
        "mock": row.payload.get("mock", False),
        "event": row.payload["event"],
    }
