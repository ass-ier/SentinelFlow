import secrets
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import delete, func, select

from app.core.errors import DomainError
from app.integrations.outbox import delivery_response
from app.integrations.profiles import profiles_for
from app.integrations.queue_worker import suppress_pending
from app.integrations.schemas import (
    ConnectorConfig,
    CredentialConfig,
    DestinationConfig,
    NotificationPolicy,
)
from app.integrations.settings import SecretStore
from app.storage.integrations import (
    CheckpointRecord,
    ConnectorRecord,
    CredentialRecord,
    DeliveryAttemptRecord,
    DeliveryRecord,
    DestinationRecord,
    PolicyRecord,
)
from app.storage.models import AuditRecord, utcnow

if TYPE_CHECKING:
    from app.services.platform import Platform


def connector_response(row: ConnectorRecord) -> dict[str, Any]:
    return {
        "id": row.id,
        **row.definition,
        "status": row.status,
        "last_success": row.last_success,
        "last_failure": row.last_failure,
        "last_error": row.last_error,
        "last_event_time": row.last_event_time,
        "events_received": row.events_received,
        "events_processed": row.events_processed,
        "events_failed": row.events_failed,
        "duplicate_events": row.duplicate_events,
        "retry_count": row.retry_count,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "run_id": row.run_id,
    }


class IntegrationManagement:
    def __init__(self, platform: "Platform", secret_store: SecretStore) -> None:
        self.platform, self.secrets = platform, secret_store

    def save_connector(
        self, config: ConnectorConfig, actor: str, connector_id: str | None = None
    ) -> dict[str, Any]:
        profiles_for(config)
        with self.platform.lock, self.platform.db.session() as session:
            row = session.get(ConnectorRecord, connector_id) if connector_id else None
            if connector_id and row is None:
                raise DomainError("Connector not found", 404, "not_found")
            if row:
                before = ConnectorConfig.model_validate(row.definition)
                if row.run_id and any(
                    getattr(before, key) != getattr(config, key)
                    for key in ("type", "mode", "tenant_id", "workspace_id")
                ):
                    raise DomainError(
                        "Create a new connector for a different telemetry source",
                        409,
                        "connector_identity",
                    )
                if before.mode != config.mode or any(
                    getattr(before, key) != getattr(config, key)
                    for key in ("type", "tenant_id", "workspace_id")
                ):
                    session.execute(
                        delete(CheckpointRecord).where(CheckpointRecord.connector_id == row.id)
                    )
                action = (
                    ("connector_enabled" if config.enabled else "connector_disabled")
                    if before.enabled != config.enabled
                    else "connector_modified"
                )
            else:
                if (session.scalar(select(func.count()).select_from(ConnectorRecord)) or 0) >= 20:
                    raise DomainError(
                        "This instance supports at most 20 connectors", 409, "connector_limit"
                    )
                row = ConnectorRecord(id=uuid.uuid4().hex, definition={})
                session.add(row)
                action = "connector_created"
            row.definition = config.model_dump(mode="json")
            row.updated_at = utcnow()
            row.status = "configured" if config.enabled else "disabled"
            session.add(AuditRecord(actor=actor, action=action, target=row.id))
            session.flush()
            return connector_response(row)

    def connectors(self) -> list[dict[str, Any]]:
        with self.platform.db.session() as session:
            result = []
            for row in session.scalars(
                select(ConnectorRecord).order_by(ConnectorRecord.created_at, ConnectorRecord.id)
            ):
                value = connector_response(row)
                value["checkpoints"] = [
                    {
                        "profile": checkpoint.profile,
                        "last_error": checkpoint.last_error,
                        "checkpoint": checkpoint.state.get("checkpoint"),
                        "continuation_pending": bool(checkpoint.state.get("start")),
                    }
                    for checkpoint in session.scalars(
                        select(CheckpointRecord).where(CheckpointRecord.connector_id == row.id)
                    )
                ]
                result.append(value)
            return result

    def save_destination(
        self, config: DestinationConfig, actor: str, destination_id: str | None = None
    ) -> dict[str, Any]:
        with self.platform.lock, self.platform.db.session() as session:
            row = session.get(DestinationRecord, destination_id) if destination_id else None
            if destination_id and (row is None or row.deleted):
                raise DomainError("Destination not found", 404, "not_found")
            if row:
                previous = DestinationConfig.model_validate(row.definition)
                if previous.mode != config.mode or previous.type != config.type:
                    raise DomainError(
                        "Create a new destination to change delivery type or mode",
                        409,
                        "destination_identity",
                    )
                action = (
                    ("destination_enabled" if config.enabled else "destination_disabled")
                    if previous.enabled != config.enabled
                    else "destination_modified"
                )
            else:
                if (
                    session.scalar(
                        select(func.count())
                        .select_from(DestinationRecord)
                        .where(~DestinationRecord.deleted)
                    )
                    or 0
                ) >= 20:
                    raise DomainError(
                        "This instance supports at most 20 destinations", 409, "destination_limit"
                    )
                row = DestinationRecord(id=uuid.uuid4().hex, definition={})
                session.add(row)
                action = "destination_created"
            row.definition, row.updated_at = config.model_dump(mode="json"), utcnow()
            if not config.enabled:
                suppress_pending(session, row.id)
            session.add(AuditRecord(actor=actor, action=action, target=row.id))
            session.flush()
            return {
                "id": row.id,
                **row.definition,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }

    def delete_destination(self, destination_id: str, actor: str) -> dict[str, str]:
        with self.platform.lock, self.platform.db.session() as session:
            row = session.get(DestinationRecord, destination_id)
            if row is None or row.deleted:
                raise DomainError("Destination not found", 404, "not_found")
            row.deleted = True
            row.definition = {**row.definition, "enabled": False, "url_ref": None, "auth_ref": None}
            suppress_pending(session, row.id)
            session.add(AuditRecord(actor=actor, action="destination_deleted", target=row.id))
        return {"status": "deleted"}

    def destinations(self) -> list[dict[str, Any]]:
        with self.platform.db.session() as session:
            result = []
            for row in session.scalars(
                select(DestinationRecord)
                .where(~DestinationRecord.deleted)
                .order_by(DestinationRecord.created_at)
            ):
                latest = session.scalar(
                    select(DeliveryRecord)
                    .where(DeliveryRecord.destination_id == row.id)
                    .order_by(DeliveryRecord.created_at.desc(), DeliveryRecord.id.desc())
                    .limit(1)
                )
                failures = (
                    session.scalar(
                        select(func.count())
                        .select_from(DeliveryRecord)
                        .where(
                            DeliveryRecord.destination_id == row.id,
                            DeliveryRecord.status.in_(["failed", "dead_letter"]),
                        )
                    )
                    or 0
                )
                result.append(
                    {
                        "id": row.id,
                        **row.definition,
                        "failure_count": failures,
                        "last_delivery": delivery_response(latest) if latest else None,
                        "health": "disabled"
                        if not row.definition["enabled"]
                        else latest.status
                        if latest
                        else "configured",
                    }
                )
            return result

    def save_policy(
        self, policy: NotificationPolicy, actor: str, policy_id: str | None = None
    ) -> dict[str, Any]:
        with self.platform.lock, self.platform.db.session() as session:
            for destination_id in policy.destinations:
                destination = session.get(DestinationRecord, destination_id)
                if destination is None or destination.deleted:
                    raise DomainError(
                        "Policy destination does not exist", 422, "destination_missing"
                    )
            row = session.get(PolicyRecord, policy_id) if policy_id else None
            if policy_id and row is None:
                raise DomainError("Policy not found", 404, "not_found")
            if row is None:
                if (session.scalar(select(func.count()).select_from(PolicyRecord)) or 0) >= 50:
                    raise DomainError(
                        "This instance supports at most 50 notification policies",
                        409,
                        "policy_limit",
                    )
                row = PolicyRecord(id=uuid.uuid4().hex, definition={})
                session.add(row)
            row.definition, row.updated_at = policy.model_dump(mode="json"), utcnow()
            session.add(AuditRecord(actor=actor, action="notification_policy_saved", target=row.id))
            return {"id": row.id, **row.definition}

    def policies(self) -> list[dict[str, Any]]:
        with self.platform.db.session() as session:
            return [
                {"id": row.id, **row.definition}
                for row in session.scalars(select(PolicyRecord).order_by(PolicyRecord.id))
            ]

    def delete_policy(self, policy_id: str, actor: str) -> dict[str, str]:
        with self.platform.lock, self.platform.db.session() as session:
            if session.get(PolicyRecord, policy_id) is None:
                raise DomainError("Policy not found", 404, "not_found")
            session.execute(delete(PolicyRecord).where(PolicyRecord.id == policy_id))
            session.add(
                AuditRecord(actor=actor, action="notification_policy_deleted", target=policy_id)
            )
        return {"status": "deleted"}

    def save_credential(
        self, config: CredentialConfig, actor: str, credential_id: str | None = None
    ) -> dict[str, Any]:
        value = self.secrets.read(config.token_ref) if config.enabled else ""
        if config.enabled and (
            not 32 <= len(value) <= 256
            or not value.isascii()
            or any(c.isspace() for c in value)
            or (
                self.platform.settings.api_token
                and secrets.compare_digest(value, self.platform.settings.api_token)
            )
        ):
            raise DomainError(
                "Use a separate random printable integration token of 32-256 characters",
                422,
                "credential_value",
            )
        with self.platform.lock, self.platform.db.session() as session:
            if config.connector_id:
                connector = session.get(ConnectorRecord, config.connector_id)
                if connector is None or connector.definition["type"] != "windows_wef":
                    raise DomainError(
                        "Credential must reference a Windows connector", 422, "collector_binding"
                    )
            others = list(session.scalars(select(CredentialRecord)))
            if any(
                row.id != credential_id and row.definition["token_ref"] == config.token_ref
                for row in others
            ):
                raise DomainError(
                    "This credential reference is already registered", 409, "credential_conflict"
                )
            row = session.get(CredentialRecord, credential_id) if credential_id else None
            if credential_id and row is None:
                raise DomainError("Credential not found", 404, "not_found")
            if row is None:
                if len(others) >= 50:
                    raise DomainError(
                        "This instance supports at most 50 integration credentials",
                        409,
                        "credential_limit",
                    )
                row = CredentialRecord(id=uuid.uuid4().hex, definition={})
                session.add(row)
            row.definition, row.updated_at = config.model_dump(mode="json"), utcnow()
            session.add(
                AuditRecord(actor=actor, action="integration_credential_changed", target=row.id)
            )
            return {"id": row.id, **row.definition}

    def credentials(self) -> list[dict[str, Any]]:
        with self.platform.db.session() as session:
            return [
                {
                    "id": row.id,
                    **CredentialConfig.model_validate(row.definition).model_dump(mode="json"),
                }
                for row in session.scalars(select(CredentialRecord))
            ]

    def deliveries(
        self, *, alert_id: str | None = None, offset: int = 0, limit: int = 50
    ) -> dict[str, Any]:
        with self.platform.db.session() as session:
            query = select(DeliveryRecord)
            if alert_id:
                query = query.where(DeliveryRecord.alert_id == alert_id)
            total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
            rows = session.scalars(
                query.order_by(DeliveryRecord.created_at.desc(), DeliveryRecord.id)
                .offset(offset)
                .limit(limit)
            )
            return {"items": [delivery_response(row) for row in rows], "total": total}

    def delivery(self, delivery_id: str) -> dict[str, Any]:
        with self.platform.db.session() as session:
            row = session.get(DeliveryRecord, delivery_id)
            if row is None:
                raise DomainError("Delivery not found", 404, "not_found")
            return {
                **delivery_response(row),
                "payload": row.payload,
                "attempts": [
                    {
                        "number": item.number,
                        "timestamp": item.timestamp,
                        "http_status": item.http_status,
                        "error": item.error,
                    }
                    for item in session.scalars(
                        select(DeliveryAttemptRecord)
                        .where(DeliveryAttemptRecord.delivery_id == row.id)
                        .order_by(DeliveryAttemptRecord.timestamp, DeliveryAttemptRecord.number)
                    )
                ],
            }
