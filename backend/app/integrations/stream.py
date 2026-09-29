import hashlib
from typing import TYPE_CHECKING, Any

from app.core.errors import DomainError
from app.integrations.schemas import ConnectorConfig
from app.integrations.transport import encoded_json
from app.schemas.events import NormalizedEvent
from app.storage.integrations import CheckpointRecord, ConnectorEventRecord, ConnectorRecord
from app.storage.models import AuditRecord, utcnow

if TYPE_CHECKING:
    from app.services.platform import Platform


def ingest_page(
    platform: "Platform",
    connector_id: str,
    config: ConnectorConfig,
    events: list[NormalizedEvent],
    actor: str,
    *,
    profile: str | None = None,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    with platform.lock, platform.db.session() as session:
        row = session.get(ConnectorRecord, connector_id)
        if row is None or row.definition != config.model_dump(mode="json") or not config.enabled:
            raise DomainError(
                "Connector changed or was disabled during ingestion", 409, "connector_changed"
            )
        fresh = []
        duplicates = 0
        seen: dict[str, str] = {}
        for event in events:
            digest = hashlib.sha256(encoded_json(event.model_dump(mode="json"))).hexdigest()
            previous = session.get(ConnectorEventRecord, (connector_id, event.event.id))
            known = previous.content_hash if previous else seen.get(event.event.id)
            if known is not None:
                if known != digest:
                    raise DomainError(
                        "Provider event ID was reused with different content", 409, "id_conflict"
                    )
                duplicates += 1
                continue
            seen[event.event.id] = digest
            session.add(
                ConnectorEventRecord(
                    connector_id=connector_id, event_id=event.event.id, content_hash=digest
                )
            )
            enriched = event.model_copy(deep=True)
            enriched.metadata = {
                **enriched.metadata,
                "ingested_at": utcnow(),
                "integration_mode": config.mode,
            }
            fresh.append(enriched)
        result: dict[str, Any] = {"events_stored": 0, "alerts_created": 0}
        if fresh:
            if row.run_id is None:
                run = platform._new_run(session, name=config.name, kind="connector")
                row.run_id = run.id
            result = platform.ingest(
                fresh, run_id=row.run_id, actor=actor, connector_worker=True, transaction=session
            )
        if profile is not None and state is not None:
            checkpoint = session.get(CheckpointRecord, (connector_id, profile))
            if checkpoint is None:
                checkpoint = CheckpointRecord(connector_id=connector_id, profile=profile)
                session.add(checkpoint)
            checkpoint.state, checkpoint.last_error = state, None
        row.events_received += len(events)
        row.events_processed += len(fresh)
        row.duplicate_events += duplicates
        row.last_success, row.last_error = utcnow(), None
        row.status = "mock" if config.mode == "demo" else "healthy"
        if fresh:
            row.last_event_time = max(
                [event.event.timestamp.isoformat() for event in fresh]
                + ([row.last_event_time] if row.last_event_time else [])
            )
        session.add(
            AuditRecord(
                actor=actor,
                action="connector_ingest",
                target=row.id,
                details={"received": len(events), "stored": len(fresh), "duplicates": duplicates},
            )
        )
        return {**result, "run_id": row.run_id, "duplicates_ignored": duplicates}
