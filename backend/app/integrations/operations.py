import uuid
from typing import Any

from sqlalchemy import select

from app.core.errors import DomainError
from app.integrations.demo import demo_fixtures
from app.integrations.normalize import normalize_provider
from app.integrations.outbox import delivery_response, enqueue_alert
from app.integrations.payloads import NotificationPayload
from app.integrations.profiles import GRAPH_PROFILES, SENTINEL_PROFILES, QueryProfile
from app.integrations.runtime import IntegrationRuntime
from app.integrations.schemas import (
    ConnectorConfig,
    ConnectorType,
    DestinationConfig,
    NotificationPolicy,
    QuerySelection,
)
from app.integrations.stream import ingest_page
from app.storage.integrations import (
    ConnectorRecord,
    DeliveryRecord,
    DestinationRecord,
    PolicyRecord,
)
from app.storage.models import AlertRecord, AuditRecord, RunRecord


def enqueue_test(runtime: IntegrationRuntime, destination_id: str, actor: str) -> dict[str, Any]:
    runtime.limit(actor, "notification_send")
    with runtime.platform.lock, runtime.platform.db.session() as session:
        destination = session.get(DestinationRecord, destination_id)
        if destination is None or destination.deleted:
            raise DomainError("Destination not found", 404, "not_found")
        config = DestinationConfig.model_validate(destination.definition)
        if not config.enabled or (
            config.mode == "live" and not runtime.settings.notifications_enabled
        ):
            raise DomainError(
                "Enable this destination and server-side notifications before testing",
                409,
                "notifications_disabled",
            )
        identifier = uuid.uuid4().hex
        row = DeliveryRecord(
            id=identifier,
            destination_id=destination_id,
            idempotency_key=identifier,
            payload=NotificationPayload(
                event="notification_test", mock=config.mode == "demo"
            ).model_dump(mode="json"),
        )
        session.add(row)
        session.add(
            AuditRecord(actor=actor, action="notification_test_queued", target=destination_id)
        )
        session.flush()
        result = delivery_response(row)
    runtime.start()
    return result


def notify_alert(
    runtime: IntegrationRuntime, alert_id: str, destinations: list[str], actor: str
) -> dict[str, Any]:
    runtime.limit(actor, "notification_send")
    with runtime.platform.lock, runtime.platform.db.session() as session:
        alert = session.get(AlertRecord, alert_id)
        if alert is None:
            raise DomainError("Alert not found", 404, "not_found")
        run = session.get(RunRecord, alert.run_id)
        assert run is not None
        for identifier in destinations:
            destination = session.get(DestinationRecord, identifier)
            if destination is None or destination.deleted:
                raise DomainError("Destination not found", 404, "not_found")
        rows = enqueue_alert(session, alert, run, runtime.settings, destinations)
        session.add(
            AuditRecord(actor=actor, action="alert_notification_requested", target=alert.id)
        )
        result = {"items": [delivery_response(row) for row in rows], "total": len(rows)}
    runtime.start()
    return result


def run_demo(runtime: IntegrationRuntime, source: ConnectorType, actor: str) -> dict[str, Any]:
    runtime.limit(actor, "demo", count=5)
    identifier = "demo-" + source
    profiles = (
        SENTINEL_PROFILES[:2]
        if source == "microsoft_sentinel"
        else GRAPH_PROFILES
        if source == "microsoft_graph"
        else ()
    )
    config = ConnectorConfig(
        name=f"Demo {source.replace('_', ' ')}",
        type=source,
        mode="demo",
        enabled=True,
        page_size=5,
        max_pages=10,
        profiles=[QuerySelection(id=p.id) for p in profiles],
    )
    with runtime.platform.lock, runtime.platform.db.session() as session:
        if session.get(ConnectorRecord, identifier) is None:
            session.add(ConnectorRecord(id=identifier, definition=config.model_dump(mode="json")))
        else:
            row = session.get(ConnectorRecord, identifier)
            assert row is not None
            config = ConnectorConfig.model_validate(row.definition)
        if session.get(DestinationRecord, "demo-power-automate") is None:
            session.add(
                DestinationRecord(
                    id="demo-power-automate",
                    definition=DestinationConfig(
                        name="Mock Power Automate", type="power_automate", mode="demo", enabled=True
                    ).model_dump(mode="json"),
                )
            )
        if session.get(PolicyRecord, "demo-notifications") is None:
            session.add(
                PolicyRecord(
                    id="demo-notifications",
                    definition=NotificationPolicy(
                        name="Offline demonstration",
                        destinations=["demo-power-automate"],
                        providers=["microsoft_sentinel", "microsoft_graph", "windows_wef"],
                    ).model_dump(mode="json"),
                )
            )
        session.add(
            AuditRecord(actor=actor, action="integration_demo_requested", target=identifier)
        )
    if source == "windows_wef":
        events = [
            normalize_provider(
                row,
                QueryProfile("windows", "WindowsEvent", "", "windows"),
                "windows_wef",
                identifier,
            )
            for row in demo_fixtures()["windows"]
        ]
        ingest_page(runtime.platform, identifier, config, events, actor)
    else:
        runtime.poll(identifier, actor)
    if runtime.claim("worker"):
        try:
            for _ in range(20):
                if not runtime.queue.process_one():
                    break
        finally:
            runtime.release("worker")
    runtime.start()
    with runtime.platform.db.session() as session:
        row = session.get(ConnectorRecord, identifier)
        assert row is not None
        deliveries = list(
            session.scalars(
                select(DeliveryRecord)
                .join(AlertRecord, DeliveryRecord.alert_id == AlertRecord.id)
                .where(AlertRecord.run_id == row.run_id)
            )
        )
        return {
            "mode": "demo",
            "connector_id": identifier,
            "run_id": row.run_id,
            "events_processed": row.events_processed,
            "status": row.status,
            "deliveries": [delivery_response(delivery) for delivery in deliveries],
            "live_tested": False,
        }
