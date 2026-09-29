from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Query, Request

from app.core.errors import DomainError
from app.core.security import analyst, get_platform, local_features
from app.integrations.auth import require_scope, scoped_identity
from app.integrations.normalize import ProviderDataError, normalize_batch
from app.integrations.operations import enqueue_test, notify_alert, run_demo
from app.integrations.profiles import QueryProfile
from app.integrations.runtime import IntegrationRuntime
from app.integrations.schemas import (
    ConnectorConfig,
    CredentialConfig,
    DemoRequest,
    DestinationConfig,
    EnabledUpdate,
    NotificationPolicy,
    NotifyRequest,
    TestNotificationRequest,
    WindowsBatch,
)
from app.integrations.stream import ingest_page
from app.services.platform import Platform
from app.storage.integrations import ConnectorRecord, DestinationRecord

router = APIRouter(tags=["Integrations"])
Service = Annotated[Platform, Depends(get_platform)]


def runtime(service: Service) -> IntegrationRuntime:
    return service.integrations


def administrator(
    request: Request, service: Service, authorization: Annotated[str | None, Header()] = None
) -> str:
    local_features(service)
    return analyst(request, service, authorization)


def notify_actor(
    request: Request, service: Service, authorization: Annotated[str | None, Header()] = None
) -> str:
    local_features(service)
    if scoped_identity(service, authorization) is not None:
        scope = (
            "notifications:test"
            if request.url.path.endswith("/notifications/test")
            else "alerts:notify"
        )
        return require_scope(service, authorization, scope)
    return analyst(request, service, authorization)


Runtime = Annotated[IntegrationRuntime, Depends(runtime)]
Admin = Annotated[str, Depends(administrator)]
Reader = Annotated[str, Depends(analyst)]
Notifier = Annotated[str, Depends(notify_actor)]


@router.get("/integrations")
def overview(service: Runtime, actor: Reader) -> dict[str, Any]:
    return service.overview()


@router.get("/integrations/connectors")
def connectors(service: Runtime, actor: Reader) -> dict[str, Any]:
    items = service.management.connectors()
    return {"items": items, "total": len(items)}


@router.post("/integrations/connectors", status_code=201)
def create_connector(body: ConnectorConfig, service: Runtime, actor: Admin) -> dict[str, Any]:
    service.limit(actor, "management", count=30)
    if body.enabled:
        service.ensure_enabled(body)
    result = service.management.save_connector(body, actor)
    if body.enabled:
        service.start()
    return result


@router.patch("/integrations/connectors/{connector_id}")
def edit_connector(
    connector_id: str, body: ConnectorConfig, service: Runtime, actor: Admin
) -> dict[str, Any]:
    service.limit(actor, "management", count=30)
    if body.enabled:
        service.ensure_enabled(body)
    result = service.management.save_connector(body, actor, connector_id)
    if body.enabled:
        service.start()
    return result


@router.post("/integrations/connectors/{connector_id}/enabled")
def enable_connector(
    connector_id: str, body: EnabledUpdate, service: Runtime, actor: Admin
) -> dict[str, Any]:
    with service.platform.db.session() as session:
        row = session.get(ConnectorRecord, connector_id)
        if row is None:
            raise DomainError("Connector not found", 404, "not_found")
        config = ConnectorConfig.model_validate({**row.definition, "enabled": body.enabled})
    return edit_connector(connector_id, config, service, actor)


@router.post("/integrations/connectors/{connector_id}/test")
def test_connector(connector_id: str, service: Runtime, actor: Admin) -> dict[str, Any]:
    service.limit(actor, "connection_test", count=5)
    return service.poll(connector_id, actor, test=True)


@router.post("/integrations/connectors/{connector_id}/poll")
def poll_connector(connector_id: str, service: Runtime, actor: Admin) -> dict[str, Any]:
    service.limit(actor, "connector_poll", count=5)
    return service.poll(connector_id, actor)


@router.post("/integrations/demo")
def demo(body: DemoRequest, service: Runtime, actor: Admin) -> dict[str, Any]:
    return run_demo(service, body.source, actor)


@router.post("/ingest/windows", status_code=202)
def windows(
    body: WindowsBatch, service: Runtime, authorization: Annotated[str | None, Header()] = None
) -> dict[str, Any]:
    actor = require_scope(service.platform, authorization, "windows:ingest", body.connector_id)
    service.limit(actor, "windows_ingest", count=120)
    with service.platform.db.session() as session:
        row = session.get(ConnectorRecord, body.connector_id)
        if row is None or row.definition["type"] != "windows_wef":
            raise DomainError("Windows connector not found", 404, "not_found")
        config = ConnectorConfig.model_validate(row.definition)
    service.ensure_enabled(config)
    if not service.claim(f"collector:{body.connector_id}"):
        raise DomainError(
            "Another process is ingesting this collector batch", 409, "integration_busy"
        )
    try:
        try:
            events = normalize_batch(
                body.events,
                QueryProfile("windows", "WindowsEvent", "", "windows"),
                "windows_wef",
                body.connector_id,
            )
        except ProviderDataError as exc:
            service.rejected_batch(body.connector_id, exc, actor)
            raise
        return ingest_page(service.platform, body.connector_id, config, events, actor)
    finally:
        service.release(f"collector:{body.connector_id}")


@router.get("/notifications/destinations", tags=["Notifications"])
def destinations(service: Runtime, actor: Reader) -> dict[str, Any]:
    items = service.management.destinations()
    return {"items": items, "total": len(items)}


@router.post("/notifications/destinations", status_code=201, tags=["Notifications"])
def create_destination(body: DestinationConfig, service: Runtime, actor: Admin) -> dict[str, Any]:
    service.limit(actor, "management", count=30)
    result = service.management.save_destination(body, actor)
    if body.enabled:
        service.start()
    return result


@router.patch("/notifications/destinations/{destination_id}", tags=["Notifications"])
def edit_destination(
    destination_id: str, body: DestinationConfig, service: Runtime, actor: Admin
) -> dict[str, Any]:
    service.limit(actor, "management", count=30)
    result = service.management.save_destination(body, actor, destination_id)
    if body.enabled:
        service.start()
    return result


@router.post("/notifications/destinations/{destination_id}/enabled", tags=["Notifications"])
def enable_destination(
    destination_id: str, body: EnabledUpdate, service: Runtime, actor: Admin
) -> dict[str, Any]:
    with service.platform.db.session() as session:
        row = session.get(DestinationRecord, destination_id)
        if row is None or row.deleted:
            raise DomainError("Destination not found", 404, "not_found")
        config = DestinationConfig.model_validate({**row.definition, "enabled": body.enabled})
    return edit_destination(destination_id, config, service, actor)


@router.delete("/notifications/destinations/{destination_id}", tags=["Notifications"])
def delete_destination(destination_id: str, service: Runtime, actor: Admin) -> dict[str, str]:
    return service.management.delete_destination(destination_id, actor)


@router.get("/notifications/policies", tags=["Notifications"])
def policies(service: Runtime, actor: Reader) -> dict[str, Any]:
    items = service.management.policies()
    return {"items": items, "total": len(items)}


@router.post("/notifications/policies", status_code=201, tags=["Notifications"])
def create_policy(body: NotificationPolicy, service: Runtime, actor: Admin) -> dict[str, Any]:
    return service.management.save_policy(body, actor)


@router.patch("/notifications/policies/{policy_id}", tags=["Notifications"])
def edit_policy(
    policy_id: str, body: NotificationPolicy, service: Runtime, actor: Admin
) -> dict[str, Any]:
    return service.management.save_policy(body, actor, policy_id)


@router.delete("/notifications/policies/{policy_id}", tags=["Notifications"])
def delete_policy(policy_id: str, service: Runtime, actor: Admin) -> dict[str, str]:
    return service.management.delete_policy(policy_id, actor)


@router.post("/alerts/{alert_id}/notify", status_code=202, tags=["Notifications"])
def notify(alert_id: str, body: NotifyRequest, service: Runtime, actor: Notifier) -> dict[str, Any]:
    return notify_alert(service, alert_id, body.destination_ids, actor)


@router.post("/notifications/test", status_code=202, tags=["Notifications"])
def notification_test(
    body: TestNotificationRequest, service: Runtime, actor: Notifier
) -> dict[str, Any]:
    return enqueue_test(service, body.destination_id, actor)


@router.get("/notifications/deliveries", tags=["Notifications"])
def deliveries(
    service: Runtime,
    actor: Reader,
    alert_id: str | None = Query(None, max_length=64),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
) -> dict[str, Any]:
    return service.management.deliveries(alert_id=alert_id, offset=offset, limit=limit)


@router.get("/notifications/deliveries/{delivery_id}", tags=["Notifications"])
def delivery(delivery_id: str, service: Runtime, actor: Reader) -> dict[str, Any]:
    return service.management.delivery(delivery_id)


@router.get("/integrations/credentials")
def credentials(service: Runtime, actor: Admin) -> dict[str, Any]:
    items = service.management.credentials()
    return {"items": items, "total": len(items)}


@router.post("/integrations/credentials", status_code=201)
def create_credential(body: CredentialConfig, service: Runtime, actor: Admin) -> dict[str, Any]:
    service.limit(actor, "credentials", count=10)
    return service.management.save_credential(body, actor)


@router.patch("/integrations/credentials/{credential_id}")
def edit_credential(
    credential_id: str, body: CredentialConfig, service: Runtime, actor: Admin
) -> dict[str, Any]:
    service.limit(actor, "credentials", count=10)
    return service.management.save_credential(body, actor, credential_id)
