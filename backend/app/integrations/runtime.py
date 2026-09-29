import logging
import os
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, or_, select, update
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.exc import SQLAlchemyError

from app.core.errors import DomainError
from app.integrations.connectors import GraphConnector, MicrosoftConnector, SentinelConnector
from app.integrations.destinations import WebhookDestination
from app.integrations.management import IntegrationManagement, connector_response
from app.integrations.normalize import ProviderDataError
from app.integrations.profiles import GRAPH_PROFILES, SENTINEL_PROFILES, profiles_for
from app.integrations.queue_worker import NotificationWorker
from app.integrations.schemas import ConnectorConfig, DestinationConfig, QuerySelection
from app.integrations.settings import EnvironmentSecrets, IntegrationSettings
from app.integrations.stream import ingest_page
from app.integrations.transport import SafeHTTPTransport
from app.storage.integrations import (
    CheckpointRecord,
    ConnectorRecord,
    DeliveryRecord,
    DestinationRecord,
    LeaseRecord,
)
from app.storage.models import AuditRecord, utcnow

if TYPE_CHECKING:
    from app.integrations.demo import DemoServer
    from app.services.platform import Platform

logger = logging.getLogger("sentinelflow.integrations")


class IntegrationRuntime:
    def __init__(self, platform: "Platform") -> None:
        self.platform = platform
        self.settings = platform.settings.integrations
        self.secrets = EnvironmentSecrets()
        self.transport = SafeHTTPTransport(self.settings)
        self.management = IntegrationManagement(platform, self.secrets)
        self.queue = NotificationWorker(
            platform.db, self.destination, notifications_enabled=self.settings.notifications_enabled
        )
        self.owner = uuid.uuid4().hex
        self.lock = threading.Lock()
        self.tick_lock = threading.Lock()
        self.demo_lock = threading.Lock()
        self.stopping = threading.Event()
        self.wake = threading.Event()
        self.thread: threading.Thread | None = None
        self.last_error: str | None = None
        self.demo: DemoServer | None = None
        self.rate_lock = threading.Lock()
        self.rate: dict[str, deque[float]] = defaultdict(deque)
        if not platform.settings.public_demo:
            self.seed()

    def seed(self) -> None:
        defaults = (
            (
                "sentinel-default",
                "Microsoft Sentinel",
                "microsoft_sentinel",
                "SENTINEL",
                self.settings.sentinel_enabled,
            ),
            (
                "graph-default",
                "Microsoft Entra / Graph",
                "microsoft_graph",
                "GRAPH",
                self.settings.graph_enabled,
            ),
            (
                "windows-default",
                "Windows / AD / WEF",
                "windows_wef",
                "WINDOWS",
                self.settings.windows_enabled,
            ),
        )
        with self.platform.db.session() as session:
            for identifier, name, kind, prefix, enabled in defaults:
                if session.get(ConnectorRecord, identifier):
                    continue
                profiles = (
                    SENTINEL_PROFILES[:2]
                    if kind == "microsoft_sentinel"
                    else GRAPH_PROFILES
                    if kind == "microsoft_graph"
                    else ()
                )
                config = ConnectorConfig.model_validate(
                    {
                        "name": name,
                        "type": kind,
                        "enabled": enabled,
                        "tenant_id": os.getenv(f"{prefix}_TENANT_ID") or None,
                        "client_id": os.getenv(f"{prefix}_CLIENT_ID") or None,
                        "workspace_id": os.getenv("SENTINEL_WORKSPACE_ID") or None
                        if kind == "microsoft_sentinel"
                        else None,
                        "secret_ref": f"{prefix}_CLIENT_SECRET" if kind != "windows_wef" else None,
                        "profiles": [
                            QuerySelection(
                                id=p.id,
                                interval_seconds=int(
                                    os.getenv(f"{prefix}_POLL_INTERVAL_SECONDS", "60")
                                ),
                            ).model_dump()
                            for p in profiles
                        ],
                    }
                )
                session.add(
                    ConnectorRecord(
                        id=identifier,
                        definition=config.model_dump(mode="json"),
                        status="configured" if enabled else "disabled",
                    )
                )

    def start(self) -> None:
        if self.platform.settings.public_demo or not self.settings.worker_enabled:
            return
        if self.thread is None or not self.thread.is_alive():
            self.thread = threading.Thread(
                target=self._worker, daemon=True, name="sentinel-integrations"
            )
            self.thread.start()
        self.wake.set()

    def resume(self) -> None:
        with self.platform.db.session() as session:
            configured = any(
                definition["enabled"]
                for model in (ConnectorRecord, DestinationRecord)
                for definition in session.scalars(select(model.definition))
            )
            pending = session.scalar(
                select(DeliveryRecord.id)
                .where(DeliveryRecord.status.in_(["pending", "processing", "failed"]))
                .limit(1)
            )
        if self.settings.external_enabled or configured or pending:
            self.start()

    def close(self) -> None:
        self.stopping.set()
        self.wake.set()
        if self.thread:
            self.thread.join(timeout=90)
            if self.thread.is_alive():
                raise RuntimeError(
                    "Integration worker did not stop within its bounded shutdown period"
                )
        if self.demo:
            self.demo.close()
        with self.platform.db.session() as session:
            session.execute(
                update(LeaseRecord)
                .where(LeaseRecord.owner == self.owner)
                .values(owner="", expires_at=0)
            )

    def _worker(self) -> None:
        while not self.stopping.is_set():
            try:
                self.tick()
                self.last_error = None
            except (DomainError, SQLAlchemyError) as exc:
                self.last_error = (
                    exc.code if isinstance(exc, DomainError) else "database_unavailable"
                )
                logger.error("Integration worker deferred: %s", self.last_error)
                self.stopping.wait(5)
            except Exception as exc:
                self.last_error = "worker_failed"
                logger.error("Integration worker stopped after unexpected %s", type(exc).__name__)
                return
            self.wake.wait(1)
            self.wake.clear()

    def limit(self, actor: str, operation: str, *, count: int = 10) -> None:
        with self.rate_lock:
            now = time.monotonic()
            key = f"{actor}:{operation}"
            if key not in self.rate and len(self.rate) >= 256:
                raise DomainError(
                    "Integration request capacity reached", 429, "integration_rate_limit"
                )
            entries = self.rate[key]
            while entries and entries[0] <= now - 60:
                entries.popleft()
            if len(entries) >= count:
                raise DomainError(
                    "Integration request rate limit reached; retry later",
                    429,
                    "integration_rate_limit",
                )
            entries.append(now)

    def claim(self, name: str, ttl: float = 120) -> bool:
        with self.platform.db.session() as session:
            session.execute(
                insert(LeaseRecord)
                .values(name=name, owner="", expires_at=0)
                .on_conflict_do_nothing()
            )
            result = session.execute(
                update(LeaseRecord)
                .where(
                    LeaseRecord.name == name,
                    or_(LeaseRecord.owner == self.owner, LeaseRecord.expires_at <= time.time()),
                )
                .values(owner=self.owner, expires_at=time.time() + ttl)
            )
            return result.rowcount == 1

    def release(self, name: str) -> None:
        with self.platform.db.session() as session:
            session.execute(
                update(LeaseRecord)
                .where(LeaseRecord.name == name, LeaseRecord.owner == self.owner)
                .values(owner="", expires_at=0)
            )

    def ensure_enabled(self, config: ConnectorConfig) -> None:
        if self.platform.settings.public_demo:
            raise DomainError(
                "Integrations are disabled in the public demo", 403, "public_demo_restricted"
            )
        allowed = {
            "microsoft_sentinel": self.settings.sentinel_enabled,
            "microsoft_graph": self.settings.graph_enabled,
            "windows_wef": self.settings.windows_enabled,
        }
        if config.mode == "live" and not allowed[config.type]:
            raise DomainError(
                "Enable this integration in the server environment first",
                409,
                "integration_disabled",
            )

    def demo_server(self) -> "DemoServer":
        from app.integrations.demo import DemoServer

        with self.demo_lock:
            if self.demo is None:
                self.demo = DemoServer()
            return self.demo

    def adapter(self, connector_id: str, config: ConnectorConfig) -> MicrosoftConnector:
        implementation = (
            SentinelConnector if config.type == "microsoft_sentinel" else GraphConnector
        )
        if config.mode == "demo":
            from app.integrations.demo import DemoSecrets

            server = self.demo_server()
            demo_config = config.model_copy(
                update={
                    "tenant_id": "00000000-0000-0000-0000-000000000001",
                    "client_id": "00000000-0000-0000-0000-000000000002",
                    "workspace_id": "00000000-0000-0000-0000-000000000003",
                    "secret_ref": "SENTINEL_INTEGRATION_DEMO_SECRET",
                }
            )
            return implementation(
                connector_id,
                demo_config,
                SafeHTTPTransport(IntegrationSettings(allow_local_http=True)),
                DemoSecrets(),
                api_base=server.url,
                oauth_base=server.url,
            )
        return implementation(connector_id, config, self.transport, self.secrets)

    def destination(self, config: DestinationConfig) -> WebhookDestination:
        if config.mode == "demo":
            policy = IntegrationSettings(allow_local_http=True)
            return WebhookDestination(
                config,
                SafeHTTPTransport(policy),
                self.secrets,
                policy,
                demo_url=self.demo_server().url + "/notifications",
            )
        return WebhookDestination(config, self.transport, self.secrets, self.settings)

    def poll(
        self, connector_id: str, actor: str, *, test: bool = False, due_only: bool = False
    ) -> dict[str, Any]:
        with self.platform.db.session() as session:
            row = session.get(ConnectorRecord, connector_id)
            if row is None:
                raise DomainError("Connector not found", 404, "not_found")
            config = ConnectorConfig.model_validate(row.definition)
        self.ensure_enabled(config)
        if not config.enabled and not test:
            raise DomainError("Enable the connector before polling", 409, "connector_disabled")
        if config.type == "windows_wef":
            raise DomainError(
                "Windows collectors push authenticated batches; they cannot be polled remotely",
                409,
                "collector_push",
            )
        if not self.lock.acquire(blocking=False):
            raise DomainError(
                "An integration operation is already running", 409, "integration_busy"
            )
        lease = f"connector:{connector_id}"
        try:
            if not self.claim(lease):
                raise DomainError(
                    "Another process owns this connector checkpoint", 409, "integration_busy"
                )
            adapter = self.adapter(connector_id, config)
            adapter.start()
            catalog = profiles_for(config)
            now = (
                datetime(2026, 1, 15, 10, 10, tzinfo=UTC)
                if config.mode == "demo"
                else datetime.now(UTC)
            )
            selected = [p for p in config.profiles if p.enabled]
            if not selected:
                raise DomainError("Enable at least one query profile", 409, "query_profile")
            for selection in selected:
                with self.platform.db.session() as session:
                    checkpoint = session.get(CheckpointRecord, (connector_id, selection.id))
                    state = checkpoint.state if checkpoint else {}
                    if due_only and checkpoint and checkpoint.next_poll > time.time():
                        continue
                try:
                    previous_retries = adapter.retries
                    if test:
                        adapter.test_connection(catalog[selection.id], now)
                    else:
                        for _ in range(config.max_pages):
                            page = adapter.poll(catalog[selection.id], state, now)
                            ingest_page(
                                self.platform,
                                connector_id,
                                config,
                                page.events,
                                actor,
                                profile=selection.id,
                                state=page.state,
                            )
                            state = page.state
                            if page.complete:
                                break
                    self._poll_status(
                        connector_id,
                        selection.id,
                        selection.interval_seconds,
                        None,
                        actor,
                        adapter.retries - previous_retries,
                        test,
                    )
                except DomainError as exc:
                    self._poll_status(
                        connector_id,
                        selection.id,
                        selection.interval_seconds,
                        exc,
                        actor,
                        adapter.retries - previous_retries,
                        test,
                    )
                    if test:
                        raise
            with self.platform.db.session() as session:
                current = session.get(ConnectorRecord, connector_id)
                assert current is not None
                failures = [
                    checkpoint.last_error
                    for checkpoint in session.scalars(
                        select(CheckpointRecord).where(
                            CheckpointRecord.connector_id == connector_id,
                            CheckpointRecord.profile.in_([item.id for item in selected]),
                        )
                    )
                    if checkpoint.last_error
                ]
                if failures:
                    current.status, current.last_error = "degraded", failures[0]
                return connector_response(current)
        finally:
            try:
                self.release(lease)
            finally:
                self.lock.release()

    def _poll_status(
        self,
        connector_id: str,
        profile: str,
        interval: int,
        error: DomainError | None,
        actor: str,
        retries: int,
        test: bool,
    ) -> None:
        with self.platform.lock, self.platform.db.session() as session:
            row = session.get(ConnectorRecord, connector_id)
            if row is None:
                return
            checkpoint = session.get(CheckpointRecord, (connector_id, profile))
            if checkpoint is None:
                checkpoint = CheckpointRecord(connector_id=connector_id, profile=profile, state={})
                session.add(checkpoint)
            delay = getattr(error, "retry_after", None) if error else None
            checkpoint.next_poll = time.time() + max(interval, delay or 0)
            checkpoint.last_error = error.code if error else None
            row.retry_count += retries
            if error:
                if isinstance(error, ProviderDataError):
                    row.events_failed += error.received
                    row.events_received += error.received
                row.last_error, row.last_failure = error.code, utcnow()
                row.status = error.code if row.definition["enabled"] else "disabled"
                logger.warning(
                    "Connector operation failed connector=%s code=%s", row.id, error.code
                )
            elif test:
                row.last_success, row.last_error = utcnow(), None
                row.status = (
                    ("mock" if row.definition["mode"] == "demo" else "healthy")
                    if row.definition["enabled"]
                    else "disabled"
                )
            session.add(
                AuditRecord(
                    actor=actor,
                    action="connector_test" if test else "connector_poll",
                    target=connector_id,
                    details={"profile": profile, "error": error.code if error else None},
                )
            )

    def tick(self) -> None:
        if self.platform.settings.public_demo or not self.tick_lock.acquire(blocking=False):
            return
        try:
            if not self.claim("worker"):
                return
            for item in self.management.connectors():
                config = ConnectorConfig.model_validate(
                    {key: item[key] for key in ConnectorConfig.model_fields}
                )
                if config.enabled and config.type != "windows_wef":
                    self.claim("worker")
                    try:
                        self.poll(item["id"], "integration-worker", due_only=True)
                    except DomainError as exc:
                        if exc.code not in {"integration_disabled", "integration_busy"}:
                            raise
                if self.stopping.is_set():
                    return
            for _ in range(20):
                if (
                    self.stopping.is_set()
                    or not self.claim("worker")
                    or not self.queue.process_one()
                ):
                    break
        finally:
            try:
                self.release("worker")
            finally:
                self.tick_lock.release()

    def rejected_batch(self, connector_id: str, error: ProviderDataError, actor: str) -> None:
        with self.platform.lock, self.platform.db.session() as session:
            row = session.get(ConnectorRecord, connector_id)
            if row is not None:
                row.events_received += error.received
                row.events_failed += error.received
                row.last_failure, row.last_error = utcnow(), error.code
                row.status = "degraded"
                session.add(
                    AuditRecord(
                        actor=actor,
                        action="collector_batch_rejected",
                        target=connector_id,
                        details={"count": error.received, "error": error.code},
                    )
                )

    def overview(self) -> dict[str, Any]:
        with self.platform.db.session() as session:
            counts = {
                status: count
                for status, count in session.execute(
                    select(DeliveryRecord.status, func.count()).group_by(DeliveryRecord.status)
                )
            }
        return {
            "connectors": self.management.connectors(),
            "notifications": counts,
            "external_enabled": self.settings.external_enabled,
            "notifications_enabled": self.settings.notifications_enabled,
            "public_demo": self.platform.settings.public_demo,
            "worker": {
                "running": bool(self.thread and self.thread.is_alive()),
                "enabled": self.settings.worker_enabled,
                "last_error": self.last_error,
            },
            "profiles": {
                "microsoft_sentinel": [vars(p) for p in SENTINEL_PROFILES],
                "microsoft_graph": [vars(p) for p in GRAPH_PROFILES],
            },
        }
