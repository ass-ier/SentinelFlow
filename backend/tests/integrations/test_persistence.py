from copy import deepcopy
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.exc import OperationalError

from app.core.config import Settings
from app.core.errors import DomainError
from app.integrations.demo import demo_fixtures
from app.integrations.normalize import normalize_provider
from app.integrations.operations import run_demo
from app.integrations.profiles import GRAPH_PROFILES
from app.integrations.schemas import ConnectorConfig, QuerySelection
from app.integrations.settings import IntegrationSettings
from app.integrations.stream import ingest_page
from app.services.platform import Platform
from app.storage.integrations import (
    INTEGRATION_MODELS,
    CheckpointRecord,
    ConnectorRecord,
    CredentialRecord,
    DeliveryRecord,
    SchemaRevision,
)
from app.storage.models import (
    AlertRecord,
    AuditRecord,
    EventRecord,
    EvidenceRecord,
    RuleRecord,
    RunRecord,
)

pytestmark = [pytest.mark.integration, pytest.mark.regression, pytest.mark.migration]


def test_actual_unversioned_schema_upgrade_preserves_existing_records(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'legacy.sqlite3'}"
    engine = create_engine(url)
    legacy = (RuleRecord, RunRecord, EventRecord, AlertRecord, EvidenceRecord, AuditRecord)
    for model in legacy:
        model.__table__.create(engine)
    with engine.begin() as connection:
        connection.execute(
            AuditRecord.__table__.insert().values(
                actor="existing", action="legacy", target="keep", details={"unchanged": True}
            )
        )
    engine.dispose()
    platform = Platform(
        Settings(database_url=url, integrations=IntegrationSettings(worker_enabled=False))
    )
    try:
        tables = set(inspect(platform.db.engine).get_table_names())
        assert {
            model.__tablename__ for model in (*legacy, *INTEGRATION_MODELS, SchemaRevision)
        } == tables
        with platform.db.session() as session:
            assert set(session.scalars(select(SchemaRevision.version))) == {1, 2}
            record = session.scalar(select(AuditRecord).where(AuditRecord.action == "legacy"))
            assert record.details == {"unchanged": True}
            assert all(
                not row.definition["enabled"] for row in session.scalars(select(ConnectorRecord))
            )
    finally:
        platform.close()
    restored = Platform(Settings(database_url=url))
    try:
        with restored.db.session() as session:
            assert len(list(session.scalars(select(SchemaRevision)))) == 2
    finally:
        restored.close()


def test_future_schema_is_rejected_before_any_additive_mutation(tmp_path: Path) -> None:
    from app.storage.migrations import migrate

    engine = create_engine(f"sqlite:///{tmp_path / 'future.sqlite3'}")
    SchemaRevision.__table__.create(engine)
    with engine.begin() as connection:
        connection.execute(SchemaRevision.__table__.insert().values(version=3))
    try:
        with pytest.raises(DomainError, match="newer"):
            migrate(engine)
        assert inspect(engine).get_table_names() == [SchemaRevision.__tablename__]
    finally:
        engine.dispose()


def test_reset_preserves_configuration_but_clears_demo_checkpoint_and_dedup_state(
    tmp_path: Path, monkeypatch
) -> None:
    import app.services.platform as module

    path = tmp_path / "sentinelflow-demo.sqlite3"
    monkeypatch.setattr(module, "DEMO_DB", path)
    service = Platform(
        Settings(
            database_url=f"sqlite:///{path}", integrations=IntegrationSettings(worker_enabled=False)
        )
    )
    try:
        run_demo(service.integrations, "microsoft_graph", "test")
        with pytest.raises(DomainError, match="Disable connectors"):
            service.reset_demo("test")
        from app.storage.integrations import DestinationRecord

        with service.db.session() as session:
            for model in (ConnectorRecord, DestinationRecord):
                for row in session.scalars(select(model)):
                    row.definition = {**row.definition, "enabled": False}
        assert service.reset_demo("test")["status"] == "reset"
        with service.db.session() as session:
            assert session.scalar(select(CheckpointRecord)) is None
            assert session.scalar(select(DeliveryRecord)) is None
            assert all(
                row.events_processed == 0 for row in session.scalars(select(ConnectorRecord))
            )
            assert session.scalar(select(CredentialRecord)) is None
            connector = session.get(ConnectorRecord, "demo-microsoft_graph")
            connector.definition = {**connector.definition, "enabled": True}
        assert service.integrations.poll("demo-microsoft_graph", "test")["events_processed"] == 13
    finally:
        service.close()


def test_pending_mock_delivery_resumes_automatically_after_process_restart(tmp_path: Path) -> None:
    import time

    from app.integrations.operations import enqueue_test
    from app.integrations.schemas import DestinationConfig

    url = f"sqlite:///{tmp_path / 'restart.sqlite3'}"
    service = Platform(
        Settings(database_url=url, integrations=IntegrationSettings(worker_enabled=False))
    )
    target = service.integrations.management.save_destination(
        DestinationConfig(name="Restart mock", type="webhook", mode="demo", enabled=True), "test"
    )
    queued = enqueue_test(service.integrations, target["id"], "test")
    service.close()
    restored = Platform(Settings(database_url=url))
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = restored.integrations.management.delivery(queued["id"])
            if result["status"] == "delivered":
                break
            time.sleep(0.05)
        assert result["status"] == "delivered"
        assert len(restored.integrations.demo.receipts) == 1
    finally:
        restored.close()


def test_checkpoint_dedup_and_alert_identity_survive_delayed_arrival_and_restart(
    tmp_path: Path,
) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'late.sqlite3'}",
        integrations=IntegrationSettings(worker_enabled=False),
    )
    service = Platform(settings)
    runtime = service.integrations
    report = run_demo(runtime, "microsoft_graph", "test")
    first = service.alerts({"run_id": report["run_id"], "rule_id": "AUTH-001"}, 0, 10)["items"][0]
    identifier = report["connector_id"]
    with service.db.session() as session:
        config = ConnectorConfig.model_validate(session.get(ConnectorRecord, identifier).definition)
    original = deepcopy(demo_fixtures()["graph"]["signIns"][0])
    original["id"] = "late-arrival"
    original["createdDateTime"] = "2026-01-15T09:59:30+00:00"
    event = normalize_provider(original, GRAPH_PROFILES[0], "microsoft_graph", identifier)
    result = ingest_page(
        service,
        identifier,
        config,
        [event],
        "test",
        profile="signins",
        state={"checkpoint": "2026-01-15T10:10:00+00:00"},
    )
    assert result["alerts_created"] == 0
    late = service.alert(first["id"])
    assert late["event_count"] == 11
    assert late["first_seen"] == "2026-01-15T09:59:30+00:00"
    assert len(late["evidence"]) == 11
    assert "ingested_at" not in event.metadata
    assert runtime.management.deliveries()["total"] == 2
    repeated = ingest_page(service, identifier, config, [event], "test")
    assert repeated["events_stored"] == 0
    assert repeated["duplicates_ignored"] == 1
    service.close()
    restored = Platform(settings)
    try:
        repeated = ingest_page(restored, identifier, config, [event], "test")
        assert repeated["duplicates_ignored"] == 1
        assert restored.alert(first["id"])["event_count"] == 11
        assert restored.integrations.management.deliveries()["total"] == 2
    finally:
        restored.close()


def test_duplicate_content_conflict_does_not_advance_checkpoint(service) -> None:
    report = run_demo(service.integrations, "microsoft_graph", "test")
    identifier = report["connector_id"]
    with service.db.session() as session:
        config = ConnectorConfig.model_validate(session.get(ConnectorRecord, identifier).definition)
        checkpoint = deepcopy(session.get(CheckpointRecord, (identifier, "signins")).state)
    raw = deepcopy(demo_fixtures()["graph"]["signIns"][0])
    raw["status"]["errorCode"] = 0
    event = normalize_provider(raw, GRAPH_PROFILES[0], "microsoft_graph", identifier)
    with pytest.raises(DomainError, match="reused"):
        ingest_page(
            service,
            identifier,
            config,
            [event],
            "test",
            profile="signins",
            state={"checkpoint": "2099-01-01T00:00:00Z"},
        )
    with service.db.session() as session:
        assert session.get(CheckpointRecord, (identifier, "signins")).state == checkpoint
    assert service.alerts({}, 0, 100)["total"] == 2


def test_atomic_rollback_includes_events_detections_outbox_and_checkpoint(
    service, monkeypatch
) -> None:
    runtime = service.integrations
    config = ConnectorConfig(
        name="Atomic Graph",
        type="microsoft_graph",
        mode="demo",
        enabled=True,
        profiles=[QuerySelection(id="signins")],
    )
    connector = runtime.management.save_connector(config, "test")
    original = service.ingest

    def unavailable(*args, **kwargs):
        original(*args, **kwargs)
        raise OperationalError("database unavailable", {}, None)

    monkeypatch.setattr(service, "ingest", unavailable)
    with pytest.raises(OperationalError):
        runtime.poll(connector["id"], "test")
    with service.db.session() as session:
        assert session.scalar(select(EventRecord)) is None
        assert session.scalar(select(AlertRecord)) is None
        assert session.scalar(select(DeliveryRecord)) is None
        assert session.get(CheckpointRecord, (connector["id"], "signins")) is None
    monkeypatch.setattr(service, "ingest", original)
    assert runtime.poll(connector["id"], "test")["events_processed"] == 12


def test_bounded_pages_persist_continuation_and_resume_after_restart(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'resume.sqlite3'}",
        integrations=IntegrationSettings(worker_enabled=False),
    )
    service = Platform(settings)
    config = ConnectorConfig(
        name="Budgeted Graph",
        type="microsoft_graph",
        mode="demo",
        enabled=True,
        page_size=3,
        max_pages=1,
        profiles=[QuerySelection(id="signins")],
    )
    connector = service.integrations.management.save_connector(config, "test")
    assert service.integrations.poll(connector["id"], "test")["events_processed"] == 3
    with service.db.session() as session:
        before = deepcopy(session.get(CheckpointRecord, (connector["id"], "signins")).state)
        assert before.get("next_link")
    service.close()
    restored = Platform(settings)
    try:
        for _ in range(3):
            restored.integrations.poll(connector["id"], "test")
        item = next(
            row
            for row in restored.integrations.management.connectors()
            if row["id"] == connector["id"]
        )
        assert item["events_processed"] == 12
        with restored.db.session() as session:
            checkpoint = session.get(CheckpointRecord, (connector["id"], "signins"))
            assert checkpoint.state == {"checkpoint": "2026-01-15T10:10:00+00:00"}
    finally:
        restored.close()
