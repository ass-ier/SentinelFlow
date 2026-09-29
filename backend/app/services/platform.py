from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from collections import Counter
from collections.abc import Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager, nullcontext
from datetime import UTC, datetime, timedelta
from typing import Any, TypedDict

import yaml
from sqlalchemy import delete, func, inspect, or_, select
from sqlalchemy.orm import Session

from app.core.config import DEMO_DB, PUBLIC_DEMO_RUN_LIMIT, ROOT, Settings
from app.core.errors import DomainError
from app.detection.engine import evaluate, unique_chronological
from app.detection.rules import MITRE_NAMES, Rule, load_bundled_rules
from app.integrations.correlation import retain_alert_identity, telemetry_sources
from app.integrations.outbox import delivery_response, enqueue_alert
from app.integrations.runtime import IntegrationRuntime
from app.schemas.events import NormalizedEvent
from app.services.datasets import DatasetStore
from app.storage.database import Database
from app.storage.integrations import INTEGRATION_MODELS, DeliveryRecord, SchemaRevision
from app.storage.models import (
    AlertRecord,
    AuditRecord,
    EventRecord,
    EvidenceRecord,
    RuleRecord,
    RunRecord,
    utcnow,
)

logger = logging.getLogger("sentinelflow")
PUBLIC_MARKER = "public_demo_initialized"


class TimelineBin(TypedDict):
    timestamp: str
    events: int
    alerts: int


def event_response(row: EventRecord) -> dict[str, Any]:
    return {"storage_id": row.storage_id, "run_id": row.run_id, **row.payload}


def alert_response(row: AlertRecord) -> dict[str, Any]:
    return {**row.payload, "run_id": row.run_id, "status": row.status, "created_at": row.created_at}


def rule_response(row: RuleRecord) -> dict[str, Any]:
    return {**row.definition, "yaml": row.yaml_text, "updated_at": row.updated_at}


def run_response(row: RunRecord) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "kind": row.kind,
        "dataset_id": row.dataset_id,
        "status": row.status,
        "created_at": row.created_at,
        "completed_at": row.completed_at,
        "total_events": row.total_events,
        "processed_events": row.processed_events,
        "duplicate_events": row.duplicate_events,
        "alerts_created": row.alerts_created,
        "speed": row.speed,
        "error": row.error,
        "watermark": row.watermark,
        "watermark_event_id": row.watermark_event_id,
        "metrics": row.metrics,
        "rules_count": len(row.rules_snapshot),
    }


class Platform:
    def __init__(self, settings: Settings, datasets: DatasetStore | None = None) -> None:
        self.settings = settings
        self.db = Database(settings.database_url)
        self.datasets = (
            DatasetStore(datasets.root if datasets else ROOT / "test-data", synthetic_only=True)
            if settings.public_demo
            else datasets or DatasetStore()
        )
        self.lock = threading.RLock()
        self.shutdown = threading.Event()
        self.executor = ThreadPoolExecutor(max_workers=settings.max_replay_jobs)
        self.jobs: dict[str, tuple[Future[None], threading.Event]] = {}
        self.validation_semaphore = threading.BoundedSemaphore(1)
        self._integrations: IntegrationRuntime | None = None
        initialized = False
        try:
            seed_public = self._claim_public_database() if settings.public_demo else False
            self.seed_rules()
            with self.db.session() as session:
                for run in session.scalars(
                    select(RunRecord).where(
                        RunRecord.kind == "replay", RunRecord.status.in_(["running", "pending"])
                    )
                ):
                    run.status = "failed"
                    run.error = (
                        "Server restarted before replay completed; start a new isolated replay"
                    )
                    run.completed_at = utcnow()
            if seed_public:
                self.reset_demo("public-demo", seed=True)
            self._integrations = IntegrationRuntime(self)
            self._integrations.resume()
            initialized = True
        finally:
            if not initialized:
                self.close()

    def _claim_public_database(self) -> bool:
        models = (RuleRecord, RunRecord, EventRecord, AlertRecord, EvidenceRecord, AuditRecord)
        if set(inspect(self.db.engine).get_table_names()) != {
            model.__tablename__ for model in (*models, *INTEGRATION_MODELS, SchemaRevision)
        }:
            raise DomainError(
                "Public demo refuses a database containing unrelated tables",
                503,
                "public_demo_database",
            )
        with self.db.session() as session:
            markers = list(
                session.scalars(select(AuditRecord).where(AuditRecord.action == PUBLIC_MARKER))
            )
            if not markers:
                if any(
                    session.scalar(select(func.count()).select_from(model))
                    for model in (*models, *INTEGRATION_MODELS)
                ):
                    raise DomainError(
                        "Public demo refuses an existing unmarked database. "
                        "Configure a new empty dedicated public-demo database.",
                        503,
                        "public_demo_database",
                    )
                session.add(
                    AuditRecord(
                        actor="public-demo",
                        action=PUBLIC_MARKER,
                        target="public-demo",
                        details={"version": 1, "seed_state": "initializing"},
                    )
                )
                return True
            if any(
                session.scalar(select(func.count()).select_from(model))
                for model in INTEGRATION_MODELS
            ):
                raise DomainError(
                    "Public demo refuses configured private integrations",
                    503,
                    "public_demo_database",
                )
            marker = markers[0]
            if (
                len(markers) != 1
                or marker.details.get("version") != 1
                or marker.details.get("seed_state") not in {"initializing", "ready"}
            ):
                raise DomainError(
                    "Invalid public demo ownership marker", 503, "public_demo_database"
                )
            if marker.details["seed_state"] == "initializing":
                return True
            allowed = {item["id"] for item in self.datasets.catalog()}
            for run in session.scalars(select(RunRecord)):
                if run.kind not in {"demo", "replay"} or run.dataset_id not in allowed:
                    raise DomainError(
                        "Public demo contains a run outside its synthetic catalog",
                        503,
                        "public_demo_database",
                    )
            bundled = {rule.id for rule in load_bundled_rules(ROOT / "rules")}
            if any(row.id not in bundled for row in session.scalars(select(RuleRecord))):
                raise DomainError(
                    "Public demo contains a non-bundled rule", 503, "public_demo_database"
                )
            return False

    @contextmanager
    def validation_slot(self) -> Iterator[None]:
        if not self.settings.public_demo:
            yield
            return
        if not self.validation_semaphore.acquire(blocking=False):
            raise DomainError(
                "Another public validation is running; retry shortly", 429, "validation_limit"
            )
        try:
            yield
        finally:
            self.validation_semaphore.release()

    def close(self) -> None:
        self.shutdown.set()
        if self._integrations is not None:
            self._integrations.close()
        self.executor.shutdown(wait=True, cancel_futures=False)
        self.db.close()

    @property
    def integrations(self) -> IntegrationRuntime:
        if self._integrations is None:
            raise DomainError("Integrations are not initialized", 503, "not_ready")
        return self._integrations

    def seed_rules(self, *, restore: bool = False) -> None:
        with self.lock, self.db.session() as session:
            if restore:
                session.execute(delete(RuleRecord))
            bundled = {rule.id: rule for rule in load_bundled_rules(ROOT / "rules")}
            for path in sorted((ROOT / "rules").glob("*.yml")):
                rule = bundled[path.stem]
                if session.get(RuleRecord, rule.id) is None:
                    session.add(
                        RuleRecord(
                            id=rule.id,
                            definition=rule.model_dump(mode="json", by_alias=True),
                            yaml_text=path.read_text(),
                        )
                    )

    @staticmethod
    def _rules(session: Session) -> list[Rule]:
        return [
            Rule.model_validate(row.definition)
            for row in session.scalars(select(RuleRecord).order_by(RuleRecord.id))
        ]

    def rules(self) -> list[dict[str, Any]]:
        with self.db.session() as session:
            return [
                rule_response(row)
                for row in session.scalars(select(RuleRecord).order_by(RuleRecord.id))
            ]

    def definitions(self) -> list[Rule]:
        with self.db.session() as session:
            return self._rules(session)

    def rule(self, rule_id: str) -> dict[str, Any]:
        with self.db.session() as session:
            row = session.get(RuleRecord, rule_id)
            if row is None:
                raise DomainError("Rule not found", 404, "not_found")
            return rule_response(row)

    def save_rule(self, rule: Rule, *, actor: str) -> dict[str, Any]:
        with self.lock, self.db.session() as session:
            if session.get(RuleRecord, rule.id):
                raise DomainError("A rule with this ID already exists", 409, "rule_conflict")
            if (session.scalar(select(func.count()).select_from(RuleRecord)) or 0) >= 100:
                raise DomainError("This local instance is limited to 100 rules", 409, "rule_limit")
            definition = rule.model_dump(mode="json", by_alias=True, exclude_none=True)
            row = RuleRecord(
                id=rule.id,
                definition=definition,
                yaml_text=yaml.safe_dump(definition, sort_keys=False),
                updated_at=utcnow(),
            )
            session.add(row)
            session.add(AuditRecord(actor=actor, action="rule_import", target=rule.id))
            session.flush()
            return rule_response(row)

    def toggle_rule(self, rule_id: str, enabled: bool, actor: str) -> dict[str, Any]:
        with self.lock, self.db.session() as session:
            row = session.get(RuleRecord, rule_id)
            if row is None:
                raise DomainError("Rule not found", 404, "not_found")
            row.definition = {**row.definition, "enabled": enabled}
            row.yaml_text = yaml.safe_dump(row.definition, sort_keys=False)
            row.updated_at = utcnow()
            session.add(
                AuditRecord(
                    actor=actor,
                    action="rule_enable" if enabled else "rule_disable",
                    target=rule_id,
                )
            )
            return rule_response(row)

    def _new_run(
        self,
        session: Session,
        *,
        name: str,
        kind: str = "import",
        dataset_id: str | None = None,
        total: int = 0,
        speed: str = "instant",
    ) -> RunRecord:
        run = RunRecord(
            id=uuid.uuid4().hex,
            name=name,
            kind=kind,
            dataset_id=dataset_id,
            total_events=total,
            status="pending" if kind == "replay" else "running",
            speed=speed,
            rules_snapshot=[
                rule.model_dump(mode="json", by_alias=True)
                for rule in self._rules(session)
                if rule.enabled
            ],
        )
        session.add(run)
        session.flush()
        return run

    def ingest(
        self,
        events: list[NormalizedEvent],
        *,
        name: str = "Local import",
        run_id: str | None = None,
        actor: str = "local-analyst",
        replay_worker: bool = False,
        connector_worker: bool = False,
        transaction: Session | None = None,
    ) -> dict[str, Any]:
        ordered, input_duplicates = unique_chronological(events)
        if not ordered:
            raise DomainError("Input contains no events")
        with (
            self.lock,
            self.db.session() if transaction is None else nullcontext(transaction) as session,
        ):
            run = session.get(RunRecord, run_id) if run_id else self._new_run(session, name=name)
            if run is None:
                raise DomainError("Run not found", 404, "not_found")
            if run.kind == "replay" and not replay_worker:
                raise DomainError("Replay runs cannot be appended manually", 409, "run_immutable")
            if run.kind == "connector" and not connector_worker:
                raise DomainError(
                    "Connector runs cannot be appended manually", 409, "run_immutable"
                )
            if run.status in {"cancelled", "failed"}:
                raise DomainError("Cannot append to a failed or cancelled run", 409, "run_closed")
            stored = list(session.scalars(select(EventRecord).where(EventRecord.run_id == run.id)))
            existing = {row.event_id: NormalizedEvent.model_validate(row.payload) for row in stored}
            new_events = []
            duplicates = input_duplicates
            for event in ordered:
                previous = existing.get(event.event.id)
                if previous is not None:
                    if previous != event:
                        raise DomainError(
                            "Event ID reused with different content", 409, "id_conflict"
                        )
                    duplicates += 1
                    continue
                if (
                    not connector_worker
                    and run.watermark is not None
                    and (event.event.timestamp, event.event.id)
                    < (
                        datetime.fromisoformat(run.watermark),
                        run.watermark_event_id or "",
                    )
                ):
                    raise DomainError(
                        "Late event precedes this run's (timestamp, ID) watermark. "
                        "Use a new isolated import or chronological replay.",
                        409,
                        "late_event",
                    )
                new_events.append(event)
            if len(existing) + len(new_events) > self.settings.max_events:
                raise DomainError(
                    "Run exceeds its event limit; create another run", 413, "event_limit"
                )
            before_alerts = run.alerts_created
            previous_alerts = (
                list(
                    session.scalars(
                        select(AlertRecord)
                        .where(AlertRecord.run_id == run.id)
                        .order_by(AlertRecord.created_at, AlertRecord.id)
                    )
                )
                if connector_worker
                else []
            )
            used_alerts: set[str] = set()
            for event in new_events:
                storage_id = hashlib.sha256(f"{run.id}:{event.event.id}".encode()).hexdigest()[:32]
                session.add(
                    EventRecord(
                        storage_id=storage_id,
                        run_id=run.id,
                        event_id=event.event.id,
                        timestamp=event.event.timestamp.isoformat(),
                        category=event.event.category,
                        action=event.event.action,
                        outcome=event.event.outcome,
                        severity=event.event.severity,
                        event_type=event.event.type,
                        event_source=event.event.source,
                        source_ip=event.source.ip,
                        host_name=event.host.name,
                        user_name=event.user.name,
                        process_name=event.process.name,
                        payload=event.model_dump(mode="json"),
                    )
                )
            session.flush()
            detections, metrics = evaluate(
                list(existing.values()) + new_events,
                [Rule.model_validate(definition) for definition in run.rules_snapshot],
                run.id,
            )
            for detection in detections:
                if connector_worker:
                    detection.id = retain_alert_identity(detection, previous_alerts, used_alerts)
                    used_alerts.add(detection.id)
                payload = detection.to_dict()
                payload["telemetry_sources"] = telemetry_sources(detection.events)
                row = session.get(AlertRecord, detection.id)
                is_new = row is None
                if row is None:
                    row = AlertRecord(
                        id=detection.id,
                        run_id=run.id,
                        rule_id=detection.rule.id,
                        severity=detection.rule.severity,
                        first_seen=payload["first_seen"],
                        last_seen=payload["last_seen"],
                        event_count=len(detection.events),
                        payload=payload,
                        rule_snapshot=detection.rule.model_dump(mode="json", by_alias=True),
                    )
                    session.add(row)
                else:
                    row.first_seen = payload["first_seen"]
                    row.last_seen = payload["last_seen"]
                    row.event_count = len(detection.events)
                    row.payload = payload
                session.flush()
                session.execute(delete(EvidenceRecord).where(EvidenceRecord.alert_id == row.id))
                for evidence in detection.events:
                    storage_id = hashlib.sha256(
                        f"{run.id}:{evidence.event.id}".encode()
                    ).hexdigest()[:32]
                    session.add(EvidenceRecord(alert_id=row.id, event_storage_id=storage_id))
                if is_new and not self.settings.public_demo:
                    enqueue_alert(session, row, run, self.settings.integrations)
            run.processed_events += len(events)
            run.duplicate_events += duplicates
            session.flush()
            run.alerts_created = (
                (
                    session.scalar(
                        select(func.count())
                        .select_from(AlertRecord)
                        .where(AlertRecord.run_id == run.id)
                    )
                    or 0
                )
                if connector_worker
                else len(detections)
            )
            cumulative_seconds = run.metrics.get("cumulative_detection_seconds", 0.0)
            run.metrics = {
                **metrics.to_dict(),
                "duplicates_ignored": run.duplicate_events,
                "cumulative_detection_seconds": cumulative_seconds + metrics.detection_seconds,
            }
            if new_events:
                latest = max(
                    [*existing.values(), *new_events],
                    key=lambda event: (event.event.timestamp, event.event.id),
                )
                run.watermark = latest.event.timestamp.isoformat()
                run.watermark_event_id = latest.event.id
            if not replay_worker:
                run.total_events = run.processed_events
                run.status = "completed"
                run.completed_at = utcnow()
                session.add(
                    AuditRecord(
                        actor=actor,
                        action="event_ingest",
                        target=run.id,
                        details={"stored": len(new_events), "duplicates": duplicates},
                    )
                )
            else:
                run.status = "running"
            session.flush()
            return {
                "run": run_response(run),
                "events_processed": len(events),
                "events_stored": len(new_events),
                "duplicates_ignored": duplicates,
                "detections_triggered": run.alerts_created - before_alerts,
                "alerts_created": run.alerts_created - before_alerts,
            }

    def runs(self) -> list[dict[str, Any]]:
        with self.db.session() as session:
            return [
                run_response(row)
                for row in session.scalars(
                    select(RunRecord).order_by(RunRecord.created_at.desc()).limit(100)
                )
            ]

    def run(self, run_id: str) -> dict[str, Any]:
        with self.db.session() as session:
            row = session.get(RunRecord, run_id)
            if row is None:
                raise DomainError("Run not found", 404, "not_found")
            return run_response(row)

    def start_replay(self, dataset_id: str, speed: str, actor: str) -> dict[str, Any]:
        if speed not in {"instant", "realtime", "10x"}:
            raise DomainError("Replay speed must be instant, realtime, or 10x")
        dataset = self.datasets.get(dataset_id)
        events = self.datasets.events(dataset_id)
        events.sort(key=lambda event: (event.event.timestamp, event.event.id))
        divisor = 10 if speed == "10x" else 1
        duration = (events[-1].event.timestamp - events[0].event.timestamp).total_seconds()
        if speed != "instant" and duration / divisor > 600:
            raise DomainError(
                "Timed replay exceeds 10 minutes; choose instant or a shorter dataset"
            )
        with self.lock:
            self.jobs = {key: job for key, job in self.jobs.items() if not job[0].done()}
            if len(self.jobs) >= self.settings.max_replay_jobs:
                raise DomainError(
                    "Replay capacity reached; wait or cancel a run", 429, "replay_limit"
                )
            with self.db.session() as session:
                if self.settings.public_demo:
                    self._prune_public_replays(session)
                run = self._new_run(
                    session,
                    name=dataset["name"],
                    kind="replay",
                    dataset_id=dataset_id,
                    total=len(events),
                    speed=speed,
                )
                session.add(AuditRecord(actor=actor, action="replay_start", target=run.id))
                response = run_response(run)
            cancel = threading.Event()
            future = self.executor.submit(self._replay, run.id, events, speed, cancel)
            self.jobs[run.id] = (future, cancel)
            return response

    @staticmethod
    def _prune_public_replays(session: Session) -> None:
        count = session.scalar(select(func.count()).select_from(RunRecord)) or 0
        remove = count - PUBLIC_DEMO_RUN_LIMIT + 1
        if remove <= 0:
            return
        old = list(
            session.scalars(
                select(RunRecord.id)
                .where(
                    RunRecord.kind == "replay",
                    RunRecord.status.in_(["completed", "cancelled", "failed"]),
                )
                .order_by(RunRecord.created_at, RunRecord.id)
                .limit(remove)
            )
        )
        if len(old) != remove:
            raise DomainError(
                "Public demo history is busy; retry after active replays finish",
                429,
                "replay_limit",
            )
        session.execute(delete(AuditRecord).where(AuditRecord.target.in_(old)))
        session.execute(delete(RunRecord).where(RunRecord.id.in_(old)))

    def _replay(
        self,
        run_id: str,
        events: list[NormalizedEvent],
        speed: str,
        cancel: threading.Event,
    ) -> None:
        try:
            if speed == "instant":
                if not cancel.is_set() and not self.shutdown.is_set():
                    self.ingest(events, run_id=run_id, replay_worker=True)
            else:
                divisor = 10 if speed == "10x" else 1
                wall_start = time.monotonic()
                origin = events[0].event.timestamp
                for event in events:
                    target = (event.event.timestamp - origin).total_seconds() / divisor
                    while time.monotonic() - wall_start < target:
                        if cancel.wait(
                            min(0.05, max(0.0, target - (time.monotonic() - wall_start)))
                        ):
                            break
                        if self.shutdown.is_set():
                            break
                    if cancel.is_set() or self.shutdown.is_set():
                        break
                    self.ingest([event], run_id=run_id, replay_worker=True)
            with self.lock, self.db.session() as session:
                row = session.get(RunRecord, run_id)
                if row is not None:
                    row.status = (
                        "cancelled" if cancel.is_set() or self.shutdown.is_set() else "completed"
                    )
                    row.completed_at = utcnow()
        except DomainError as exc:
            self._fail_run(run_id, exc.message)
        except Exception:
            logger.exception("Replay failed (run_id=%s)", run_id)
            self._fail_run(run_id, "Internal replay failure; inspect local server logs")

    def _fail_run(self, run_id: str, message: str) -> None:
        with self.lock, self.db.session() as session:
            run = session.get(RunRecord, run_id)
            if run is not None:
                run.status, run.error, run.completed_at = "failed", message, utcnow()

    def cancel_replay(self, run_id: str, actor: str) -> dict[str, Any]:
        with self.lock:
            response = self.run(run_id)
            if response["kind"] != "replay":
                raise DomainError("This is not a replay run")
            job = self.jobs.get(run_id)
            if job and not job[0].done():
                job[1].set()
                with self.db.session() as session:
                    session.add(AuditRecord(actor=actor, action="replay_cancel", target=run_id))
            return self.run(run_id)

    def search_events(self, filters: dict[str, Any], offset: int, limit: int) -> dict[str, Any]:
        columns = {
            "source_ip": EventRecord.source_ip,
            "user_name": EventRecord.user_name,
            "category": EventRecord.category,
            "action": EventRecord.action,
            "outcome": EventRecord.outcome,
            "host_name": EventRecord.host_name,
            "process_name": EventRecord.process_name,
            "severity": EventRecord.severity,
            "event_type": EventRecord.event_type,
            "event_source": EventRecord.event_source,
            "run_id": EventRecord.run_id,
        }
        query = select(EventRecord)
        for field, column in columns.items():
            if filters.get(field):
                query = query.where(column == filters[field])
        if filters.get("timestamp_from"):
            query = query.where(EventRecord.timestamp >= filters["timestamp_from"])
        if filters.get("timestamp_to"):
            query = query.where(EventRecord.timestamp <= filters["timestamp_to"])
        if filters.get("q"):
            text = filters["q"]
            query = query.where(
                or_(
                    EventRecord.action.contains(text, autoescape=True),
                    EventRecord.user_name.contains(text, autoescape=True),
                    EventRecord.host_name.contains(text, autoescape=True),
                    EventRecord.process_name.contains(text, autoescape=True),
                    EventRecord.source_ip.contains(text, autoescape=True),
                )
            )
        with self.db.session() as session:
            total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
            rows = session.scalars(
                query.order_by(EventRecord.timestamp.desc(), EventRecord.event_id.desc())
                .offset(offset)
                .limit(limit)
            )
            return {
                "items": [event_response(row) for row in rows],
                "total": total,
                "offset": offset,
                "limit": limit,
            }

    def event(self, storage_id: str) -> dict[str, Any]:
        with self.db.session() as session:
            row = session.get(EventRecord, storage_id)
            if row is None:
                raise DomainError("Event not found", 404, "not_found")
            return event_response(row)

    def alerts(self, filters: dict[str, Any], offset: int, limit: int) -> dict[str, Any]:
        query = select(AlertRecord)
        for field, column in {
            "run_id": AlertRecord.run_id,
            "severity": AlertRecord.severity,
            "status": AlertRecord.status,
            "rule_id": AlertRecord.rule_id,
        }.items():
            if filters.get(field):
                query = query.where(column == filters[field])
        if filters.get("q"):
            text = filters["q"]
            query = query.where(
                or_(
                    AlertRecord.rule_id.contains(text, autoescape=True),
                    AlertRecord.payload["rule_name"].as_string().contains(text, autoescape=True),
                    AlertRecord.payload["source_entities"]["ips"]
                    .as_string()
                    .contains(text, autoescape=True),
                    AlertRecord.payload["affected_entities"]["hosts"]
                    .as_string()
                    .contains(text, autoescape=True),
                    AlertRecord.payload["affected_entities"]["users"]
                    .as_string()
                    .contains(text, autoescape=True),
                )
            )
        with self.db.session() as session:
            total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
            rows = session.scalars(
                query.order_by(AlertRecord.created_at.desc(), AlertRecord.id)
                .offset(offset)
                .limit(limit)
            )
            return {
                "items": [alert_response(row) for row in rows],
                "total": total,
                "offset": offset,
                "limit": limit,
            }

    def alert(self, alert_id: str) -> dict[str, Any]:
        with self.db.session() as session:
            row = session.get(AlertRecord, alert_id)
            if row is None:
                raise DomainError("Alert not found", 404, "not_found")
            events = session.scalars(
                select(EventRecord)
                .join(EvidenceRecord, EvidenceRecord.event_storage_id == EventRecord.storage_id)
                .where(EvidenceRecord.alert_id == alert_id)
                .order_by(EventRecord.timestamp, EventRecord.event_id)
            )
            return {
                **alert_response(row),
                "rule_snapshot": row.rule_snapshot,
                "evidence": [event_response(event) for event in events],
                "notifications": [
                    delivery_response(delivery)
                    for delivery in session.scalars(
                        select(DeliveryRecord)
                        .where(DeliveryRecord.alert_id == alert_id)
                        .order_by(DeliveryRecord.created_at)
                    )
                ],
            }

    def change_status(
        self, alert_id: str, status: str, actor: str, note: str = ""
    ) -> dict[str, Any]:
        if status not in {"new", "investigating", "resolved", "false_positive", "suppressed"}:
            raise DomainError("Unsupported alert status")
        with self.lock, self.db.session() as session:
            row = session.get(AlertRecord, alert_id)
            if row is None:
                raise DomainError("Alert not found", 404, "not_found")
            before = row.status
            row.status = status
            if not self.settings.public_demo:
                run = session.get(RunRecord, row.run_id)
                if run is not None:
                    enqueue_alert(session, row, run, self.settings.integrations)
            session.add(
                AuditRecord(
                    actor=actor,
                    action="alert_status",
                    target=alert_id,
                    details={"before": before, "after": status, "note": note},
                )
            )
            return alert_response(row)

    def dashboard(self, run_id: str | None = None) -> dict[str, Any]:
        with self.db.session() as session:
            event_query = select(EventRecord)
            alert_query = select(AlertRecord)
            if run_id:
                event_query = event_query.where(EventRecord.run_id == run_id)
                alert_query = alert_query.where(AlertRecord.run_id == run_id)
            events = list(session.scalars(event_query))
            alerts = list(session.scalars(alert_query))
            active = [row for row in alerts if row.status in {"new", "investigating"}]
            all_rules = self._rules(session)
            times = [datetime.fromisoformat(row.timestamp) for row in events]
            first = min(times).replace(second=0, microsecond=0) if times else datetime.now(UTC)
            span = (max(times) - first).total_seconds() if times else 0
            step = max(60, int(span // 12 // 60 + 1) * 60)
            bins: list[TimelineBin] = (
                [
                    {
                        "timestamp": (first + timedelta(seconds=i * step)).isoformat(),
                        "events": 0,
                        "alerts": 0,
                    }
                    for i in range(12)
                ]
                if times
                else []
            )
            for timestamp in times:
                bins[min(11, int((timestamp - first).total_seconds() // step))]["events"] += 1
            for row in alerts:
                if bins:
                    index = int(
                        (
                            datetime.fromisoformat(row.payload["triggered_at"]) - first
                        ).total_seconds()
                        // step
                    )
                    bins[max(0, min(11, index))]["alerts"] += 1
            sources = Counter(row.source_ip for row in events if row.source_ip)
            top_rules = Counter(row.rule_id for row in alerts)
            names = {row.rule_id: row.payload["rule_name"] for row in alerts}
            mitre_counts: Counter[str] = Counter()
            mitre_rules: dict[str, set[str]] = {}
            for row in alerts:
                for technique in row.payload["mitre_attack"]:
                    mitre_counts[technique] += 1
                    mitre_rules.setdefault(technique, set()).add(row.rule_id)
            return {
                "events_processed": len(events),
                "active_alerts": len(active),
                "critical_alerts": sum(row.severity == "critical" for row in active),
                "high_alerts": sum(row.severity == "high" for row in active),
                "total_alerts": len(alerts),
                "detection_rules": len(all_rules),
                "enabled_rules": sum(rule.enabled for rule in all_rules),
                "runs": 1
                if run_id
                else session.scalar(select(func.count()).select_from(RunRecord)),
                "timeline": bins,
                "top_sources": [{"ip": ip, "count": count} for ip, count in sources.most_common(6)],
                "top_rules": [
                    {"rule_id": key, "name": names[key], "count": count}
                    for key, count in top_rules.most_common(7)
                ],
                "mitre": [
                    {
                        "id": key,
                        "name": MITRE_NAMES.get(key, "ATT&CK technique"),
                        "count": count,
                        "rules": sorted(mitre_rules[key]),
                    }
                    for key, count in mitre_counts.most_common()
                ],
                "recent_alerts": [
                    alert_response(row)
                    for row in sorted(alerts, key=lambda row: row.created_at, reverse=True)[:6]
                ],
            }

    def reset_demo(self, actor: str, *, seed: bool = False) -> dict[str, Any]:
        public = self.settings.public_demo
        if not public and self.settings.database_url != f"sqlite:///{DEMO_DB}":
            raise DomainError(
                "Reset is restricted to the default named demo database", 403, "reset_scope"
            )
        with self.lock:
            if any(not job[0].done() for job in self.jobs.values()):
                raise DomainError(
                    "Cancel active replays before resetting the demo", 409, "active_replay"
                )
            if public and not seed:
                raise DomainError("Public demo reset requires seed=true", 422, "demo_seed_required")
            events = self.datasets.events("mixed-incident") if seed else []
            with self.db.session() as session:
                if public and not session.scalar(
                    select(AuditRecord).where(AuditRecord.action == PUBLIC_MARKER)
                ):
                    raise DomainError(
                        "Reset requires an owned public demo database", 403, "reset_scope"
                    )
                from app.storage.integrations import (
                    CheckpointRecord,
                    ConnectorEventRecord,
                    ConnectorRecord,
                    DeliveryAttemptRecord,
                    DeliveryRecord,
                    DestinationRecord,
                )

                if any(
                    definition["enabled"]
                    for model in (ConnectorRecord, DestinationRecord)
                    for definition in session.scalars(select(model.definition))
                ) or session.scalar(
                    select(DeliveryRecord.id).where(DeliveryRecord.status == "processing").limit(1)
                ):
                    raise DomainError(
                        "Disable connectors and destinations and wait for active deliveries "
                        "before reset",
                        409,
                        "active_integration",
                    )
                session.execute(delete(DeliveryAttemptRecord))
                session.execute(delete(DeliveryRecord))
                session.execute(delete(ConnectorEventRecord))
                session.execute(delete(CheckpointRecord))
                for connector in session.scalars(select(ConnectorRecord)):
                    connector.run_id = None
                    connector.events_received = connector.events_processed = (
                        connector.events_failed
                    ) = 0
                    connector.duplicate_events = connector.retry_count = 0
                    connector.last_success = connector.last_failure = connector.last_error = None
                    connector.last_event_time = None
                    connector.status = "disabled"
                session.execute(delete(EvidenceRecord))
                session.execute(delete(AlertRecord))
                session.execute(delete(EventRecord))
                session.execute(delete(RunRecord))
                session.execute(delete(AuditRecord))
                if public:
                    session.add(
                        AuditRecord(
                            actor=actor,
                            action=PUBLIC_MARKER,
                            target="public-demo",
                            details={"version": 1, "seed_state": "initializing"},
                        )
                    )
            self.seed_rules(restore=True)
            if public:
                with self.db.session() as session:
                    seed_run = self._new_run(
                        session,
                        name="Included incident timeline",
                        kind="demo",
                        dataset_id="mixed-incident",
                        total=len(events),
                    )
                    run_id = seed_run.id
                self.ingest(events, run_id=run_id, actor=actor, replay_worker=True)
                with self.db.session() as session:
                    row = session.get(RunRecord, run_id)
                    marker = session.scalar(
                        select(AuditRecord).where(AuditRecord.action == PUBLIC_MARKER)
                    )
                    if row is None or marker is None:
                        raise DomainError("Demo initialization did not complete", 500, "demo_error")
                    row.status, row.completed_at = "completed", utcnow()
                    marker.details = {"version": 1, "seed_state": "ready"}
                    return {"status": "reset", "run": run_response(row)}
            if seed:
                result = self.ingest(
                    events,
                    name="Included incident timeline",
                    actor=actor,
                )
                return {"status": "reset", "run": result["run"]}
            return {"status": "reset", "run": None}

    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(self.rules(), sort_keys=True).encode()).hexdigest()
