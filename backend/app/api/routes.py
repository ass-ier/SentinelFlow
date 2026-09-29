import json
import os
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile

from app.core.config import ROOT
from app.core.errors import DomainError
from app.core.evidence import source_fingerprint
from app.core.security import analyst, get_platform, local_features, operator
from app.detection.rules import load_bundled_rules, load_rule
from app.detection.sigma import compile_sigma, sigma_samples
from app.parsers import parse_content
from app.schemas.api import (
    AlertFilters,
    EventFilters,
    IngestRequest,
    ReplayRequest,
    ResetRequest,
    RuleImport,
    RuleUpdate,
    SigmaImport,
    SigmaRequest,
    SigmaTest,
    StatusUpdate,
    TestRequest,
    ValidationRequest,
)
from app.schemas.events import LogFormat
from app.services.platform import Platform
from app.services.validation import validate_detections

router = APIRouter(dependencies=[Depends(analyst)])
Service = Annotated[Platform, Depends(get_platform)]
Actor = Annotated[str, Depends(analyst)]
Owner = Annotated[str, Depends(operator)]


@router.get("/dashboard", tags=["Analytics"])
def dashboard(service: Service, run_id: str | None = Query(None, max_length=64)) -> dict[str, Any]:
    return service.dashboard(run_id)


@router.get("/events", tags=["Events"])
@router.get("/events/search", tags=["Events"])
def events(service: Service, filters: Annotated[EventFilters, Query()]) -> dict[str, Any]:
    values = filters.model_dump(exclude_none=True)
    for key in ("timestamp_from", "timestamp_to"):
        if key in values:
            values[key] = values[key].isoformat()
    return service.search_events(values, filters.offset, filters.limit)


@router.post("/events", status_code=201, tags=["Events"], dependencies=[Depends(local_features)])
def ingest(body: IngestRequest, service: Service, actor: Actor) -> dict[str, Any]:
    parsed = parse_content(
        body.content,
        body.format,
        max_bytes=service.settings.max_upload_bytes,
        max_events=service.settings.max_events,
        syslog_year=body.syslog_year,
    )
    return service.ingest(parsed, name=body.name, run_id=body.run_id, actor=actor)


@router.post(
    "/events/upload", status_code=201, tags=["Events"], dependencies=[Depends(local_features)]
)
async def upload(
    service: Service,
    actor: Actor,
    file: Annotated[UploadFile, File()],
    format: Annotated[LogFormat, Form()],
) -> dict[str, Any]:
    content = await file.read(service.settings.max_upload_bytes + 1)
    if len(content) > service.settings.max_upload_bytes:
        raise DomainError("Upload exceeds the configured size limit", 413, "size_limit")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise DomainError("Logs must be UTF-8 text; binary EVTX is not supported") from exc
    parsed = parse_content(text, format, max_events=service.settings.max_events)
    return service.ingest(
        parsed, name=Path(file.filename or "Local upload").name[:255], actor=actor
    )


@router.get("/events/{storage_id}", tags=["Events"])
def event_detail(storage_id: str, service: Service) -> dict[str, Any]:
    return service.event(storage_id)


@router.get("/rules", tags=["Rules"])
def rules(service: Service) -> dict[str, Any]:
    items = service.rules()
    return {"items": items, "total": len(items)}


@router.post("/rules", status_code=201, tags=["Rules"], dependencies=[Depends(local_features)])
def import_rule(body: RuleImport, service: Service, actor: Actor) -> dict[str, Any]:
    return service.save_rule(load_rule(body.yaml), actor=actor)


@router.get("/rules/{rule_id}", tags=["Rules"])
def rule_detail(rule_id: str, service: Service) -> dict[str, Any]:
    return service.rule(rule_id)


@router.patch("/rules/{rule_id}", tags=["Rules"], dependencies=[Depends(local_features)])
def rule_update(rule_id: str, body: RuleUpdate, service: Service, actor: Actor) -> dict[str, Any]:
    return service.toggle_rule(rule_id, body.enabled, actor)


@router.post("/rules/{rule_id}/test", tags=["Validation"])
def rule_test(rule_id: str, body: TestRequest, service: Service) -> dict[str, Any]:
    with service.validation_slot():
        return validate_detections(
            service.datasets,
            service.definitions(),
            dataset_id=body.dataset_id,
            rule_id=rule_id,
            expected_count=body.expected_alerts,
            scope="current rule",
            definition_test=True,
        )


@router.get("/alerts", tags=["Alerts"])
def alerts(service: Service, filters: Annotated[AlertFilters, Query()]) -> dict[str, Any]:
    return service.alerts(filters.model_dump(exclude_none=True), filters.offset, filters.limit)


@router.get("/alerts/{alert_id}", tags=["Alerts"])
def alert_detail(alert_id: str, service: Service) -> dict[str, Any]:
    return service.alert(alert_id)


@router.patch("/alerts/{alert_id}/status", tags=["Alerts"], dependencies=[Depends(local_features)])
@router.post(
    "/alerts/{alert_id}/status",
    tags=["Alerts"],
    include_in_schema=False,
    dependencies=[Depends(local_features)],
)
def alert_status(
    alert_id: str,
    body: StatusUpdate,
    service: Service,
    actor: Actor,
) -> dict[str, Any]:
    return service.change_status(alert_id, body.status, actor, body.note)


@router.get("/datasets", tags=["Datasets"])
def datasets(service: Service) -> dict[str, Any]:
    items = service.datasets.catalog()
    return {"items": items, "total": len(items)}


@router.get("/runs", tags=["Replay"])
def runs(service: Service) -> dict[str, Any]:
    items = service.runs()
    return {"items": items, "total": len(items)}


@router.get("/runs/{run_id}/feed", tags=["Replay"])
def feed(run_id: str, service: Service) -> dict[str, Any]:
    service.run(run_id)
    return {
        "events": service.search_events({"run_id": run_id}, 0, 25)["items"],
        "alerts": service.alerts({"run_id": run_id}, 0, 25)["items"],
    }


@router.post("/detections/replay", status_code=202, tags=["Replay"])
def replay(body: ReplayRequest, service: Service, actor: Actor) -> dict[str, Any]:
    return service.start_replay(body.dataset_id, body.speed, actor)


@router.get("/detections/replay/{run_id}", tags=["Replay"])
def replay_progress(run_id: str, service: Service) -> dict[str, Any]:
    return service.run(run_id)


@router.post("/detections/replay/{run_id}/cancel", tags=["Replay"])
def cancel_replay(run_id: str, service: Service, actor: Actor) -> dict[str, Any]:
    return service.cancel_replay(run_id, actor)


@router.get("/detections/scenarios", tags=["Validation"])
def scenarios(service: Service) -> dict[str, Any]:
    items = service.datasets.scenarios()
    return {"items": items, "total": len(items)}


@router.post("/detections/validate", tags=["Validation"])
def validate(body: ValidationRequest, service: Service) -> dict[str, Any]:
    rules = load_bundled_rules(ROOT / "rules") if body.scope == "bundled" else service.definitions()
    with service.validation_slot():
        return validate_detections(
            service.datasets,
            rules,
            dataset_id=body.dataset_id,
            rule_id=body.rule_id,
            scope=body.scope,
        )


def sigma_definition(body: SigmaRequest) -> dict[str, Any]:
    rule = compile_sigma(
        body.yaml,
        source_url=body.source_url,
        license_name=body.license,
        license_url=body.license_url,
    )
    return rule.model_dump(mode="json", by_alias=True)


def public_sigma_source(body: SigmaRequest, service: Service) -> None:
    if not service.settings.public_demo:
        return
    fields = ("yaml", "source_url", "license", "license_url")
    if not any(
        all(getattr(body, field) == sample.get(field) for field in fields)
        for sample in sigma_samples()
    ):
        raise DomainError(
            "The public demo accepts only its unchanged bundled, licensed Sigma samples.",
            403,
            "public_demo_restricted",
        )


@router.get("/sigma/samples", tags=["Sigma"])
def samples() -> dict[str, Any]:
    items = sigma_samples()
    return {"items": items, "total": len(items)}


@router.post("/sigma/compile", tags=["Sigma"])
def sigma_compile(body: SigmaRequest, service: Service) -> dict[str, Any]:
    with service.validation_slot():
        public_sigma_source(body, service)
        definition = sigma_definition(body)
    return {
        "rule": definition,
        "warnings": [
            "Limited Sigma subset; no correlations, pipelines, or full backend compatibility.",
            "Missing source fields do not match. "
            "Imported rules start disabled unless explicitly enabled.",
        ],
    }


@router.post(
    "/sigma/import", status_code=201, tags=["Sigma"], dependencies=[Depends(local_features)]
)
def sigma_import(body: SigmaImport, service: Service, actor: Actor) -> dict[str, Any]:
    rule = compile_sigma(
        body.yaml,
        source_url=body.source_url,
        license_name=body.license,
        license_url=body.license_url,
    )
    rule.enabled = body.enabled
    return service.save_rule(rule, actor=actor)


@router.post("/sigma/test", tags=["Sigma"])
def sigma_test(body: SigmaTest, service: Service) -> dict[str, Any]:
    with service.validation_slot():
        public_sigma_source(body, service)
        rule = compile_sigma(
            body.yaml,
            source_url=body.source_url,
            license_name=body.license,
            license_url=body.license_url,
        )
        return validate_detections(
            service.datasets,
            [rule],
            dataset_id=body.dataset_id,
            rule_id=rule.id,
            expected_count=body.expected_alerts,
            scope="Sigma definition",
            definition_test=True,
        )


def evidence_files() -> list[dict[str, Any]]:
    directories = ["backend/tests", "scripts", "docs", "test-data"]
    files = []
    for directory in directories:
        for path in sorted((ROOT / directory).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                files.append({"path": str(path.relative_to(ROOT)), "bytes": path.stat().st_size})
    return files


def read_report(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise DomainError("Saved validation evidence is unreadable", 500, "report_error") from exc


@router.get("/project/evidence", tags=["Evidence"], dependencies=[Depends(local_features)])
def project_evidence() -> dict[str, Any]:
    artifact = ROOT / "artifacts"
    validation_path = artifact / "validation.json"
    benchmark_path = artifact / "benchmark.json"
    saved = ROOT / "docs" / "results"
    running_path = artifact / "validation-running.json"
    validation = read_report(
        validation_path
        if validation_path.exists() or running_path.exists()
        else saved / "validation.json"
    )
    benchmark = read_report(
        benchmark_path
        if benchmark_path.exists() or running_path.exists()
        else saved / "benchmark.json"
    )
    fingerprint = source_fingerprint()
    for receipt in (validation, benchmark):
        if isinstance(receipt, dict):
            receipt["is_current"] = receipt.get("source_fingerprint") == fingerprint
            if not receipt["is_current"]:
                receipt["status"] = "stale"
                receipt["stale_reason"] = (
                    "Code, dependencies, rules, or fixtures changed after measurement."
                )
    state = read_report(running_path)
    running = False
    if isinstance(state, dict) and state.get("pid"):
        try:
            os.kill(int(state["pid"]), 0)
            running = True
        except (ProcessLookupError, PermissionError):
            running = False
    log = artifact / "validation.log"
    if not log.exists() and not running:
        log = saved / "validation.log"
    return {
        "validation": validation,
        "benchmark": benchmark,
        "validation_log": log.read_text()[-120_000:] if log.exists() else "",
        "validation_running": running,
        "files": evidence_files(),
        "documents": [
            {"path": path, "title": Path(path).stem.replace("-", " ").title()}
            for path in ["README.md", "test-data/README.md"]
            + [str(file.relative_to(ROOT)) for file in sorted((ROOT / "docs").glob("*.md"))]
            if (ROOT / path).is_file()
        ],
    }


@router.get("/project/document", tags=["Evidence"], dependencies=[Depends(local_features)])
def project_document(path: str = Query(max_length=200)) -> dict[str, str]:
    allowed = {"README.md", "test-data/README.md"} | {
        str(file.relative_to(ROOT)) for file in (ROOT / "docs").glob("*.md")
    }
    if path not in allowed or not (ROOT / path).is_file():
        raise DomainError("Document not found", 404, "not_found")
    return {"path": path, "content": (ROOT / path).read_text()}


@router.post("/admin/demo-reset", tags=["Demo"])
def demo_reset(body: ResetRequest, service: Service, actor: Owner) -> dict[str, Any]:
    return service.reset_demo(actor, seed=body.seed)
