import shutil
import sqlite3
import time
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path
from threading import Event
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.config import PUBLIC_DEMO_FILENAME, PUBLIC_DEMO_RUN_LIMIT, Settings
from app.core.errors import DomainError
from app.main import create_app
from app.services.datasets import DatasetStore
from app.services.platform import PUBLIC_MARKER, Platform
from app.storage.models import AuditRecord, EventRecord, RunRecord

pytestmark = [pytest.mark.integration, pytest.mark.security, pytest.mark.regression]
OWNER_TOKEN = "test-only-public-demo-owner"


def settings_for(tmp_path: Path, *, token: str = OWNER_TOKEN) -> Settings:
    return Settings(
        public_demo=True,
        database_url=f"sqlite:///{tmp_path / PUBLIC_DEMO_FILENAME}",
        api_token=token,
        allowed_hosts=("testserver", "backend.example.test"),
        allowed_origins=("https://portfolio.example.test",),
    )


@pytest.mark.parametrize("token", ["", "test-only-legacy-health-token"])
def test_private_health_preserves_its_original_exact_response(tmp_path: Path, token: str) -> None:
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'legacy.sqlite3'}", api_token=token)
    with TestClient(create_app(settings)) as client:
        for path in ("/health", "/api/health"):
            assert client.get(path).json() == {
                "status": "ok",
                "version": "0.1.0",
                "auth_required": bool(token),
            }


@pytest.fixture
def public_client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(settings_for(tmp_path)), client=("198.51.100.42", 40000)) as client:
        yield client


def replay(client: TestClient, dataset: str = "auth-brute-force") -> dict[str, Any]:
    response = client.post("/api/detections/replay", json={"dataset_id": dataset})
    assert response.status_code == 202, response.text
    run = response.json()
    deadline = time.monotonic() + 5
    while run["status"] in {"running", "pending"} and time.monotonic() < deadline:
        time.sleep(0.01)
        response = client.get(f"/api/detections/replay/{run['id']}")
        assert response.status_code == 200, response.text
        run = response.json()
    assert run["status"] == "completed", run
    return run


def test_remote_visitor_gets_seeded_synthetic_evidence_without_credentials(
    public_client: TestClient,
) -> None:
    health = public_client.get("/health")
    assert health.status_code == 200
    assert health.json() == {
        "status": "ok",
        "version": "0.1.0",
        "auth_required": False,
        "public_demo": True,
        "public_demo_run_limit": 20,
    }
    assert OWNER_TOKEN not in health.text
    data = public_client.get("/api/dashboard").json()
    assert (data["events_processed"], data["total_alerts"], data["detection_rules"]) == (56, 7, 7)
    catalog = public_client.get("/api/datasets").json()
    assert catalog["total"] == 49
    assert all(item["synthetic"] is True for item in catalog["items"])
    assert public_client.get("/api/detections/scenarios").json()["total"] == 49
    assert public_client.get("/api/runs").json()["items"][0]["kind"] == "demo"
    for alert in public_client.get("/api/alerts").json()["items"]:
        detail = public_client.get(f"/api/alerts/{alert['id']}").json()
        assert detail["event_count"] == len(detail["evidence"]) == len(detail["evidence_ids"])
        assert detail["provenance"]["kind"] == "bundled"
        assert all(event["raw_event"] for event in detail["evidence"])


@pytest.mark.parametrize("prefix", ["", "/api"])
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/events"),
        ("POST", "/events/upload"),
        ("POST", "/rules"),
        ("PATCH", "/rules/AUTH-001"),
        ("PATCH", "/alerts/example/status"),
        ("POST", "/alerts/example/status"),
        ("POST", "/sigma/import"),
        ("GET", "/project/evidence"),
        ("GET", "/project/document?path=README.md"),
    ],
)
def test_public_restrictions_cannot_be_bypassed_with_owner_token(
    public_client: TestClient, prefix: str, method: str, path: str
) -> None:
    response = public_client.request(
        method,
        prefix + path,
        json={} if method != "GET" else None,
        headers={"Authorization": f"Bearer {OWNER_TOKEN}"},
    )
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "public_demo_restricted"
    assert public_client.get("/events").json()["total"] == 56
    assert public_client.get("/rules").json()["total"] == 7


def test_public_replay_is_real_and_validation_does_not_persist_results(
    public_client: TestClient,
) -> None:
    run = replay(public_client)
    assert (run["processed_events"], run["total_events"], run["alerts_created"]) == (25, 25, 1)
    alerts = public_client.get("/alerts", params={"run_id": run["id"]}).json()
    assert alerts["total"] == 1
    alert = alerts["items"][0]
    assert (alert["rule_id"], alert["severity"], alert["event_count"]) == ("AUTH-001", "high", 25)
    evidence = public_client.get(f"/alerts/{alert['id']}").json()["evidence"]
    expected = DatasetStore().events("auth-brute-force")
    assert {item["event"]["id"]: item["raw_event"] for item in evidence} == {
        item.event.id: item.raw_event for item in expected
    }
    validation = public_client.post("/detections/validate", json={}).json()
    assert (validation["status"], validation["passed"], validation["failed"]) == ("passed", 49, 0)
    assert (validation["benign_passed"], validation["benign_total"]) == (14, 14)
    benign = public_client.post(
        "/rules/AUTH-001/test", json={"dataset_id": "auth-normal-failures", "expected_alerts": 0}
    ).json()
    assert benign["status"] == "passed" and benign["results"][0]["actual"] == []
    assert public_client.get("/events").json()["total"] == 81
    assert public_client.get("/alerts").json()["total"] == 8


def test_non_synthetic_telemetry_is_unavailable_to_public_requests(
    public_client: TestClient,
) -> None:
    non_synthetic = [item for item in DatasetStore().catalog() if item["synthetic"] is not True]
    assert len(non_synthetic) == 1
    dataset = non_synthetic[0]["id"]
    for path in ("/detections/replay", "/detections/validate", "/rules/AUTH-001/test"):
        response = public_client.post(path, json={"dataset_id": dataset})
        assert response.status_code == 404, response.text
    assert public_client.get("/events").json()["total"] == 56


def sigma_body(sample: dict[str, Any]) -> dict[str, Any]:
    return {key: sample[key] for key in ("yaml", "source_url", "license", "license_url")}


def test_both_public_sigma_samples_compile_and_pass_positive_and_benign_tests(
    public_client: TestClient,
) -> None:
    samples = public_client.get("/sigma/samples").json()["items"]
    assert len(samples) == 2
    for sample in samples:
        body = sigma_body(sample)
        response = public_client.post("/sigma/compile", json=body)
        assert response.status_code == 200, response.text
        assert response.json()["rule"]["provenance"]["source_url"] == sample["source_url"]
        for dataset, count in ((sample["dataset_id"], 1), (sample["negative_dataset_id"], 0)):
            response = public_client.post(
                "/sigma/test", json={**body, "dataset_id": dataset, "expected_alerts": count}
            )
            assert response.status_code == 200, response.text
            assert response.json()["status"] == "passed"
            assert len(response.json()["results"][0]["actual"]) == count
    assert public_client.get("/rules").json()["total"] == 7
    assert public_client.get("/alerts").json()["total"] == 7


@pytest.mark.parametrize("field", ["yaml", "source_url", "license", "license_url"])
@pytest.mark.parametrize("path", ["/sigma/compile", "/sigma/test"])
def test_public_sigma_rejects_modified_source_or_provenance(
    public_client: TestClient, field: str, path: str
) -> None:
    sample = public_client.get("/sigma/samples").json()["items"][0]
    body = {**sigma_body(sample), field: "untrusted-public-input"}
    if path.endswith("/test"):
        body.update(dataset_id=sample["dataset_id"], expected_alerts=1)
    response = public_client.post(path, json=body)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "public_demo_restricted"
    assert "untrusted-public-input" not in response.text


def test_configured_cors_hosts_and_local_swagger_assets(public_client: TestClient) -> None:
    origin = "https://portfolio.example.test"
    preflight = public_client.options(
        "/api/detections/validate",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == origin
    response = public_client.post(
        "/api/detections/validate",
        json={"dataset_id": "auth-normal-failures"},
        headers={"Origin": origin, "Host": "backend.example.test"},
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == origin
    assert "access-control-allow-credentials" not in response.headers
    assert (
        public_client.post(
            "/detections/validate", json={}, headers={"Origin": "https://untrusted.example.test"}
        ).status_code
        == 403
    )
    assert (
        public_client.get("/health", headers={"Host": "untrusted.example.test"}).status_code == 400
    )
    assert (
        public_client.get("/events", headers={"Accept": "text/html"})
        .headers["content-type"]
        .startswith("application/json")
    )
    assert public_client.get("/").status_code == 404
    assert public_client.get("/docs").status_code == 200
    assert public_client.get("/api/docs").status_code == 200
    assert public_client.get("/openapi.json").status_code == 200
    assert public_client.get("/swagger/swagger-ui-bundle.js").status_code == 200
    assert public_client.get("/swagger/swagger-ui.css").status_code == 200
    assert public_client.get("/favicon.svg").status_code == 200
    assert public_client.get("/redoc").status_code == 404


def test_restart_preserves_operation_and_owner_reset_restores_exact_seed(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    with TestClient(create_app(settings)) as client:
        seed_id = client.get("/runs").json()["items"][0]["id"]
        run = replay(client)
    with TestClient(create_app(settings)) as restarted:
        assert restarted.get("/events").json()["total"] == 81
        assert restarted.get("/alerts").json()["total"] == 8
        assert {row["id"] for row in restarted.get("/runs").json()["items"]} == {seed_id, run["id"]}
        body = {"confirmation": "RESET DEMO", "seed": True}
        assert restarted.post("/admin/demo-reset", json=body).status_code == 403
        assert (
            restarted.post(
                "/admin/demo-reset",
                json=body,
                headers={"Authorization": "Bearer incorrect-test-value"},
            ).status_code
            == 403
        )
        headers = {"Authorization": f"Bearer {OWNER_TOKEN}"}
        assert (
            restarted.post(
                "/admin/demo-reset", json={**body, "seed": False}, headers=headers
            ).status_code
            == 422
        )
        reset = restarted.post("/admin/demo-reset", json=body, headers=headers)
        assert reset.status_code == 200, reset.text
        assert restarted.get("/events").json()["total"] == 56
        assert restarted.get("/alerts").json()["total"] == 7
        assert restarted.get("/runs").json()["total"] == 1
    with TestClient(create_app(settings)) as again:
        assert again.get("/events").json()["total"] == 56
        assert again.get("/alerts").json()["total"] == 7


def test_unset_owner_token_disables_remote_reset_but_not_visitor_workflows(tmp_path: Path) -> None:
    with TestClient(create_app(settings_for(tmp_path, token=""))) as client:
        assert client.get("/events").status_code == 200
        assert (
            client.post(
                "/admin/demo-reset",
                json={"confirmation": "RESET DEMO", "seed": True},
                headers={"Authorization": f"Bearer {OWNER_TOKEN}"},
            ).status_code
            == 403
        )


def test_existing_unmarked_data_is_refused_without_deleting_it(tmp_path: Path) -> None:
    private_path = tmp_path / "private.sqlite3"
    private = Platform(Settings(database_url=f"sqlite:///{private_path}"))
    try:
        private.ingest(DatasetStore().events("auth-success"), name="private-input-marker")
    finally:
        private.close()
    shutil.copyfile(private_path, tmp_path / PUBLIC_DEMO_FILENAME)
    with pytest.raises(DomainError, match="unmarked database"):
        Platform(settings_for(tmp_path))
    with closing(sqlite3.connect(tmp_path / PUBLIC_DEMO_FILENAME)) as database:
        assert database.execute("SELECT count(*) FROM events").fetchone()[0] == 8
        assert database.execute("SELECT name FROM runs").fetchone()[0] == "private-input-marker"


def test_public_mode_refuses_an_unrelated_sqlite_schema_without_deleting_it(tmp_path: Path) -> None:
    with closing(sqlite3.connect(tmp_path / PUBLIC_DEMO_FILENAME)) as database, database:
        database.execute("CREATE TABLE unrelated_records (value TEXT)")
        database.execute("INSERT INTO unrelated_records VALUES ('preserve-this-test-record')")
    with pytest.raises(DomainError, match="unrelated tables"):
        Platform(settings_for(tmp_path))
    with closing(sqlite3.connect(tmp_path / PUBLIC_DEMO_FILENAME)) as database:
        assert database.execute("SELECT value FROM unrelated_records").fetchone()[0] == (
            "preserve-this-test-record"
        )


def test_interrupted_initialization_recovers_only_owned_public_database(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    service = Platform(settings)
    try:
        with service.db.session() as session:
            marker = session.scalar(select(AuditRecord).where(AuditRecord.action == PUBLIC_MARKER))
            assert marker is not None
            marker.details = {"version": 1, "seed_state": "initializing"}
    finally:
        service.close()
    recovered = Platform(settings)
    try:
        assert recovered.dashboard()["events_processed"] == 56
        assert recovered.dashboard()["total_alerts"] == 7
        assert len(recovered.runs()) == 1
    finally:
        recovered.close()


def test_public_history_is_bounded_and_seed_and_cascaded_evidence_are_preserved(
    public_client: TestClient,
) -> None:
    seed = public_client.get("/runs").json()["items"][0]["id"]
    first = replay(public_client, "auth-normal-failures")
    for _ in range(PUBLIC_DEMO_RUN_LIMIT):
        replay(public_client, "auth-normal-failures")
    runs = public_client.get("/runs").json()
    assert runs["total"] == PUBLIC_DEMO_RUN_LIMIT
    assert seed in {row["id"] for row in runs["items"]}
    assert public_client.get(f"/detections/replay/{first['id']}").status_code == 404
    assert public_client.get("/events").json()["total"] == 56 + 19 * 3
    service = public_client.app.state.platform
    with service.db.session() as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditRecord)
                .where(AuditRecord.target == first["id"])
            )
            == 0
        )
        assert (
            session.scalar(
                select(func.count())
                .select_from(EventRecord)
                .where(EventRecord.run_id == first["id"])
            )
            == 0
        )


def test_public_concurrency_and_reset_preserve_active_replays(
    public_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = public_client.app.state.platform
    gate = Event()
    original = service._replay

    def blocked_replay(*args: Any) -> None:
        assert gate.wait(5)
        original(*args)

    monkeypatch.setattr(service, "_replay", blocked_replay)
    try:
        for _ in range(2):
            assert (
                public_client.post(
                    "/detections/replay", json={"dataset_id": "auth-normal-failures"}
                ).status_code
                == 202
            )
        assert (
            public_client.post(
                "/detections/replay", json={"dataset_id": "auth-normal-failures"}
            ).status_code
            == 429
        )
        assert (
            public_client.post(
                "/admin/demo-reset",
                json={"confirmation": "RESET DEMO", "seed": True},
                headers={"Authorization": f"Bearer {OWNER_TOKEN}"},
            ).status_code
            == 409
        )
    finally:
        gate.set()


def test_public_validation_limit_is_explicit_and_released(public_client: TestClient) -> None:
    service = public_client.app.state.platform
    with service.validation_slot():
        response = public_client.post("/detections/validate", json={})
        assert response.status_code == 429
        assert response.json()["error"]["code"] == "validation_limit"
    assert (
        public_client.post(
            "/detections/validate", json={"dataset_id": "auth-normal-failures"}
        ).json()["status"]
        == "passed"
    )
    with pytest.raises(ValueError), service.validation_slot():
        raise ValueError("deliberate test exception")
    with service.validation_slot():
        pass


def test_public_request_bodies_have_a_smaller_fixed_resource_limit(
    public_client: TestClient,
) -> None:
    response = public_client.post(
        "/sigma/compile",
        content=b"x" * (128 * 1024 + 1),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "size_limit"
    assert public_client.get("/health").status_code == 200


def test_public_mode_cannot_reopen_imported_runs_under_an_existing_marker(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    service = Platform(settings)
    try:
        with service.db.session() as session:
            run = session.scalar(select(RunRecord))
            assert run is not None
            run.kind = "import"
    finally:
        service.close()
    with pytest.raises(DomainError, match="outside its synthetic catalog"):
        Platform(settings)
