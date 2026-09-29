from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import ROOT, Settings
from app.services.datasets import DatasetStore
from app.services.platform import Platform
from app.storage.models import AuditRecord

pytestmark = pytest.mark.integration


def ingest(client: TestClient, dataset_id: str, datasets: DatasetStore) -> dict:
    descriptor = datasets.get(dataset_id)
    response = client.post(
        "/events",
        json={
            "format": descriptor["format"],
            "name": descriptor["name"],
            "content": (ROOT / "test-data" / descriptor["path"]).read_text(),
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_health_and_offline_openapi_documentation(client: TestClient) -> None:
    assert client.get("/health").json() == {
        "status": "ok",
        "version": "0.1.0",
        "auth_required": False,
    }
    assert client.get("/api/health").status_code == 200
    schema = client.get("/openapi.json").json()
    required = [
        "/events",
        "/events/search",
        "/rules",
        "/rules/{rule_id}",
        "/rules/{rule_id}/test",
        "/alerts",
        "/alerts/{alert_id}",
        "/alerts/{alert_id}/status",
        "/detections/replay",
        "/detections/validate",
        "/datasets",
        "/health",
    ]
    assert all(path in schema["paths"] for path in required)
    docs = client.get("/docs")
    assert "/swagger/swagger-ui-bundle.js" in docs.text
    assert client.get("/swagger/swagger-ui-bundle.js").status_code == 200


@pytest.mark.regression
def test_browser_icon_is_included_and_explicitly_referenced() -> None:
    assert (ROOT / "frontend/public/favicon.svg").is_file()
    assert 'href="/favicon.svg"' in (ROOT / "frontend/index.html").read_text()


def test_full_pipeline_evidence_and_real_dashboard(
    client: TestClient, datasets: DatasetStore
) -> None:
    response = ingest(client, "mixed-incident", datasets)
    assert response["events_stored"] == 56
    assert response["alerts_created"] == 7
    run_id = response["run"]["id"]
    dashboard = client.get("/dashboard", params={"run_id": run_id}).json()
    assert dashboard["events_processed"] == 56
    assert dashboard["active_alerts"] == dashboard["total_alerts"] == 7
    assert dashboard["high_alerts"] == 4
    assert dashboard["critical_alerts"] == 0
    assert sum(point["events"] for point in dashboard["timeline"]) == 56
    assert sum(point["alerts"] for point in dashboard["timeline"]) == 7
    alerts = client.get("/alerts", params={"run_id": run_id}).json()
    assert alerts["total"] == 7
    for alert in alerts["items"]:
        detail = client.get("/alerts/" + alert["id"]).json()
        assert detail["event_count"] == len(detail["evidence"]) == len(detail["evidence_ids"])
        assert detail["rule_snapshot"]["id"] == detail["rule_id"]
        assert detail["provenance"]["author"] == "SentinelFlow contributors"
        assert {event["event"]["id"] for event in detail["evidence"]} == set(detail["evidence_ids"])
        for event in detail["evidence"]:
            assert event["run_id"] == run_id
            assert (
                client.get("/events/" + event["storage_id"]).json()["raw_event"]
                == event["raw_event"]
            )
    rule = client.get("/rules/AUTH-001").json()
    assert rule["threshold"] == {"count": 10, "window_seconds": 300}


@pytest.mark.regression
@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("Brute force", 1),
        ("10.10.20.15", 5),
        ("dc-02", 1),
        ("engineer01", 1),
        ("%", 0),
    ],
)
def test_alert_search_matches_the_displayed_entities(
    client: TestClient, datasets: DatasetStore, query: str, expected: int
) -> None:
    ingest(client, "mixed-incident", datasets)
    response = client.get("/alerts", params={"q": query})
    assert response.status_code == 200
    assert response.json()["total"] == expected


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("source_ip", "10.10.20.15", 47),
        ("user_name", "engineer01", 5),
        ("category", "process", 8),
        ("action", "account_lockout", 4),
        ("outcome", "failure", 29),
        ("host_name", "dc-02", 2),
        ("process_name", "powershell.exe", 5),
        ("severity", "informational", 56),
        ("event_type", "start", 8),
        ("event_source", "synthetic.telemetry", 56),
        ("q", "powershell.exe", 5),
    ],
)
def test_all_event_search_filters(
    client: TestClient, datasets: DatasetStore, field: str, value: str, expected: int
) -> None:
    ingest(client, "mixed-incident", datasets)
    response = client.get("/events/search", params={field: value})
    assert response.status_code == 200
    assert response.json()["total"] == expected


def test_timestamp_boundaries_pagination_and_scope(
    client: TestClient, datasets: DatasetStore
) -> None:
    first = ingest(client, "auth-brute-force", datasets)
    ingest(client, "auth-brute-force", datasets)
    scoped = {
        "run_id": first["run"]["id"],
        "timestamp_from": "2026-01-15T12:00:00+03:00",
        "timestamp_to": "2026-01-15T09:00:09Z",
        "limit": 3,
        "offset": 2,
    }
    response = client.get("/events/search", params=scoped)
    assert response.status_code == 200
    assert response.json()["total"] == 10
    assert len(response.json()["items"]) == 3
    assert response.json()["items"][0]["event"]["id"] == "auth-brute-007"
    assert client.get("/events").json()["total"] == 50
    for params in [
        {"timestamp_from": "2026-01-15T09:00:00"},
        {"timestamp_from": "2026-01-16T00:00:00Z", "timestamp_to": "2026-01-15T00:00:00Z"},
        {"limit": 101},
        {"offset": -1},
    ]:
        assert client.get("/events/search", params=params).status_code == 422


@pytest.mark.parametrize(
    "status", ["new", "investigating", "resolved", "false_positive", "suppressed"]
)
def test_alert_status_and_queue_filters(
    client: TestClient, datasets: DatasetStore, status: str
) -> None:
    ingest(client, "auth-brute-force", datasets)
    hit = client.get("/alerts").json()["items"][0]
    response = client.patch(
        f"/alerts/{hit['id']}/status", json={"status": status, "note": "Reviewed locally"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == status
    assert (
        client.get(
            "/alerts", params={"status": status, "severity": "high", "rule_id": "AUTH-001"}
        ).json()["total"]
        == 1
    )
    if status not in {"new", "investigating"}:
        assert client.get("/dashboard").json()["active_alerts"] == 0


def test_rule_toggles_and_isolated_testing(client: TestClient, datasets: DatasetStore) -> None:
    response = client.patch("/rules/AUTH-001", json={"enabled": False})
    assert response.json()["enabled"] is False
    run = ingest(client, "auth-brute-force", datasets)
    assert run["alerts_created"] == 0
    result = client.post("/rules/AUTH-001/test", json={"dataset_id": "auth-brute-force"}).json()
    assert result["status"] == "passed"
    assert "definition test" in result["scope"]
    assert client.get("/alerts").json()["total"] == 0
    assert client.get("/rules/AUTH-001").json()["enabled"] is False
    current = client.post(
        "/detections/validate",
        json={
            "dataset_id": "auth-brute-force",
            "scope": "current",
        },
    ).json()
    assert current["status"] == "failed"
    baseline = client.post(
        "/detections/validate",
        json={
            "dataset_id": "auth-brute-force",
            "scope": "bundled",
        },
    ).json()
    assert baseline["status"] == "passed"
    benign = client.post("/detections/validate", json={"dataset_id": "auth-normal-failures"}).json()
    assert benign["status"] == "passed" and benign["results"][0]["actual"] == []
    assert client.get("/alerts").json()["total"] == 0


def test_csv_multipart_upload(client: TestClient) -> None:
    content = (ROOT / "test-data/parsers/events.csv").read_bytes()
    response = client.post(
        "/events/upload",
        data={"format": "csv"},
        files={"file": ("sample.csv", content, "text/csv")},
    )
    assert response.status_code == 201
    assert response.json()["events_stored"] == 1


def test_storage_survives_process_reinitialization(tmp_path: Path, datasets: DatasetStore) -> None:
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'persistent.sqlite3'}")
    service = Platform(settings)
    try:
        result = service.ingest(datasets.events("auth-brute-force"))
        alert = service.alerts({}, 0, 100)["items"][0]
        service.change_status(alert["id"], "resolved", "test", "persisted note")
    finally:
        service.close()
    reopened = Platform(settings)
    try:
        assert reopened.run(result["run"]["id"])["alerts_created"] == 1
        detail = reopened.alert(alert["id"])
        assert detail["status"] == "resolved"
        assert len(detail["evidence"]) == 25
        with reopened.db.session() as session:
            entries = list(session.scalars(select(AuditRecord)))
            assert entries[-1].details["note"] == "persisted note"
    finally:
        reopened.close()


def test_missing_items_and_bad_inputs_are_explicit(client: TestClient) -> None:
    for path in ["/events/nope", "/alerts/nope", "/rules/nope", "/detections/replay/nope"]:
        assert client.get(path).status_code == 404
    assert client.post("/events", json={"format": "evtx", "content": "binary"}).status_code == 422
    assert client.patch("/alerts/nope/status", json={"status": "invented"}).status_code == 422
    response = client.post(
        "/events", json={"format": "json", "content": '{"token":"private-marker"}'}
    )
    assert response.status_code == 422
    assert "private-marker" not in response.text


def test_demo_reset_cannot_touch_custom_database(
    client: TestClient, datasets: DatasetStore
) -> None:
    ingest(client, "auth-brute-force", datasets)
    response = client.post("/admin/demo-reset", json={"confirmation": "RESET DEMO"})
    assert response.status_code == 403
    assert client.get("/events").json()["total"] == 25
