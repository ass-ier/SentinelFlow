import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import ROOT, Settings
from app.main import create_app
from app.services.datasets import DatasetStore

pytestmark = [pytest.mark.security, pytest.mark.integration]


def test_api_token_and_local_boundary(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'auth.sqlite3'}", api_token="test-only-value"
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/health").json()["auth_required"] is True
        assert client.get("/events").status_code == 401
        assert client.get("/events", headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert (
            client.get("/events", headers={"Authorization": "Bearer test-only-value"}).status_code
            == 200
        )
    local = Settings(database_url=f"sqlite:///{tmp_path / 'local.sqlite3'}")
    with TestClient(create_app(local), client=("198.51.100.12", 40000)) as remote:
        assert remote.get("/health").status_code == 200
        assert remote.get("/events").status_code == 403


def test_origin_and_host_boundaries(client: TestClient) -> None:
    assert (
        client.post(
            "/detections/validate", json={}, headers={"Origin": "https://untrusted.example.test"}
        ).status_code
        == 403
    )
    assert client.get("/health", headers={"Host": "attacker.example.test"}).status_code == 400
    allowed = client.options(
        "/events",
        headers={
            "Origin": "http://127.0.0.1:5173",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert allowed.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"


def test_headers_and_errors_do_not_echo_payload_secrets(client: TestClient) -> None:
    response = client.get("/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["content-security-policy"].startswith("default-src 'self'")
    rejected = client.post("/events", json={"format": "invalid", "content": "sensitive-marker"})
    assert rejected.status_code == 422
    assert "sensitive-marker" not in rejected.text
    assert rejected.json()["request_id"]


def test_sql_search_is_parameterized(client: TestClient, datasets: DatasetStore) -> None:
    content = json.dumps([row.model_dump(mode="json") for row in datasets.events("auth-success")])
    assert client.post("/events", json={"format": "json", "content": content}).status_code == 201
    for params in [{"user_name": "' OR 1=1 --"}, {"q": "%"}, {"q": "_"}]:
        assert client.get("/events/search", params=params).json()["total"] == 0
    assert client.get("/events").json()["total"] == 8


def test_logs_are_never_executed_and_evidence_is_not_rewritten(
    client: TestClient, datasets: DatasetStore, tmp_path: Path
) -> None:
    marker = tmp_path / "must-not-exist"
    row = datasets.events("powershell-indicators")[0].model_dump(mode="json")
    text = f"<script>alert('example')</script>; touch {marker}"
    row["process"]["command_line"] = "powershell.exe EncodedCommand " + text
    row["raw_event"] = text
    response = client.post("/events", json={"format": "json", "content": json.dumps(row)})
    assert response.status_code == 201
    assert not marker.exists()
    assert client.get("/events").json()["items"][0]["raw_event"] == text


def test_size_limits_and_invalid_utf8(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'limits.sqlite3'}", max_upload_bytes=1000
    )
    with TestClient(create_app(settings)) as client:
        assert (
            client.post(
                "/events/upload",
                data={"format": "json"},
                files={"file": ("too-big.json", b"x" * 1001)},
            ).status_code
            == 413
        )
        response = client.post(
            "/events/upload", data={"format": "json"}, files={"file": ("bad.evtx", b"\xff\xfe\x01")}
        )
        assert response.status_code == 422
        body = client.post(
            "/events", content=b"x" * 70000, headers={"Content-Type": "application/json"}
        )
        assert body.status_code == 413
        assert client.get("/events").json()["total"] == 0


def test_event_count_limit_is_atomic(tmp_path: Path, datasets: DatasetStore) -> None:
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'count.sqlite3'}", max_events=3)
    with TestClient(create_app(settings)) as client:
        content = json.dumps(
            [row.model_dump(mode="json") for row in datasets.events("auth-success")]
        )
        response = client.post("/events", json={"format": "json", "content": content})
        assert response.status_code == 413
        assert client.get("/events").json()["total"] == 0
        assert client.get("/runs").json()["total"] == 0


def test_untrusted_yaml_and_document_paths(client: TestClient) -> None:
    for text in ["!!python/object/apply:os.system ['echo not-executed']", "x: &a [1]\ny: *a"]:
        assert client.post("/rules", json={"yaml": text}).status_code == 422
        assert client.post("/sigma/compile", json={"yaml": text}).status_code == 422
    assert client.get("/project/document", params={"path": "../.env"}).status_code == 404
    assert client.get("/project/document", params={"path": str(ROOT / ".env")}).status_code == 404


@pytest.mark.regression
def test_regex_timeout_rolls_back_ingestion(client: TestClient, datasets: DatasetStore) -> None:
    yaml = """
id: TIMEOUT-001
name: Deliberately pathological test pattern
description: Runtime must stop and report, never silently skip.
severity: low
conditions:
  field: process.command_line
  operator: regex
  value: '(a|aa)+$'
"""
    assert client.post("/rules", json={"yaml": yaml}).status_code == 201
    row = datasets.events("process-benign")[0].model_dump(mode="json")
    row["process"]["command_line"] = "a" * 16000 + "!"
    row["raw_event"] = "bounded regex regression"
    response = client.post("/events", json={"format": "json", "content": json.dumps(row)})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "regex_timeout"
    assert client.get("/events").json()["total"] == 0
    assert client.get("/alerts").json()["total"] == 0
    assert client.get("/runs").json()["total"] == 0
