import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.errors import DomainError
from app.core.safe import json_loads, yaml_loads
from app.integrations.settings import IntegrationSettings
from app.main import create_app
from app.parsers import parse_content

pytestmark = [pytest.mark.security, pytest.mark.regression]


@pytest.mark.parametrize("value", ["\ud800", "\udfff"])
@pytest.mark.parametrize("parser", ["json", "yaml", "content"])
def test_invalid_unicode_is_rejected_before_serialization(value: str, parser: str) -> None:
    with pytest.raises(DomainError):
        if parser == "json":
            json_loads(json.dumps({"value": value}))
        elif parser == "yaml":
            yaml_loads("value: " + value)
        else:
            parse_content(value, "json")


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/events", {"format": "json", "content": "\ud800"}),
        ("/rules", {"yaml": "\ud800"}),
        ("/sigma/compile", {"yaml": "\ud800"}),
        (
            "/integrations/connectors",
            {"name": "\ud800", "type": "windows_wef", "mode": "demo"},
        ),
        (
            "/notifications/destinations",
            {"name": "\ud800", "type": "webhook", "mode": "demo"},
        ),
        ("/events", {"format": "json", "content": "{}", "\ud800": "invalid key"}),
    ],
)
def test_malformed_unicode_api_requests_never_poison_persisted_state(
    tmp_path: Path, path: str, body: dict
) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'unicode.sqlite3'}",
        integrations=IntegrationSettings(worker_enabled=False),
    )
    with TestClient(create_app(settings), raise_server_exceptions=False) as client:
        response = client.post(
            path,
            content=json.dumps(body).encode("ascii"),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 422, response.text
        for read in (
            "/events",
            "/rules",
            "/integrations/connectors",
            "/notifications/destinations",
        ):
            assert client.get(read).status_code == 200


@pytest.mark.parametrize(
    "path",
    [
        "/%5c%5cexample.invalid%5cshare%5csecret",
        "/C:%5csecret",
        "/%2e%2e/.env",
        "/%2e%2e%2f.env",
        "/%00hidden",
        "/assets/%2e%2e/%2e%2e/.env",
    ],
)
def test_static_paths_do_not_leave_the_frontend_root(client: TestClient, path: str) -> None:
    response = client.get(path)
    assert response.status_code == 404
    assert "SENTINEL_CLIENT_SECRET" not in response.text


def test_static_symlinks_are_not_followed(tmp_path: Path, monkeypatch) -> None:
    import app.main as module

    dist = tmp_path / "frontend/dist"
    dist.mkdir(parents=True)
    secret = tmp_path / "synthetic-private.txt"
    secret.write_text("must not be served")
    (dist / "symlink.txt").symlink_to(secret)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    with TestClient(
        create_app(Settings(database_url=f"sqlite:///{tmp_path / 'static.sqlite3'}"))
    ) as client:
        assert client.get("/symlink.txt").status_code == 404


def test_origin_rejection_keeps_security_headers(client: TestClient) -> None:
    response = client.post(
        "/detections/validate", json={}, headers={"Origin": "https://untrusted.example.invalid"}
    )
    assert response.status_code == 403
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-request-id"] == response.json()["request_id"]


def test_public_schema_contains_only_the_public_interface(tmp_path: Path) -> None:
    settings = Settings(
        public_demo=True,
        database_url=f"sqlite:///{tmp_path / 'sentinelflow-public-demo.sqlite3'}",
    )
    with TestClient(create_app(settings)) as client:
        schema = client.get("/openapi.json").json()
        assert "/events" in schema["paths"]
        assert "post" not in schema["paths"]["/events"]
        assert "/detections/replay" in schema["paths"]
        for path in schema["paths"]:
            assert not path.startswith(
                ("/integrations", "/notifications", "/ingest", "/admin", "/project")
            )
        assert "CredentialConfig" not in schema["components"]["schemas"]
        assert "IngestRequest" not in schema["components"]["schemas"]


def test_private_schema_declares_actual_owner_and_scoped_requirements(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    assert schema["components"]["securitySchemes"]["OwnerBearer"]["scheme"] == "bearer"
    windows = schema["paths"]["/ingest/windows"]["post"]
    assert windows["security"] == [{"IntegrationBearer": []}]
    assert windows["x-required-integration-scope"] == "windows:ingest"
    assert schema["paths"]["/rules"]["post"]["security"] == [{"OwnerBearer": []}]
    assert schema["paths"]["/alerts"]["get"]["security"] == [
        {"OwnerBearer": []},
        {"IntegrationBearer": []},
    ]
    assert schema["paths"]["/health"]["get"]["security"] == []
