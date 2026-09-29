from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.integrations.schemas import ConnectorConfig, CredentialConfig
from app.integrations.settings import IntegrationSettings
from app.main import create_app

pytestmark = [pytest.mark.security, pytest.mark.integration, pytest.mark.regression]


@pytest.fixture
def secured(tmp_path: Path, monkeypatch):
    owner = "synthetic-owner-" + "o" * 32
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'authorization.sqlite3'}",
        api_token=owner,
        integrations=IntegrationSettings(worker_enabled=False),
    )
    with TestClient(create_app(settings), client=("192.0.2.20", 43100)) as client:
        tokens = {"owner": owner, "invalid": "synthetic-invalid-" + "i" * 32, "missing": None}
        scopes = ["alerts:read", "alerts:notify", "notifications:test", "windows:ingest"]
        management = client.app.state.platform.integrations.management
        management.save_connector(
            ConnectorConfig(name="Fixture WEC", type="windows_wef", mode="demo", enabled=True),
            "test",
            "windows-default",
        )
        for index, name in enumerate(
            [*scopes, "revoked", "expired", "revoked_windows", "expired_windows"]
        ):
            token = f"synthetic-scoped-{index}-" + "x" * 32
            reference = f"SENTINEL_INTEGRATION_MATRIX_{index}"
            monkeypatch.setenv(reference, token)
            management.save_credential(
                CredentialConfig(
                    name=name,
                    token_ref=reference,
                    scopes=[name]
                    if name in scopes
                    else ["windows:ingest" if name.endswith("_windows") else "alerts:read"],
                    connector_id="windows-default"
                    if name == "windows:ingest" or name.endswith("_windows")
                    else None,
                    enabled=not name.startswith("revoked"),
                    expires_at=datetime.now(UTC) - timedelta(seconds=1)
                    if name.startswith("expired")
                    else datetime.now(UTC) + timedelta(hours=1),
                ),
                "test",
            )
            tokens[name] = token
        yield client, tokens


@pytest.mark.parametrize("prefix", ["", "/api"])
@pytest.mark.parametrize(
    ("method", "path", "allowed"),
    [
        ("GET", "/alerts", {"owner", "alerts:read"}),
        ("GET", "/alerts/missing", {"owner", "alerts:read"}),
        ("GET", "/events", {"owner"}),
        ("POST", "/events", {"owner"}),
        ("POST", "/events/upload", {"owner"}),
        ("POST", "/rules", {"owner"}),
        ("PATCH", "/rules/AUTH-001", {"owner"}),
        ("PATCH", "/alerts/missing/status", {"owner"}),
        ("POST", "/detections/replay", {"owner"}),
        ("POST", "/detections/validate", {"owner"}),
        ("POST", "/sigma/import", {"owner"}),
        ("GET", "/project/evidence", {"owner"}),
        ("GET", "/integrations/credentials", {"owner"}),
        ("POST", "/integrations/credentials", {"owner"}),
        ("PATCH", "/integrations/credentials/missing", {"owner"}),
        ("GET", "/integrations/connectors", {"owner"}),
        ("GET", "/integrations", {"owner"}),
        ("POST", "/integrations/demo", {"owner"}),
        ("POST", "/integrations/connectors", {"owner"}),
        ("PATCH", "/integrations/connectors/missing", {"owner"}),
        ("POST", "/integrations/connectors/missing/poll", {"owner"}),
        ("POST", "/integrations/connectors/missing/test", {"owner"}),
        ("POST", "/integrations/connectors/missing/enabled", {"owner"}),
        ("GET", "/notifications/destinations", {"owner"}),
        ("POST", "/notifications/destinations", {"owner"}),
        ("PATCH", "/notifications/destinations/missing", {"owner"}),
        ("DELETE", "/notifications/destinations/missing", {"owner"}),
        ("POST", "/notifications/destinations/missing/enabled", {"owner"}),
        ("GET", "/notifications/policies", {"owner"}),
        ("POST", "/notifications/policies", {"owner"}),
        ("PATCH", "/notifications/policies/missing", {"owner"}),
        ("DELETE", "/notifications/policies/missing", {"owner"}),
        ("GET", "/notifications/deliveries", {"owner"}),
        ("GET", "/notifications/deliveries/missing", {"owner"}),
        ("POST", "/notifications/test", {"owner", "notifications:test"}),
        ("POST", "/alerts/missing/notify", {"owner", "alerts:notify"}),
        ("POST", "/ingest/windows", {"windows:ingest"}),
    ],
)
def test_remote_endpoint_permission_matrix(secured, prefix, method, path, allowed) -> None:
    client, tokens = secured
    for name, token in tokens.items():
        body = {}
        if path == "/ingest/windows":
            body = {"connector_id": "windows-default", "events": [{}]}
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        response = client.request(method, prefix + path, json=body, headers=headers)
        if name in allowed:
            # Missing records/fields are deliberate: auth must finish before business validation.
            assert response.status_code in {200, 404, 422}, (name, path, response.text)
        else:
            assert response.status_code in {401, 403}, (name, path, response.text)


def test_expiration_is_timezone_aware_and_legacy_records_remain_explicit() -> None:
    data = {"name": "scope", "token_ref": "SENTINEL_INTEGRATION_T", "scopes": ["alerts:read"]}
    assert CredentialConfig.model_validate(data).expires_at is None
    config = CredentialConfig.model_validate({**data, "expires_at": "2099-01-01T05:30:00+05:30"})
    assert config.model_dump(mode="json")["expires_at"] == "2099-01-01T00:00:00Z"
    with pytest.raises(ValidationError):
        CredentialConfig.model_validate({**data, "expires_at": "2099-01-01T00:00:00"})


def test_expiration_boundary_takes_effect_without_restart(secured, monkeypatch) -> None:
    import app.integrations.auth as module

    client, tokens = secured
    identity = tokens["alerts:read"]
    headers = {"Authorization": f"Bearer {identity}"}
    assert client.get("/api/alerts", headers=headers).status_code == 200
    real_datetime = datetime

    class FutureClock:
        @staticmethod
        def now(_zone):
            return real_datetime.now(UTC) + timedelta(hours=2)

    monkeypatch.setattr(module, "datetime", FutureClock)
    assert client.get("/api/alerts", headers=headers).status_code == 401
