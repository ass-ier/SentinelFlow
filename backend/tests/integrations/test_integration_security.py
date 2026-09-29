import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import Settings
from app.core.errors import DomainError
from app.integrations.demo import demo_fixtures
from app.integrations.schemas import CredentialConfig
from app.integrations.settings import EnvironmentSecrets, IntegrationSettings
from app.integrations.transport import (
    IntegrationError,
    SafeHTTPTransport,
    checked_url,
    permitted_address,
    require_success,
)
from app.main import create_app
from app.storage.models import AuditRecord

pytestmark = [pytest.mark.integration, pytest.mark.security]


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "ftp://example.com/x",
        "https://user:pass@example.com",
        "https://example.com/#fragment",
        "https://example.com/\r\nX-Test:bad",
        "https://example.com:99999",
        "https://",
        "https://example.com\\@127.0.0.1",
        " https://example.com",
        "https://example.com/a b",
    ],
)
def test_outbound_url_rejection(url: str) -> None:
    with pytest.raises(IntegrationError):
        checked_url(url, IntegrationSettings())


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "::1",
        "10.1.2.3",
        "192.168.1.1",
        "172.16.0.1",
        "169.254.169.254",
        "169.254.170.2",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "::ffff:10.1.1.1",
        "0.0.0.0",  # noqa: S104 - Reject this address; no listener is bound here.
        "::",
        "224.0.0.1",
        "100.100.100.200",
        "198.18.0.1",
    ],
)
def test_ssrf_sensitive_networks_denied_by_default(address: str) -> None:
    assert not permitted_address(address, IntegrationSettings())


def test_internal_enterprise_allowlist_is_explicit_https_only() -> None:
    policy = IntegrationSettings(allowed_networks=("10.20.0.0/16", "fd12:3456::/48"))
    assert permitted_address("10.20.1.5", policy)
    assert permitted_address("fd12:3456::7", policy)
    assert not permitted_address("10.21.1.5", policy)
    assert not permitted_address("169.254.169.254", policy)
    assert not permitted_address("10.20.1.5", policy, http=True)
    assert permitted_address("127.0.0.1", IntegrationSettings(allow_local_http=True), http=True)
    assert permitted_address("8.8.8.8", IntegrationSettings())


@pytest.mark.parametrize("addresses", [["127.0.0.1"], ["8.8.8.8", "169.254.169.254"]])
def test_dns_resolution_rejects_rebinding_and_mixed_public_private_answers(
    monkeypatch, addresses
) -> None:
    import app.integrations.transport as module

    monkeypatch.setattr(module, "resolve_addresses", lambda *_: addresses)
    monkeypatch.setattr(socket, "create_connection", lambda *_: pytest.fail("must not connect"))
    with pytest.raises(IntegrationError) as failure:
        SafeHTTPTransport(IntegrationSettings()).request("POST", "https://receiver.example/alerts")
    assert failure.value.code == "ssrf_denied"


def test_real_loopback_response_limit_redirect_and_absolute_timeout() -> None:
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            return

        def do_GET(self):
            calls.append(self.path)
            if self.path == "/slow":
                time.sleep(0.4)
                return
            self.send_response(302 if self.path == "/redirect" else 200)
            if self.path == "/redirect":
                self.send_header("Location", "http://169.254.169.254/metadata")
            self.send_header("Content-Length", "8193" if self.path == "/large" else "0")
            self.end_headers()
            if self.path == "/large":
                self.wfile.write(b"x" * 8193)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    transport = SafeHTTPTransport(IntegrationSettings(allow_local_http=True))
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with pytest.raises(IntegrationError) as failure:
            transport.request("GET", base + "/large", max_bytes=8192)
        assert failure.value.code == "response_limit"
        with pytest.raises(IntegrationError) as failure:
            require_success(transport.request("GET", base + "/redirect"))
        assert failure.value.code == "redirect_denied"
        started = time.monotonic()
        with pytest.raises(IntegrationError) as failure:
            transport.request("GET", base + "/slow", timeout=0.1)
        assert failure.value.code == "timeout"
        assert time.monotonic() - started < 1
        assert calls == ["/large", "/redirect", "/slow"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def register(client, monkeypatch, scopes, **extra):
    token = "synthetic-integration-only-token-" + "a" * 20
    monkeypatch.setenv("SENTINEL_INTEGRATION_TOKEN", token)
    response = client.post(
        "/api/integrations/credentials",
        json={
            "name": "Scoped caller",
            "token_ref": "SENTINEL_INTEGRATION_TOKEN",
            "scopes": scopes,
            **extra,
        },
    )
    assert response.status_code == 201, response.text
    return token, response.json()


@pytest.mark.parametrize(
    "endpoint",
    [
        "/api/integrations/connectors",
        "/integrations/connectors",
        "/api/notifications/destinations",
        "/notifications/destinations",
        "/api/notifications/test",
        "/api/integrations/demo",
        "/api/rules",
    ],
)
def test_scoped_reader_cannot_manage_integrations_or_analyst_state(
    client, monkeypatch, endpoint
) -> None:
    token, _ = register(client, monkeypatch, ["alerts:read"])
    response = client.post(endpoint, headers={"Authorization": f"Bearer {token}"}, json={})
    assert response.status_code in {401, 403}, response.text
    assert (
        client.get("/api/alerts", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    )


def test_rotation_revocation_and_invalid_token_never_fall_back_to_local_admin(
    client, monkeypatch
) -> None:
    token, credential = register(client, monkeypatch, ["alerts:read"])
    rotated = "different-synthetic-integration-token-" + "b" * 12
    monkeypatch.setenv("SENTINEL_INTEGRATION_TOKEN", rotated)
    assert (
        client.get("/api/alerts", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    )
    assert (
        client.get("/api/alerts", headers={"Authorization": f"Bearer {rotated}"}).status_code == 200
    )
    config = {key: value for key, value in credential.items() if key != "id"}
    config["enabled"] = False
    monkeypatch.delenv("SENTINEL_INTEGRATION_TOKEN")
    assert (
        client.patch(f"/api/integrations/credentials/{credential['id']}", json=config).status_code
        == 200
    )
    assert (
        client.post(
            "/api/integrations/demo",
            json={"source": "microsoft_sentinel"},
            headers={"Authorization": f"Bearer {rotated}"},
        ).status_code
        == 401
    )


def test_secret_references_are_allowlisted_and_never_resolved_in_response(
    client, monkeypatch, caplog
) -> None:
    secret = "synthetic-confidential-value-not-for-responses"
    monkeypatch.setenv(
        "SENTINEL_INTEGRATION_FLOW", "https://receiver.example.invalid/path?secret=" + secret
    )
    monkeypatch.setenv("SENTINEL_INTEGRATION_BEARER", secret)
    response = client.post(
        "/api/notifications/destinations",
        json={
            "name": "Private flow",
            "type": "power_automate",
            "url_ref": "SENTINEL_INTEGRATION_FLOW",
            "authentication": "bearer",
            "auth_ref": "SENTINEL_INTEGRATION_BEARER",
        },
    )
    assert response.status_code == 201
    assert secret not in response.text
    assert secret not in client.get("/api/notifications/destinations").text
    assert secret not in caplog.text
    with pytest.raises(DomainError):
        EnvironmentSecrets().read("HOME")
    with pytest.raises(DomainError):
        EnvironmentSecrets().read("AWS_SECRET_ACCESS_KEY")
    bad = client.post(
        "/api/notifications/destinations",
        json={
            "name": "raw",
            "type": "webhook",
            "url": "https://example.invalid/" + secret,
        },
    )
    assert bad.status_code == 422
    assert secret not in bad.text


def test_rate_limit_caps_notification_amplification(client) -> None:
    destination = client.post(
        "/api/notifications/destinations",
        json={
            "name": "Mock",
            "type": "webhook",
            "mode": "demo",
            "enabled": True,
        },
    ).json()
    statuses = [
        client.post(
            "/api/notifications/test", json={"destination_id": destination["id"]}
        ).status_code
        for _ in range(11)
    ]
    assert statuses == [202] * 10 + [429]


@pytest.mark.parametrize("path", ["/ingest/windows", "/api/ingest/windows"])
def test_windows_requires_scoped_credentials_and_bounded_body(client, path) -> None:
    body = {"connector_id": "windows-default", "events": demo_fixtures()["windows"][:1]}
    assert client.post(path, json=body).status_code == 401
    assert (
        client.post(
            path, content=b"x" * (512 * 1024 + 1), headers={"Content-Type": "application/json"}
        ).status_code
        == 413
    )


def test_windows_collector_cannot_write_to_other_connector(client, monkeypatch) -> None:
    token, _ = register(client, monkeypatch, ["windows:ingest"], connector_id="windows-default")
    response = client.post(
        "/api/ingest/windows",
        json={
            "connector_id": "different",
            "events": demo_fixtures()["windows"][:1],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "scope_denied"


def test_public_demo_cannot_enable_any_external_integration(tmp_path: Path) -> None:
    for flag in ("sentinel_enabled", "graph_enabled", "windows_enabled", "notifications_enabled"):
        with pytest.raises(ValueError, match="forbidden"):
            Settings(public_demo=True, integrations=IntegrationSettings(**{flag: True}))
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'sentinelflow-public-demo.sqlite3'}", public_demo=True
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/integrations").json()["connectors"] == []
        for path in (
            "/integrations/demo",
            "/notifications/test",
            "/integrations/connectors",
            "/notifications/destinations",
            "/integrations/credentials",
        ):
            assert client.post("/api" + path, json={}).status_code == 403
        assert client.get("/api/notifications/destinations").json()["items"] == []


def test_sensitive_management_actions_are_audited_without_secret_values(client) -> None:
    created = client.post(
        "/api/integrations/connectors",
        json={
            "name": "Offline",
            "type": "microsoft_graph",
            "mode": "demo",
            "profiles": [{"id": "signins"}],
        },
    ).json()
    client.post(f"/api/integrations/connectors/{created['id']}/enabled", json={"enabled": True})
    client.post(f"/api/integrations/connectors/{created['id']}/test")
    client.post(f"/api/integrations/connectors/{created['id']}/enabled", json={"enabled": False})
    with client.app.state.platform.db.session() as session:
        records = list(session.scalars(select(AuditRecord)))
        actions = {row.action for row in records}
        assert {
            "connector_created",
            "connector_enabled",
            "connector_disabled",
            "connector_test",
        } <= actions
        assert all("synthetic-oauth" not in json.dumps(row.details) for row in records)


@pytest.mark.parametrize(
    ("timestamp", "supplied"),
    [
        ("\u00b2", "sha256=" + "0" * 64),
        ("\uff11", "sha256=" + "0" * 64),
        ("1000", "\u00e9" * 71),
        ("1000", "short"),
        ("9" * 100, "sha256=" + "0" * 64),
    ],
)
def test_malformed_hmac_headers_return_false_without_raising(timestamp, supplied) -> None:
    from app.integrations.destinations import verify_signature

    assert not verify_signature("synthetic-signing-key", timestamp, b"{}", supplied, now=1000)


def test_ambiguous_rotated_token_is_denied_instead_of_selecting_broader_scope(
    client, monkeypatch
) -> None:
    runtime = client.app.state.platform.integrations
    token = "synthetic-token-identity-" + "a" * 32
    monkeypatch.setenv("SENTINEL_INTEGRATION_READ", token)
    monkeypatch.setenv("SENTINEL_INTEGRATION_NOTIFY", token + "b")
    for reference, scope in (
        ("SENTINEL_INTEGRATION_READ", "alerts:read"),
        ("SENTINEL_INTEGRATION_NOTIFY", "alerts:notify"),
    ):
        runtime.management.save_credential(
            CredentialConfig(name="Scoped credential", token_ref=reference, scopes=[scope]), "test"
        )
    monkeypatch.setenv("SENTINEL_INTEGRATION_NOTIFY", token)
    result = client.get("/api/alerts", headers={"Authorization": f"Bearer {token}"})
    assert result.status_code == 401
    assert result.json()["error"]["code"] == "credential_conflict"
    assert token not in result.text
