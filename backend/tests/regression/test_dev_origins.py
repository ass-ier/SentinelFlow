from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app

pytestmark = [pytest.mark.regression, pytest.mark.security]


def configure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Settings:
    monkeypatch.setenv("SENTINEL_FRONTEND_PORT", "5174")
    monkeypatch.setenv("SENTINEL_DATABASE_URL", f"sqlite:///{tmp_path / 'custom-port.sqlite3'}")
    monkeypatch.setenv("SENTINEL_API_TOKEN", "")
    monkeypatch.delenv("SENTINEL_ALLOWED_ORIGINS", raising=False)
    return Settings.from_env()


def test_custom_frontend_port_defines_exact_loopback_origins(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = configure(monkeypatch, tmp_path)
    assert settings.allowed_origins == ("http://127.0.0.1:5174", "http://localhost:5174")


def test_realistic_proxy_origin_on_custom_port_is_allowed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = configure(monkeypatch, tmp_path)
    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/detections/validate",
            json={"dataset_id": "auth-normal-failures"},
            headers={"Origin": "http://127.0.0.1:5174", "Host": "127.0.0.1:8766"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "passed"
        forbidden = client.post(
            "/detections/validate",
            json={"dataset_id": "auth-normal-failures"},
            headers={"Origin": "https://untrusted.example.test", "Host": "127.0.0.1:8766"},
        )
        assert forbidden.status_code == 403


def test_explicit_origin_configuration_is_not_expanded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    configure(monkeypatch, tmp_path)
    monkeypatch.setenv("SENTINEL_ALLOWED_ORIGINS", "https://approved.example.test")
    assert Settings.from_env().allowed_origins == ("https://approved.example.test",)
