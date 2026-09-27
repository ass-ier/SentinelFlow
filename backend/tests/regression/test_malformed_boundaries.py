import importlib
import sys
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from app.core.config import ROOT, Settings
from app.core.errors import DomainError
from app.detection.sigma import compile_sigma, sigma_samples
from app.main import create_app

pytestmark = [pytest.mark.regression, pytest.mark.security]


@pytest.mark.parametrize("status", [["test"], {"value": "test"}])
def test_sigma_status_has_a_controlled_type_boundary(status: object) -> None:
    source = yaml.safe_load(sigma_samples()[0]["yaml"])
    source["status"] = status
    with pytest.raises(DomainError):
        compile_sigma(yaml.safe_dump(source))


@pytest.mark.parametrize("route", ["/sigma/compile", "/sigma/import", "/sigma/test"])
def test_invalid_sigma_status_returns_422(client: TestClient, route: str) -> None:
    source = yaml.safe_load(sigma_samples()[0]["yaml"])
    source["status"] = ["test"]
    body = {"yaml": yaml.safe_dump(source)}
    if route.endswith("/test"):
        body.update({"dataset_id": "sigma-download", "expected_alerts": 1})
    response = client.post(route, json=body)
    assert response.status_code == 422


def test_non_ascii_bearer_is_unauthorized_not_internal_error(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'bearer.sqlite3'}", api_token="local-test-token"
    )
    with TestClient(create_app(settings), raise_server_exceptions=False) as client:
        response = client.get("/events", headers=[(b"authorization", b"Bearer caf\xc3\xa9")])
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "unauthorized"


@pytest.mark.parametrize("value", ["non-ascii-\u00e9", "with a space", "with\ttab", "x" * 257])
def test_invalid_token_configuration_fails_explicitly(value: str) -> None:
    with pytest.raises(ValueError, match="ASCII"):
        Settings(api_token=value)


def test_online_reset_restores_fixtures_before_seed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    reset = importlib.import_module("demo_reset")
    fixture = tmp_path / "restored.jsonl"
    order = []

    def generate() -> None:
        order.append("generate")
        fixture.write_text('{"restored": true}\n')

    def request(_api: str, _path: str, body: dict) -> dict:
        order.append("request")
        assert fixture.exists(), "Seeding was requested before the missing fixture was restored"
        assert body["seed"] is True
        return {"status": "reset", "run": None}

    monkeypatch.setattr(reset, "generate", generate)
    monkeypatch.setattr(reset, "request", request)
    monkeypatch.setattr(sys, "argv", ["demo_reset.py", "--seed"])
    reset.main()
    assert order == ["generate", "request"]


def test_generation_failure_prevents_destructive_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    reset = importlib.import_module("demo_reset")
    requests = []

    def generate() -> None:
        raise OSError("Fixtures cannot be restored")

    def request(*args: object) -> dict:
        requests.append(args)
        return {"status": "reset", "run": None}

    monkeypatch.setattr(reset, "generate", generate)
    monkeypatch.setattr(reset, "request", request)
    monkeypatch.setattr(sys, "argv", ["demo_reset.py", "--seed"])
    with pytest.raises(OSError, match="cannot be restored"):
        reset.main()
    assert requests == []
