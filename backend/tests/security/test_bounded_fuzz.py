import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import ROOT, Settings
from app.integrations.settings import IntegrationSettings
from app.main import create_app

pytestmark = [pytest.mark.security, pytest.mark.regression, pytest.mark.integration]

CORPUS = json.loads((ROOT / "test-data/security/api-fuzz.json").read_text())
TARGETS = CORPUS["targets"]


@pytest.mark.parametrize("target", TARGETS)
def test_seeded_invalid_api_shapes_are_bounded_and_atomic(target: str, tmp_path: Path) -> None:
    payloads = CORPUS["shape_cases"]
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'fuzz.sqlite3'}",
        integrations=IntegrationSettings(worker_enabled=False),
    )
    started = time.monotonic()
    with TestClient(create_app(settings), raise_server_exceptions=False) as client:
        before = client.get("/dashboard").json()
        for payload in payloads:
            response = client.post(
                target, content=json.dumps(payload), headers={"Content-Type": "application/json"}
            )
            assert response.status_code in {401, 403, 422}, response.text
            assert "Traceback" not in response.text
            assert response.headers["x-content-type-options"] == "nosniff"
        after = client.get("/dashboard").json()
        assert (after["events_processed"], after["total_alerts"], after["runs"]) == (
            before["events_processed"],
            before["total_alerts"],
            before["runs"],
        )
    assert time.monotonic() - started < 10


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize(
    "payload",
    [bytes.fromhex(value) for value in CORPUS["malformed_hex"]],
)
def test_malformed_json_never_becomes_an_internal_error(
    target: str, payload: bytes, tmp_path: Path
) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'malformed.sqlite3'}",
        integrations=IntegrationSettings(worker_enabled=False),
    )
    with TestClient(create_app(settings), raise_server_exceptions=False) as client:
        response = client.post(
            target, content=payload, headers={"Content-Type": "application/json"}
        )
        assert response.status_code in {400, 401, 403, 422}, response.text
        assert "Traceback" not in response.text
