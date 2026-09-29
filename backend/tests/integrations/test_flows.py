from collections import Counter
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import Settings
from app.integrations.demo import demo_fixtures
from app.integrations.normalize import normalize_batch
from app.integrations.profiles import QueryProfile
from app.integrations.schemas import ConnectorConfig
from app.integrations.settings import IntegrationSettings
from app.integrations.stream import ingest_page
from app.main import create_app
from app.storage.integrations import DeliveryRecord

pytestmark = [
    pytest.mark.integration,
    pytest.mark.connectors,
    pytest.mark.notifications,
    pytest.mark.end_to_end,
]


@pytest.mark.parametrize("source", ["microsoft_sentinel", "microsoft_graph", "windows_wef"])
def test_real_mock_http_to_normalization_detection_alert_and_notification(
    tmp_path: Path, source: str
) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'flows.sqlite3'}",
        integrations=IntegrationSettings(worker_enabled=False),
    )
    with TestClient(create_app(settings)) as client:
        response = client.post("/api/integrations/demo", json={"source": source})
        assert response.status_code == 200, response.text
        body = response.json()
        expected = demo_fixtures()["expected"][source]
        assert body["events_processed"] == expected["events"]
        assert body["status"] == "mock"
        alerts = client.get("/api/alerts", params={"run_id": body["run_id"]}).json()["items"]
        assert Counter(alert["rule_id"] for alert in alerts) == expected["alerts"]
        assert len(body["deliveries"]) == sum(expected["alerts"].values())
        assert {delivery["status"] for delivery in body["deliveries"]} == {"delivered"}
        runtime = client.app.state.platform.integrations
        assert len(runtime.demo.receipts) == len(body["deliveries"])
        for alert in alerts:
            detail = client.get(f"/api/alerts/{alert['id']}").json()
            assert detail["event_count"] == len(detail["evidence"])
            assert detail["telemetry_sources"][0]["provider"] == source
            assert detail["notifications"][0]["status"] == "delivered"
        repeated = client.post("/api/integrations/demo", json={"source": source})
        assert repeated.status_code == 200, repeated.text
        assert repeated.json()["events_processed"] == body["events_processed"]
        with client.app.state.platform.db.session() as session:
            assert len(list(session.scalars(select(DeliveryRecord)))) == len(body["deliveries"])
        assert len(runtime.demo.attempts) == len(body["deliveries"])


@pytest.mark.negative
@pytest.mark.parametrize("source", ["microsoft_sentinel", "microsoft_graph", "windows_wef"])
def test_provider_benign_data_does_not_trigger_alerts_or_delivery(service, source) -> None:
    runtime = service.integrations
    fixture = demo_fixtures()["benign"]
    expected = fixture["expected"][source]
    if source == "windows_wef":
        config = ConnectorConfig(
            name="Benign Windows", type="windows_wef", mode="demo", enabled=True
        )
        connector = runtime.management.save_connector(config, "test")
        events = normalize_batch(
            fixture["windows"],
            QueryProfile("windows", "WindowsEvent", "", "windows"),
            source,
            connector["id"],
        )
        result = ingest_page(service, connector["id"], config, events, "test")
        processed = result["events_stored"]
    else:
        from app.integrations.operations import run_demo

        server = runtime.demo_server()
        server.fixtures = {
            **server.fixtures,
            "sentinel": fixture["sentinel"],
            "graph": fixture["graph"],
        }
        processed = run_demo(runtime, source, "test")["events_processed"]
    assert processed == expected["events"]
    assert service.alerts({}, 0, 100)["items"] == []
    assert runtime.management.deliveries()["items"] == []
    assert all(rule["enabled"] for rule in service.rules())
