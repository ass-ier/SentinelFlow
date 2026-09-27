import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.services.platform import Platform
from app.storage.models import RunRecord

pytestmark = [pytest.mark.replay, pytest.mark.integration]
DATASETS = [
    ("auth-brute-force", 25, 1),
    ("auth-lockout", 4, 1),
    ("powershell-indicators", 5, 1),
    ("iam-privileged-group", 2, 1),
    ("process-suspicious", 3, 1),
    ("dns-long-label", 3, 1),
    ("dns-frequency", 25, 1),
    ("net-unusual", 6, 1),
    ("auth-duplicates", 50, 1),
    ("auth-shuffled", 25, 1),
    ("mixed-incident", 56, 7),
]


def finished(client: TestClient, identifier: str, timeout: float = 20) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = client.get("/detections/replay/" + identifier).json()
        if result["status"] not in {"pending", "running"}:
            return result
        time.sleep(0.025)
    pytest.fail("Replay never reached a terminal state")


@pytest.mark.parametrize(("dataset_id", "count", "alerts"), DATASETS)
def test_replay_real_pipeline(client: TestClient, dataset_id: str, count: int, alerts: int) -> None:
    response = client.post(
        "/detections/replay", json={"dataset_id": dataset_id, "speed": "instant"}
    )
    assert response.status_code == 202
    result = finished(client, response.json()["id"])
    assert result["status"] == "completed"
    assert result["processed_events"] == result["total_events"] == count
    assert result["alerts_created"] == alerts
    feed = client.get(f"/runs/{result['id']}/feed").json()
    assert len(feed["alerts"]) == alerts
    for alert in feed["alerts"]:
        detail = client.get("/alerts/" + alert["id"]).json()
        assert detail["event_count"] == len(detail["evidence"])
    if dataset_id == "auth-duplicates":
        assert result["duplicate_events"] == 25
        assert result["metrics"]["events_processed"] == 25


def test_repeated_replays_are_independent_not_stale(client: TestClient) -> None:
    first = finished(
        client,
        client.post(
            "/detections/replay",
            json={
                "dataset_id": "auth-brute-force",
            },
        ).json()["id"],
    )
    second = finished(
        client,
        client.post(
            "/detections/replay",
            json={
                "dataset_id": "auth-brute-force",
            },
        ).json()["id"],
    )
    assert first["id"] != second["id"]
    assert first["processed_events"] == second["processed_events"] == 25
    assert first["alerts_created"] == second["alerts_created"] == 1
    hits = client.get("/alerts").json()["items"]
    assert len(hits) == 2 and hits[0]["id"] != hits[1]["id"]
    negative = finished(
        client,
        client.post(
            "/detections/replay",
            json={
                "dataset_id": "auth-normal-failures",
            },
        ).json()["id"],
    )
    assert negative["alerts_created"] == 0
    assert client.get("/alerts", params={"run_id": negative["id"]}).json()["total"] == 0


def test_ten_x_speed_progress_and_snapshot(client: TestClient) -> None:
    started = time.monotonic()
    response = client.post(
        "/detections/replay",
        json={
            "dataset_id": "auth-brute-force",
            "speed": "10x",
        },
    )
    run_id = response.json()["id"]
    time.sleep(0.35)
    in_progress = client.get("/detections/replay/" + run_id).json()
    assert 0 < in_progress["processed_events"] < 25
    assert in_progress["status"] == "running"
    client.patch("/rules/AUTH-001", json={"enabled": False})
    result = finished(client, run_id)
    elapsed = time.monotonic() - started
    assert result["status"] == "completed"
    assert result["alerts_created"] == 1
    assert result["rules_count"] == 7
    assert elapsed >= 2.4


def test_realtime_cancellation_and_capacity(client: TestClient) -> None:
    ids = []
    for _ in range(2):
        response = client.post(
            "/detections/replay",
            json={
                "dataset_id": "auth-brute-force",
                "speed": "realtime",
            },
        )
        assert response.status_code == 202
        ids.append(response.json()["id"])
    overloaded = client.post(
        "/detections/replay",
        json={
            "dataset_id": "auth-brute-force",
            "speed": "realtime",
        },
    )
    assert overloaded.status_code == 429
    for identifier in ids:
        assert client.post(f"/detections/replay/{identifier}/cancel").status_code == 200
        final = finished(client, identifier)
        assert final["status"] == "cancelled"
        assert final["processed_events"] < 25


def test_replay_limits_and_immutable_manual_append(client: TestClient) -> None:
    assert (
        client.post(
            "/detections/replay",
            json={
                "dataset_id": "benign-baseline",
                "speed": "realtime",
            },
        ).status_code
        == 422
    )
    assert client.post("/detections/replay", json={"dataset_id": "../README.md"}).status_code == 404
    assert (
        client.post(
            "/detections/replay",
            json={
                "dataset_id": "auth-brute-force",
                "speed": "fake",
            },
        ).status_code
        == 422
    )
    run = finished(
        client, client.post("/detections/replay", json={"dataset_id": "auth-success"}).json()["id"]
    )
    event = client.get(f"/runs/{run['id']}/feed").json()["events"][0]
    del event["storage_id"]
    del event["run_id"]
    import json

    assert (
        client.post(
            "/events",
            json={
                "format": "json",
                "content": json.dumps(event),
                "run_id": run["id"],
            },
        ).status_code
        == 409
    )


def test_interrupted_replay_becomes_explicit_failure(tmp_path: Path) -> None:
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'restart.sqlite3'}")
    service = Platform(settings)
    with service.db.session() as session:
        session.add(
            RunRecord(
                id="interrupted",
                name="Interrupted replay",
                kind="replay",
                status="running",
                rules_snapshot=[],
                total_events=25,
            )
        )
    service.close()
    restarted = Platform(settings)
    try:
        result = restarted.run("interrupted")
        assert result["status"] == "failed"
        assert "restarted" in result["error"]
    finally:
        restarted.close()


def test_disabled_rules_are_not_evaluated_in_new_replay(client: TestClient) -> None:
    client.patch("/rules/AUTH-001", json={"enabled": False})
    result = finished(
        client,
        client.post(
            "/detections/replay",
            json={
                "dataset_id": "auth-brute-force",
            },
        ).json()["id"],
    )
    assert result["alerts_created"] == 0
    assert result["metrics"]["rules_evaluated"] == 25 * 6
