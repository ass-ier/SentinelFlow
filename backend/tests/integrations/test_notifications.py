from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from sqlalchemy import update

from app.core.config import Settings
from app.integrations.destinations import WebhookDestination, signature, verify_signature
from app.integrations.operations import enqueue_test, notify_alert, run_demo
from app.integrations.schemas import DestinationConfig, NotificationPolicy
from app.integrations.settings import EnvironmentSecrets, IntegrationSettings
from app.integrations.transport import IntegrationError, encoded_json
from app.services.platform import Platform
from app.storage.integrations import DeliveryRecord

pytestmark = [pytest.mark.notifications, pytest.mark.integration]


def destination(service, **kwargs):
    value = DestinationConfig(
        name="Mock receiver",
        type="power_automate",
        mode="demo",
        enabled=True,
        **kwargs,
    )
    return service.integrations.management.save_destination(value, "test")


@pytest.mark.parametrize(
    ("statuses", "expected", "attempts"),
    [
        ([200], "delivered", 1),
        ([202], "delivered", 1),
        ([400], "dead_letter", 1),
        ([401], "dead_letter", 1),
        ([403], "dead_letter", 1),
        ([429, 202], "delivered", 2),
        ([500, 200], "delivered", 2),
        ([500, 500, 500], "dead_letter", 3),
        ([429, 429, 429], "dead_letter", 3),
    ],
)
def test_real_loopback_delivery_state_retry_and_permanent_failures(
    service, statuses, expected, attempts
) -> None:
    runtime = service.integrations
    target = destination(service)
    server = runtime.demo_server()
    server.statuses.extend(statuses)
    queued = enqueue_test(runtime, target["id"], "test")
    for _ in range(attempts):
        assert runtime.queue.process_one()
        with service.db.session() as session:
            session.execute(
                update(DeliveryRecord)
                .where(DeliveryRecord.id == queued["id"], DeliveryRecord.status == "failed")
                .values(next_attempt_at=0)
            )
    result = runtime.management.delivery(queued["id"])
    assert result["status"] == expected
    assert result["attempt_count"] == attempts
    assert len(result["attempts"]) == attempts
    assert len(server.attempts) == attempts
    assert not runtime.queue.process_one()
    assert result["payload"]["event"] == "notification_test"
    assert result["payload"]["alert"] is None


def test_retry_after_schedules_real_future_without_immediate_repeat(service) -> None:
    runtime = service.integrations
    runtime.demo_server().statuses.append(429)
    target = destination(service)
    queued = enqueue_test(runtime, target["id"], "test")
    runtime.queue.process_one()
    result = runtime.management.delivery(queued["id"])
    assert result["status"] == "failed"
    assert result["next_attempt_at"] > runtime.queue.clock()
    assert not runtime.queue.process_one()


@pytest.mark.parametrize("code", ["timeout", "network_error"])
def test_timeout_and_connection_failure_retain_inspectable_delivery(
    service, monkeypatch, code
) -> None:
    runtime = service.integrations
    target = destination(service)
    queued = enqueue_test(runtime, target["id"], "test")

    class Unavailable:
        def send(self, *_):
            raise IntegrationError(code)

    monkeypatch.setattr(runtime.queue, "destination", lambda _: Unavailable())
    assert runtime.queue.process_one()
    result = runtime.management.delivery(queued["id"])
    assert result["status"] == "failed"
    assert result["error"] == code
    assert result["attempt_count"] == 1


def test_delivery_never_deletes_alerts_and_statuses_are_independent(service) -> None:
    runtime = service.integrations
    runtime.demo_server().statuses.extend([500, 500])
    report = run_demo(runtime, "microsoft_sentinel", "test")
    assert {item["status"] for item in report["deliveries"]} == {"failed"}
    alerts = service.alerts({"run_id": report["run_id"]}, 0, 10)["items"]
    assert len(alerts) == 2
    assert {item["status"] for item in alerts} == {"new"}
    service.change_status(alerts[0]["id"], "investigating", "test")
    assert runtime.management.deliveries()["total"] == 2
    assert service.alert(alerts[0]["id"])["status"] == "investigating"


@pytest.mark.regression
def test_claimed_and_delivered_messages_are_not_duplicated_by_competing_workers(service) -> None:
    runtime = service.integrations
    target = destination(service)
    queued = enqueue_test(runtime, target["id"], "test")
    runtime.demo_server()
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: runtime.queue.process_one(), range(2)))
    assert sum(results) == 1
    assert runtime.management.delivery(queued["id"])["status"] == "delivered"
    assert len(runtime.demo.attempts) == 1
    assert not runtime.queue.process_one()


@pytest.mark.regression
def test_restart_preserves_delivered_idempotency_and_pending_work(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'persistent.sqlite3'}",
        integrations=IntegrationSettings(worker_enabled=False),
    )
    service = Platform(settings)
    target = destination(service)
    delivered = enqueue_test(service.integrations, target["id"], "test")
    assert service.integrations.queue.process_one()
    pending = enqueue_test(service.integrations, target["id"], "test")
    service.close()
    restored = Platform(settings)
    try:
        assert restored.integrations.management.delivery(delivered["id"])["status"] == "delivered"
        assert restored.integrations.queue.process_one()
        assert restored.integrations.management.delivery(pending["id"])["status"] == "delivered"
        assert len(restored.integrations.demo.attempts) == 1
    finally:
        restored.close()


def test_retry_claim_expiry_does_not_retry_success_and_bounds_uncertain_delivery(service) -> None:
    target = destination(service, max_attempts=1)
    queued = enqueue_test(service.integrations, target["id"], "test")
    with service.db.session() as session:
        row = session.get(DeliveryRecord, queued["id"])
        row.status, row.attempt_count, row.claimed_until = "processing", 1, 0
    assert service.integrations.queue.process_one()
    detail = service.integrations.management.delivery(queued["id"])
    assert detail["status"] == "dead_letter"
    assert detail["error"] == "delivery_uncertain"
    assert detail["attempt_count"] == 1


def test_disabled_deleted_destinations_keep_history_without_delivering(service) -> None:
    target = destination(service)
    queued = enqueue_test(service.integrations, target["id"], "test")
    service.integrations.management.delete_destination(target["id"], "test")
    assert not service.integrations.queue.process_one()
    assert service.integrations.management.delivery(queued["id"])["status"] == "suppressed"
    assert service.integrations.management.destinations() == []


def test_one_alert_destination_pair_despite_multiple_rules_and_manual_retries(
    service, datasets
) -> None:
    target = destination(service)
    for name in ("one", "two"):
        service.integrations.management.save_policy(
            NotificationPolicy(
                name=name,
                destinations=[target["id"]],
                severities=["high"],
                rule_ids=["AUTH-001"],
            ),
            "test",
        )
    result = service.ingest(datasets.events("auth-brute-force"))
    alert = service.alerts({"run_id": result["run"]["id"]}, 0, 10)["items"][0]
    for _ in range(3):
        notify_alert(service.integrations, alert["id"], [target["id"]], "test")
    assert service.integrations.management.deliveries()["total"] == 1
    assert service.integrations.queue.process_one()
    assert len(service.integrations.demo.receipts) == 1
    detail = service.integrations.management.deliveries()["items"][0]
    assert detail["attempt_count"] == 1


def test_default_policies_exclude_replays(service, datasets) -> None:
    target = destination(service)
    service.integrations.management.save_policy(
        NotificationPolicy(
            name="Default",
            destinations=[target["id"]],
        ),
        "test",
    )
    with service.db.session() as session:
        run = service._new_run(session, name="Replay", kind="replay")
        identifier = run.id
    service.ingest(datasets.events("auth-brute-force"), run_id=identifier, replay_worker=True)
    assert service.alerts({"run_id": identifier}, 0, 10)["total"] == 1
    assert service.integrations.management.deliveries()["total"] == 0


@pytest.mark.security
@pytest.mark.parametrize("mode", ["bearer", "hmac"])
def test_real_generic_webhook_authentication_headers_and_signature(
    service, monkeypatch, mode
) -> None:
    from app.integrations.transport import HTTPResult

    monkeypatch.setenv("SENTINEL_INTEGRATION_URL", "https://receiver.example.invalid/alerts")
    monkeypatch.setenv("SENTINEL_INTEGRATION_SECRET", "synthetic-test-signing-key")
    requests = []

    class Receiver:
        def request(self, method, url, **kwargs):
            requests.append(kwargs)
            return HTTPResult(202, {}, b"")

    target = WebhookDestination(
        DestinationConfig(
            name="Authenticated",
            type="webhook",
            enabled=True,
            url_ref="SENTINEL_INTEGRATION_URL",
            auth_ref="SENTINEL_INTEGRATION_SECRET",
            authentication=mode,
        ),
        Receiver(),
        EnvironmentSecrets(),
        IntegrationSettings(),
    )
    payload = {"event": "notification_test", "version": "1.0"}
    target.send(payload, "logical-key")
    request = requests[0]
    assert request["body"] == encoded_json(payload)
    assert request["headers"]["Idempotency-Key"] == "logical-key"
    if mode == "bearer":
        assert request["headers"]["Authorization"] == "Bearer synthetic-test-signing-key"
    else:
        headers = request["headers"]
        assert verify_signature(
            "synthetic-test-signing-key",
            headers["X-SentinelFlow-Timestamp"],
            request["body"],
            headers["X-SentinelFlow-Signature"],
            now=int(headers["X-SentinelFlow-Timestamp"]),
        )
        assert not verify_signature(
            "synthetic-test-signing-key",
            headers["X-SentinelFlow-Timestamp"],
            request["body"] + b"x",
            headers["X-SentinelFlow-Signature"],
            now=int(headers["X-SentinelFlow-Timestamp"]),
        )
    assert signature("key", "100", b"data").startswith("sha256=")
    assert not verify_signature("key", "100", b"data", signature("key", "100", b"data"), now=401)
