"""Exercise actual loopback HTTP providers/receivers and persist measured workflow evidence."""

import json
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import ROOT, Settings
from app.core.evidence import source_fingerprint
from app.integrations.demo import demo_fixtures
from app.integrations.operations import run_demo
from app.integrations.payloads import NotificationPayload
from app.integrations.settings import IntegrationSettings
from app.services.platform import Platform


def validate() -> dict:
    rows = []
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="sentinelflow-integrations-") as folder:
        service = Platform(
            Settings(
                database_url=f"sqlite:///{Path(folder) / 'validation.sqlite3'}",
                integrations=IntegrationSettings(worker_enabled=False),
            )
        )
        try:
            for source, expected in demo_fixtures()["expected"].items():
                begin = time.perf_counter()
                result = run_demo(service.integrations, source, f"validator-{source}")
                elapsed = time.perf_counter() - begin
                alerts = service.alerts({"run_id": result["run_id"]}, 0, 100)["items"]
                actual = dict(Counter(alert["rule_id"] for alert in alerts))
                if result["events_processed"] != expected["events"] or actual != expected["alerts"]:
                    raise RuntimeError(f"{source}: event or detection count mismatch")
                if len(result["deliveries"]) != len(alerts) or any(
                    row["status"] != "delivered" for row in result["deliveries"]
                ):
                    raise RuntimeError(
                        f"{source}: notification was not accepted by the mock endpoint"
                    )
                for delivery in result["deliveries"]:
                    recorded = service.integrations.management.delivery(delivery["id"])
                    payload = NotificationPayload.model_validate(recorded["payload"])
                    receiver = service.integrations.demo
                    if receiver is None or delivery["idempotency_key"] not in receiver.receipts:
                        raise RuntimeError(f"{source}: no actual receiver receipt")
                    if not payload.mock or payload.event != "security_alert":
                        raise RuntimeError(f"{source}: incorrect notification provenance")
                for alert in alerts:
                    detail = service.alert(alert["id"])
                    if detail["event_count"] != len(detail["evidence"]):
                        raise RuntimeError(f"{source}: evidence count mismatch")
                before = service.integrations.management.deliveries()["total"]
                repeated = run_demo(service.integrations, source, f"validator-{source}")
                if (
                    repeated["events_processed"] != expected["events"]
                    or service.integrations.management.deliveries()["total"] != before
                ):
                    raise RuntimeError(f"{source}: repeated poll duplicated telemetry or delivery")
                rows.append(
                    {
                        "provider": source,
                        "normalized_events": result["events_processed"],
                        "expected_alerts": expected["alerts"],
                        "observed_alerts": actual,
                        "delivered_to_mock": len(result["deliveries"]),
                        "duplicate_deliveries": 0,
                        "workflow_seconds": round(elapsed, 6),
                        "workflow_events_per_second": round(expected["events"] / elapsed, 2),
                        "live_tested": False,
                    }
                )
                print(
                    f"{source}: {expected['events']} events, {len(alerts)} alerts, "
                    f"{len(result['deliveries'])} actual mock receipts; repeated run stable"
                )
        finally:
            service.close()
    return {
        "status": "passed",
        "created_at": datetime.now(UTC).isoformat(),
        "source_fingerprint": source_fingerprint(),
        "scenarios": rows,
        "total_events": sum(row["normalized_events"] for row in rows),
        "total_alerts": sum(sum(row["observed_alerts"].values()) for row in rows),
        "workflow_seconds": round(time.perf_counter() - started, 6),
        "measurement": (
            "Application workflow including loopback HTTP, normalization, SQLite, detection "
            "and notification; not cloud latency or a scale benchmark"
        ),
        "live_tested": False,
    }


if __name__ == "__main__":
    output = ROOT / "artifacts/integrations-validation.json"
    output.parent.mkdir(exist_ok=True)
    output.unlink(missing_ok=True)
    result = validate()
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(output)
