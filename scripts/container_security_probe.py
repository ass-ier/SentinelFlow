"""Stdlib HTTP probe inside an owned, network-isolated production container."""

import importlib.util
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path


def main() -> None:
    if not __debug__:
        raise RuntimeError("Container verification requires enabled assertions")
    base = "http://127.0.0.1:" + str(int(os.getenv("PORT", "8765")))
    token = os.environ["SENTINEL_API_TOKEN"]
    retries = {"integration_busy": 0, "integration_rate_limit": 0}

    def api(path: str, body: dict | None = None) -> dict:
        request = urllib.request.Request(  # noqa: S310 - fixed in-container loopback endpoint.
            base + "/api" + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        deadline = time.monotonic() + 75
        for _ in range(12):
            try:
                response = urllib.request.urlopen(request, timeout=30)  # noqa: S310
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                result = json.load(response)
            if response.status == 200:
                return result
            code = result.get("error", {}).get("code")
            if path == "/integrations/demo" and (response.status, code) in {
                (409, "integration_busy"),
                (429, "integration_rate_limit"),
            }:
                delay = 61 if response.status == 429 else 1
                if time.monotonic() + delay > deadline:
                    raise RuntimeError(f"{path}: retry deadline exhausted; error={code}")
                retries[code] += 1
                time.sleep(delay)
                continue
            raise RuntimeError(f"{path}: HTTP {response.status}; error={code}")
        raise RuntimeError(f"{path}: retry attempts exhausted")

    assert os.getuid() == 10001
    status = Path("/proc/self/status").read_text()
    assert "CapEff:\t0000000000000000" in status
    assert "NoNewPrivs:\t1" in status
    assert os.statvfs("/").f_flag & os.ST_RDONLY
    for package in ("pip", "pytest", "mypy", "httpx", "piptools", "swagger_ui_bundle"):
        assert importlib.util.find_spec(package) is None, f"Unexpected runtime tool: {package}"
    assert not Path("docs/results/security").exists()
    reports = []
    for source, events, alerts in (
        ("microsoft_sentinel", 13, 2),
        ("microsoft_graph", 13, 2),
        ("windows_wef", 36, 7),
    ):
        result = api("/integrations/demo", {"source": source})
        assert result["events_processed"] == events
        observed = api("/alerts?run_id=" + result["run_id"])
        assert observed["total"] == alerts
        deadline = time.monotonic() + 10
        while True:
            deliveries = [
                api("/notifications/deliveries/" + row["id"]) for row in result["deliveries"]
            ]
            if all(row["status"] == "delivered" for row in deliveries):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Mock deliveries did not finish")
            time.sleep(0.05)
        assert len(deliveries) == alerts
        repeated = api("/integrations/demo", {"source": source})
        assert {row["id"] for row in repeated["deliveries"]} == {row["id"] for row in deliveries}
        reports.append({"source": source, "events": events, "alerts": alerts, "deliveries": alerts})
    assert retries["integration_rate_limit"] >= 1
    print(
        json.dumps(
            {
                "status": "passed",
                "checks": 6 + len(reports),
                "uid": os.getuid(),
                "read_only_root": True,
                "no_new_privileges": True,
                "effective_capabilities": 0,
                "development_tools_absent": True,
                "historical_security_evidence_absent": True,
                "rate_limit_enforced_and_recovered": True,
                "retries": retries,
                "flows": reports,
                "live_integrations": "Not tested",
            }
        )
    )


if __name__ == "__main__":
    main()
