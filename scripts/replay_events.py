import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.core.errors import DomainError
from app.parsers import parse_content


def request(api: str, path: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    parsed = urlparse(api)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise DomainError("API address must be HTTP(S), without credentials, query, or fragment")
    headers = {"Content-Type": "application/json"}
    token = os.getenv("SENTINEL_API_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(  # noqa: S310 - validated HTTP(S) API address
        api.rstrip("/") + path,
        data=json.dumps(data).encode() if data is not None else None,
        headers=headers,
    )
    with urllib.request.urlopen(req, timeout=60) as response:  # noqa: S310 - explicit user API URL
        return json.load(response)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay inert telemetry into the running local app"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", type=Path)
    source.add_argument("--dataset")
    parser.add_argument("--format", choices=["json", "jsonl", "csv", "syslog", "windows"])
    parser.add_argument("--speed", choices=["instant", "realtime", "10x"], default="instant")
    parser.add_argument("--api", default="http://127.0.0.1:8765")
    args = parser.parse_args()
    if args.dataset:
        run = request(
            args.api, "/detections/replay", {"dataset_id": args.dataset, "speed": args.speed}
        )
        previous = -1
        while run["status"] in {"pending", "running"}:
            if run["processed_events"] != previous:
                print(
                    f"Processed {run['processed_events']}/{run['total_events']}; "
                    f"alerts={run['alerts_created']}"
                )
                previous = run["processed_events"]
            time.sleep(0.1)
            run = request(args.api, "/detections/replay/" + run["id"])
        if run["status"] != "completed":
            raise DomainError(f"Replay {run['status']}: {run['error'] or 'cancelled'}")
    else:
        if args.file.stat().st_size > 5 * 1024 * 1024:
            raise DomainError("File exceeds 5 MiB")
        log_format = args.format or {
            ".json": "json",
            ".jsonl": "jsonl",
            ".csv": "csv",
            ".log": "syslog",
        }.get(args.file.suffix)
        if log_format is None:
            raise DomainError("Specify --format for this file extension")
        events = parse_content(args.file.read_text(encoding="utf-8"), log_format)
        events.sort(key=lambda event: (event.event.timestamp, event.event.id))
        run = None
        divisor = 10 if args.speed == "10x" else 1
        started = time.monotonic()
        chunks = [events] if args.speed == "instant" else [[event] for event in events]
        for chunk in chunks:
            if args.speed != "instant":
                target = (
                    chunk[0].event.timestamp - events[0].event.timestamp
                ).total_seconds() / divisor
                time.sleep(max(0.0, target - (time.monotonic() - started)))
            response = request(
                args.api,
                "/events",
                {
                    "format": "json",
                    "name": args.file.name,
                    "content": json.dumps([event.model_dump(mode="json") for event in chunk]),
                    "run_id": run["id"] if run else None,
                },
            )
            run = response["run"]
            print(
                f"Processed {run['processed_events']}/{len(events)}; alerts={run['alerts_created']}"
            )
        assert run is not None
    print(
        json.dumps(
            {
                "run_id": run["id"],
                "events_processed": run["processed_events"],
                "unique_events": run["metrics"]["events_processed"],
                "duplicates_ignored": run["duplicate_events"],
                "detections_triggered": run["alerts_created"],
                "alerts_created": run["alerts_created"],
                "status": run["status"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.HTTPError as exc:
        print(exc.read().decode("utf-8", errors="replace"), file=sys.stderr)
        raise SystemExit(1) from exc
    except (DomainError, urllib.error.URLError, OSError) as exc:
        print(f"Replay failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
