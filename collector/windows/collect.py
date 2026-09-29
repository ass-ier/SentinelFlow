"""Run with the repository's pinned Python environment, including on Windows."""

import argparse
import json
import os
import sys
import time
from pathlib import Path

from app.core.errors import DomainError
from app.core.safe import json_loads
from app.integrations.collector import CHANNELS, Collector, FixtureEventSource, WindowsEventSource
from app.integrations.settings import IntegrationSettings
from app.integrations.transport import SafeHTTPTransport, checked_url


def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelFlow Windows/WEF collector")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--spool", type=Path, required=True)
    parser.add_argument("--channel", action="append", choices=CHANNELS)
    parser.add_argument("--retry-blocked", action="store_true")
    parser.add_argument("--local-test", action="store_true")
    parser.add_argument("--batch-size", type=int, default=100)
    args = parser.parse_args()
    try:
        endpoint = os.environ.get("SENTINEL_COLLECTOR_URL", "")
        token = os.environ.get("SENTINEL_COLLECTOR_TOKEN", "")
        connector_id = os.environ.get("SENTINEL_COLLECTOR_ID", "")
        if not connector_id:
            raise DomainError(
                "Set SENTINEL_COLLECTOR_ID, SENTINEL_COLLECTOR_URL "
                "and SENTINEL_COLLECTOR_TOKEN locally"
            )
        policy = IntegrationSettings(
            allow_local_http=args.local_test,
            allowed_networks=tuple(
                item
                for item in os.getenv("SENTINEL_COLLECTOR_ALLOWED_NETWORKS", "").split(",")
                if item
            ),
        )
        checked_url(endpoint, policy, query=False)
        events = json_loads(args.fixture.read_text()) if args.fixture else None
        if isinstance(events, dict):
            events = events.get("windows")
        if args.fixture and (
            not isinstance(events, list) or not all(isinstance(row, dict) for row in events)
        ):
            raise DomainError("Fixture must contain a Windows event array")
        source = FixtureEventSource(events) if isinstance(events, list) else WindowsEventSource()
        collector = Collector(
            args.spool,
            connector_id,
            endpoint,
            token,
            source,
            SafeHTTPTransport(policy),
            channels=tuple(args.channel or ["ForwardedEvents"]),
            batch_size=args.batch_size,
        )
        try:
            if args.retry_blocked:
                collector.retry_blocked()
            while True:
                result = collector.cycle()
                print(json.dumps(result), flush=True)
                if args.once:
                    return 2 if result["pending"] else 0
                time.sleep(5)
        finally:
            collector.close()
    except (DomainError, OSError) as exc:
        print(
            exc.message
            if isinstance(exc, DomainError)
            else "Collector storage/configuration is unavailable",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
