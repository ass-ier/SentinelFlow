import argparse
import sys
import urllib.error

from generate_test_data import generate
from replay_events import request

from app.core.config import Settings
from app.core.errors import DomainError
from app.services.platform import Platform


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reset only the explicitly named SentinelFlow demo DB"
    )
    parser.add_argument(
        "--seed", action="store_true", help="Load the included seven-rule incident timeline"
    )
    parser.add_argument(
        "--offline", action="store_true", help="Use only when the API server is stopped"
    )
    parser.add_argument("--api", default="http://127.0.0.1:8765")
    args = parser.parse_args()
    if args.offline:
        try:
            request(args.api, "/health")
        except urllib.error.URLError:
            pass
        else:
            raise DomainError("The server is running; omit --offline to reset through its API")
        generate()
        service = Platform(Settings())
        try:
            result = service.reset_demo("demo-reset-cli", seed=args.seed)
        finally:
            service.close()
    else:
        generate()
        result = request(
            args.api, "/admin/demo-reset", {"confirmation": "RESET DEMO", "seed": args.seed}
        )
    print(f"Demo {result['status']}; bundled rule states and deterministic fixtures restored.")
    if result["run"]:
        print(f"Seed run: {result['run']['id']}")


if __name__ == "__main__":
    try:
        main()
    except (DomainError, urllib.error.URLError, OSError) as exc:
        print(f"Reset failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
