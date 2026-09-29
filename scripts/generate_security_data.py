"""Persist the bounded, inert API mutation corpus. No network or external targets."""

import argparse
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def generate() -> dict:
    randomizer = random.Random(7341)
    shapes = [None, [], "", 1, True, ["x"], {"unexpected": "synthetic"}]
    for _ in range(9):
        value = randomizer.choice([None, [], False, 1, "synthetic"])
        for _ in range(randomizer.randint(13, 17)):
            value = {"nested": value}
        shapes.append({"unexpected": value})
    malformed = [
        b'{"unterminated":',
        b'{"number":NaN}',
        b'{"number":Infinity}',
        b'{"number":-Infinity}',
        b'{"huge":' + b"9" * 4500 + b"}",
        b"[" * 2000 + b"]" * 2000,
        b'{"bad":"\xff"}',
    ]
    return {
        "synthetic": True,
        "license": "MIT",
        "seed": 7341,
        "targets": [
            "/events",
            "/rules",
            "/sigma/compile",
            "/detections/replay",
            "/detections/validate",
            "/integrations/connectors",
            "/notifications/destinations",
            "/ingest/windows",
            "/alerts/nonexistent/notify",
        ],
        "shape_cases": shapes,
        "malformed_hex": [value.hex() for value in malformed],
        "expected": {
            "requests": 207,
            "internal_errors": 0,
            "stored_events": 0,
            "alerts": 0,
            "new_runs": 0,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    target = ROOT / "test-data/security/api-fuzz.json"
    content = json.dumps(generate(), indent=2, ensure_ascii=True) + "\n"
    if args.check:
        if not target.exists() or target.read_text() != content:
            raise SystemExit("Security corpus differs; run scripts/generate_security_data.py")
    else:
        target.write_text(content)
    print("Security corpus: 16 shape cases + 7 malformed bodies across 9 endpoints (207 requests)")


if __name__ == "__main__":
    main()
