import hashlib
import json
import re
import threading
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from app.core.config import ROOT
from app.core.errors import DomainError
from app.core.safe import json_loads
from app.integrations.normalize import stamp


def demo_fixtures() -> dict[str, Any]:
    value = json_loads((ROOT / "test-data/integrations/microsoft-windows.json").read_text())
    if not isinstance(value, dict):
        raise DomainError("Integration demo fixtures are invalid", 500, "demo_fixture")
    return value


class DemoSecrets:
    def read(self, reference: str) -> str:
        if reference != "SENTINEL_INTEGRATION_DEMO_SECRET":
            raise DomainError("Demo cannot access live secret references", 403, "demo_secret")
        return "synthetic-oauth-placeholder"


class DemoServer:
    def __init__(self) -> None:
        self.fixtures = demo_fixtures()
        self.receipts: dict[str, dict[str, Any]] = {}
        self.attempts: deque[dict[str, Any]] = deque(maxlen=2000)
        self.statuses: deque[int] = deque()
        self.guard = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def respond(self, status: int, payload: dict[str, Any]) -> None:
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                if status == 429:
                    self.send_header("Retry-After", "1")
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 <= size <= 65536:
                        self.respond(413, {"error": "size_limit"})
                        return
                    body = self.rfile.read(size)
                    if self.path.endswith("/oauth2/v2.0/token"):
                        self.respond(
                            200,
                            {
                                "access_token": "mock-token-not-live",
                                "expires_in": 3600,
                                "token_type": "Bearer",
                            },
                        )
                        return
                    data = json_loads(body.decode())
                    if not isinstance(data, dict):
                        raise DomainError("Object required")
                    if self.path.endswith("/query"):
                        self.logs(data)
                    elif self.path == "/notifications":
                        with owner.guard:
                            status = owner.statuses.popleft() if owner.statuses else 202
                            key = self.headers.get("Idempotency-Key", "")
                            owner.attempts.append({"key": key, "payload": data, "status": status})
                            if 200 <= status < 300:
                                if len(owner.receipts) >= 2000 and key not in owner.receipts:
                                    status = 429
                                else:
                                    owner.receipts.setdefault(key, data)
                        self.respond(status, {"mock": True, "accepted": 200 <= status < 300})
                    else:
                        self.respond(404, {"error": "not_found"})
                except (DomainError, UnicodeError, ValueError, KeyError, IndexError, TypeError):
                    self.respond(400, {"error": "invalid_mock_request"})

            def logs(self, data: dict[str, Any]) -> None:
                query = data.get("query", "")
                table = query.split(" ", 1)[0]
                if table not in owner.fixtures["sentinel"]:
                    self.respond(
                        400,
                        {
                            "error": {
                                "code": "BadArgumentError",
                                "innererror": {
                                    "code": "SemanticError",
                                    "message": "Failed to resolve table expression",
                                },
                            }
                        },
                    )
                    return
                times = re.findall(r"datetime\(([^)]+)\)", query)
                start, end = stamp(times[0]), stamp(times[1])
                rows = []
                for item in owner.fixtures["sentinel"][table]:
                    when = item.get("TimeGenerated", item.get("Timestamp"))
                    if not start <= stamp(when) <= end:
                        continue
                    key = str(item.get("_ItemId", item.get("Id", item.get("ReportId", ""))))
                    identity = hashlib.sha256(
                        f"{key}|{item.get('DeviceName', '')}|{when}".encode()
                    ).hexdigest()
                    rows.append({**item, "_sf_key": key, "_sf_id": identity, "_sf_time": when})
                rows.sort(key=lambda row: (stamp(row["_sf_time"]), row["_sf_id"]))
                cursor = re.search(r"_sf_id > '([a-f0-9]{64})'", query)
                if cursor:
                    rows = [
                        row
                        for row in rows
                        if (stamp(row["_sf_time"]), row["_sf_id"]) > (stamp(times[2]), cursor[1])
                    ]
                take = re.search(r"\| take (\d+)$", query)
                if take is None:
                    raise DomainError("Bounded query required")
                rows = rows[: int(take[1])]
                names = (
                    list(rows[0])
                    if rows
                    else ["Id", "TimeGenerated", "_sf_key", "_sf_id", "_sf_time"]
                )
                self.respond(
                    200,
                    {
                        "tables": [
                            {
                                "name": "PrimaryResult",
                                "columns": [{"name": name, "type": "string"} for name in names],
                                "rows": [[row.get(name) for name in names] for row in rows],
                            }
                        ]
                    },
                )

            def do_GET(self) -> None:
                parsed = urlsplit(self.path)
                table = parsed.path.rsplit("/", 1)[-1]
                if table not in owner.fixtures["graph"]:
                    self.respond(404, {"error": "not_found"})
                    return
                params = parse_qs(parsed.query)
                try:
                    offset, count = (
                        int(params.get("$skiptoken", ["0"])[0]),
                        int(params.get("$top", ["200"])[0]),
                    )
                    if offset < 0 or not 1 <= count <= 500:
                        raise ValueError
                    condition = params.get("$filter", [""])[0]
                    limits = re.findall(r"(?:ge|le) ([^ ]+)", condition)
                    field = "createdDateTime" if table == "signIns" else "activityDateTime"
                    rows = [
                        row
                        for row in owner.fixtures["graph"][table]
                        if stamp(limits[0]) <= stamp(row[field]) <= stamp(limits[1])
                    ]
                    # Graph sign-ins are returned newest first; ingestion must sort them itself.
                    rows = sorted(rows, key=lambda row: row[field], reverse=True)
                    payload: dict[str, Any] = {"value": rows[offset : offset + count]}
                    if offset + count < len(rows):
                        params["$skiptoken"] = [str(offset + count)]
                        payload["@odata.nextLink"] = (
                            owner.url + parsed.path + "?" + urlencode(params, doseq=True)
                        )
                    self.respond(200, payload)
                except (ValueError, DomainError, IndexError):
                    self.respond(400, {"error": "invalid_mock_request"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True, name="sentinel-mock-http"
        )
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
