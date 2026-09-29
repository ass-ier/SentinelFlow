import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlencode, urlsplit

from app.integrations.normalize import normalize_batch, stamp
from app.integrations.profiles import QueryProfile
from app.integrations.schemas import ConnectorConfig
from app.integrations.settings import SecretStore
from app.integrations.transport import (
    HTTPResult,
    HTTPTransport,
    IntegrationError,
    encoded_json,
    require_success,
)
from app.schemas.events import NormalizedEvent


@dataclass(frozen=True)
class PollPage:
    events: list[NormalizedEvent]
    state: dict[str, Any]
    complete: bool


class TelemetryConnector(Protocol):
    def test_connection(self, profile: QueryProfile, now: datetime) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def poll(self, profile: QueryProfile, state: dict[str, Any], now: datetime) -> PollPage: ...
    def health(self) -> dict[str, Any]: ...


def cycle(state: dict[str, Any], config: ConnectorConfig, now: datetime) -> tuple[str, str]:
    if state.get("start") and state.get("end"):
        return str(state["start"]), str(state["end"])
    previous = (
        stamp(state["checkpoint"])
        if state.get("checkpoint")
        else now - timedelta(seconds=config.lookback_seconds)
    )
    lower = previous - timedelta(seconds=config.overlap_seconds)
    return lower.isoformat(), now.isoformat()


class MicrosoftConnector:
    def __init__(
        self,
        connector_id: str,
        config: ConnectorConfig,
        transport: HTTPTransport,
        secrets: SecretStore,
        *,
        oauth_base: str = "https://login.microsoftonline.com",
        api_base: str,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.id, self.config, self.transport, self.secrets = (
            connector_id,
            config,
            transport,
            secrets,
        )
        self.oauth_base, self.api_base, self.sleep = oauth_base, api_base, sleep
        self.token = ""
        self.token_expires = 0.0
        self.deadline = time.monotonic() + 60
        self.stopped = False
        self.retries = 0

    def start(self) -> None:
        self.stopped = False
        self.deadline = time.monotonic() + 60
        self.retries = 0

    def stop(self) -> None:
        self.stopped = True
        self.token = ""

    def health(self) -> dict[str, Any]:
        return {"status": "disabled" if self.stopped else "configured", "retry_count": self.retries}

    def _request(
        self, method: str, url: str, *, body: bytes | None = None, oauth: bool = False
    ) -> HTTPResult:
        for attempt in range(3):
            if self.stopped or time.monotonic() >= self.deadline:
                raise IntegrationError("timeout")
            try:
                result = self.transport.request(
                    method,
                    url,
                    body=body,
                    timeout=min(5, self.deadline - time.monotonic()),
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded"
                        if oauth
                        else "application/json",
                        **({} if oauth else {"Authorization": f"Bearer {self.token}"}),
                    },
                )
                if result.status == 400 and self.config.type == "microsoft_sentinel" and not oauth:
                    error = result.json().get("error", {})
                    inner = error.get("innererror", {}) if isinstance(error, dict) else {}
                    if (
                        isinstance(inner, dict)
                        and inner.get("code") == "SemanticError"
                        and (
                            "resolve" in str(inner.get("message", "")).lower()
                            and "table" in str(inner.get("message", "")).lower()
                        )
                    ):
                        raise IntegrationError("table_unavailable", http_status=400)
                return require_success(result)
            except IntegrationError as exc:
                if not exc.transient or attempt == 2:
                    raise
                delay = exc.retry_after if exc.retry_after is not None else 2**attempt
                if time.monotonic() + delay >= self.deadline:
                    raise
                self.retries += 1
                self.sleep(delay)
        raise IntegrationError("timeout")

    def authenticate(self) -> None:
        if time.monotonic() < self.token_expires:
            return
        config = self.config
        if not config.tenant_id or not config.client_id or not config.secret_ref:
            raise IntegrationError("configuration_error")
        scope = (
            "https://api.loganalytics.io/.default"
            if config.type == "microsoft_sentinel"
            else "https://graph.microsoft.com/.default"
        )
        response = self._request(
            "POST",
            f"{self.oauth_base}/{config.tenant_id}/oauth2/v2.0/token",
            oauth=True,
            body=urlencode(
                {
                    "grant_type": "client_credentials",
                    "client_id": config.client_id,
                    "client_secret": self.secrets.read(config.secret_ref),
                    "scope": scope,
                }
            ).encode(),
        ).json()
        token = response.get("access_token")
        expires = response.get("expires_in")
        if (
            not isinstance(token, str)
            or not token
            or not token.isascii()
            or any(c.isspace() for c in token)
            or not isinstance(expires, int)
            or isinstance(expires, bool)
            or not 1 <= expires <= 86400
        ):
            raise IntegrationError("invalid_response")
        self.token = token
        self.token_expires = time.monotonic() + max(0, expires - 60)

    def test_connection(self, profile: QueryProfile, now: datetime) -> None:
        self.poll(profile, {}, now)

    def poll(self, profile: QueryProfile, state: dict[str, Any], now: datetime) -> PollPage:
        raise NotImplementedError

    def normalized(
        self, rows: list[dict[str, Any]], profile: QueryProfile, start: str, end: str
    ) -> list[NormalizedEvent]:
        events = normalize_batch(rows, profile, self.config.type, self.id)
        if any(not stamp(start) <= event.event.timestamp <= stamp(end) for event in events):
            raise IntegrationError("invalid_response")
        return events


def azure_rows(response: dict[str, Any]) -> list[dict[str, Any]]:
    if "error" in response:
        raise IntegrationError("invalid_response")
    tables = response.get("tables")
    if not isinstance(tables, list) or len(tables) != 1:
        raise IntegrationError("invalid_response")
    table = tables[0]
    if not isinstance(table, dict) or table.get("name") != "PrimaryResult":
        raise IntegrationError("invalid_response")
    columns, rows = table.get("columns"), table.get("rows")
    if (
        not isinstance(columns, list)
        or not columns
        or not isinstance(rows, list)
        or len(columns) > 256
        or len(rows) > 501
        or any(
            not isinstance(item, dict) or not isinstance(item.get("name"), str) for item in columns
        )
    ):
        raise IntegrationError("invalid_response")
    names = [column["name"] for column in columns]
    if len(names) != len(set(names)):
        raise IntegrationError("invalid_response")
    if any(not isinstance(row, list) or len(row) != len(names) for row in rows):
        raise IntegrationError("invalid_response")
    return [dict(zip(names, row, strict=True)) for row in rows]


class SentinelConnector(MicrosoftConnector):
    def __init__(
        self,
        connector_id: str,
        config: ConnectorConfig,
        transport: HTTPTransport,
        secrets: SecretStore,
        *,
        api_base: str = "https://api.loganalytics.azure.com",
        oauth_base: str = "https://login.microsoftonline.com",
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__(
            connector_id,
            config,
            transport,
            secrets,
            api_base=api_base,
            oauth_base=oauth_base,
            sleep=sleep,
        )

    def poll(self, profile: QueryProfile, state: dict[str, Any], now: datetime) -> PollPage:
        self.authenticate()
        if not self.config.workspace_id:
            raise IntegrationError("configuration_error")
        start, end = cycle(state, self.config, now)
        query = (
            f"{profile.table} | where {profile.timestamp} between "
            f"(datetime({stamp(start).isoformat()}) .. datetime({stamp(end).isoformat()})) "
            "| extend _sf_key=coalesce(tostring(column_ifexists('_ItemId', '')), "
            "tostring(column_ifexists('Id', '')), tostring(column_ifexists('ReportId', ''))) "
            f"| extend _sf_time={profile.timestamp}, _sf_id=hash_sha256(strcat(_sf_key, '|', "
            "tostring(column_ifexists('DeviceName', '')), '|', "
            f"tostring({profile.timestamp}))) "
        )
        if state.get("cursor"):
            cursor = state["cursor"]
            if not isinstance(cursor, dict) or not re.fullmatch(
                r"[a-f0-9]{64}", str(cursor.get("id"))
            ):
                raise IntegrationError("invalid_response")
            when = stamp(cursor.get("timestamp")).isoformat()
            query += (
                f"| where _sf_time > datetime({when}) or (_sf_time == datetime({when}) "
                f"and _sf_id > '{cursor['id']}') "
            )
        query += f"| order by _sf_time asc, _sf_id asc | take {self.config.page_size + 1}"
        result = self._request(
            "POST",
            f"{self.api_base}/v1/workspaces/{self.config.workspace_id}/query",
            body=encoded_json({"query": query}),
        )
        rows = azure_rows(result.json())
        if any(
            not row.get("_sf_key") or not re.fullmatch(r"[a-f0-9]{64}", str(row.get("_sf_id")))
            for row in rows
        ):
            raise IntegrationError("invalid_response")
        keys = [(stamp(row.get("_sf_time")), row["_sf_id"]) for row in rows]
        if keys != sorted(set(keys)):
            raise IntegrationError("invalid_response")
        if (
            keys
            and state.get("cursor")
            and keys[0] <= (stamp(state["cursor"]["timestamp"]), state["cursor"]["id"])
        ):
            raise IntegrationError("invalid_response")
        more = len(rows) > self.config.page_size
        page = rows[: self.config.page_size]
        normalized = self.normalized(
            [
                {key: value for key, value in row.items() if not key.startswith("_sf_")}
                for row in page
            ],
            profile,
            start,
            end,
        )
        next_state = (
            {
                **state,
                "start": start,
                "end": end,
                "cursor": {"timestamp": page[-1]["_sf_time"], "id": page[-1]["_sf_id"]},
            }
            if more
            else {"checkpoint": end}
        )
        return PollPage(normalized, next_state, not more)


class GraphConnector(MicrosoftConnector):
    def __init__(
        self,
        connector_id: str,
        config: ConnectorConfig,
        transport: HTTPTransport,
        secrets: SecretStore,
        *,
        api_base: str = "https://graph.microsoft.com",
        oauth_base: str = "https://login.microsoftonline.com",
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__(
            connector_id,
            config,
            transport,
            secrets,
            api_base=api_base,
            oauth_base=oauth_base,
            sleep=sleep,
        )

    def poll(self, profile: QueryProfile, state: dict[str, Any], now: datetime) -> PollPage:
        self.authenticate()
        start, end = cycle(state, self.config, now)
        endpoint = f"{self.api_base}/v1.0/auditLogs/{profile.table}"
        url = state.get("next_link") or endpoint + "?" + urlencode(
            {
                "$filter": (
                    f"{profile.timestamp} ge {stamp(start).isoformat()} "
                    f"and {profile.timestamp} le {stamp(end).isoformat()}"
                ),
                "$top": self.config.page_size,
            }
        )
        if self.config.mode == "demo" and state.get("next_link"):
            previous = urlsplit(url)
            if previous.scheme != "http" or previous.hostname != "127.0.0.1":
                raise IntegrationError("ssrf_denied")
            url = self.api_base + previous.path + ("?" + previous.query if previous.query else "")
        self.check_next_link(url, endpoint)
        response = self._request("GET", url).json()
        rows = response.get("value")
        if (
            not isinstance(rows, list)
            or len(rows) > self.config.page_size
            or any(not isinstance(row, dict) or not isinstance(row.get("id"), str) for row in rows)
        ):
            raise IntegrationError("invalid_response")
        link = response.get("@odata.nextLink")
        if link is not None:
            self.check_next_link(link, endpoint)
            if link == url or link in state.get("visited", []):
                raise IntegrationError("invalid_response")
        next_state = (
            {
                **state,
                "start": start,
                "end": end,
                "next_link": link,
                "visited": [*state.get("visited", []), url][-100:],
            }
            if link
            else {"checkpoint": end}
        )
        return PollPage(self.normalized(rows, profile, start, end), next_state, not link)

    @staticmethod
    def check_next_link(value: Any, endpoint: str) -> None:
        if not isinstance(value, str) or len(value) > 8192:
            raise IntegrationError("invalid_response")
        parsed, expected = urlsplit(value), urlsplit(endpoint)
        if (
            (parsed.scheme, parsed.netloc, parsed.path)
            != (expected.scheme, expected.netloc, expected.path)
            or parsed.username
            or parsed.password
            or parsed.fragment
            or not value.isascii()
            or any(c.isspace() for c in value)
        ):
            raise IntegrationError("ssrf_denied")
