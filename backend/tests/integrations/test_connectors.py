from collections import deque
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

import pytest

from app.integrations.connectors import GraphConnector, SentinelConnector, azure_rows
from app.integrations.demo import DemoSecrets, DemoServer, demo_fixtures
from app.integrations.normalize import normalize_provider
from app.integrations.profiles import GRAPH_PROFILES, SENTINEL_PROFILES
from app.integrations.schemas import ConnectorConfig, QuerySelection
from app.integrations.settings import IntegrationSettings
from app.integrations.transport import HTTPResult, IntegrationError, SafeHTTPTransport, encoded_json

pytestmark = [pytest.mark.connectors, pytest.mark.integration]
NOW = datetime(2026, 1, 15, 10, 10, tzinfo=UTC)
GUID = "00000000-0000-0000-0000-000000000001"


def config(kind: str, **extra: Any) -> ConnectorConfig:
    return ConnectorConfig.model_validate(
        {
            "name": "Test connector",
            "type": kind,
            "enabled": True,
            "tenant_id": GUID,
            "client_id": GUID,
            "workspace_id": GUID,
            "secret_ref": "SENTINEL_INTEGRATION_DEMO_SECRET",
            **extra,
        }
    )


def response(value: dict, status: int = 200, headers: dict | None = None) -> HTTPResult:
    return HTTPResult(status, headers or {}, encoded_json(value))


class Responses:
    def __init__(self, items: list[HTTPResult | IntegrationError]) -> None:
        self.items = deque(items)
        self.requests: list[dict] = []

    def request(self, method: str, url: str, **kwargs: Any) -> HTTPResult:
        self.requests.append({"method": method, "url": url, **kwargs})
        item = self.items.popleft()
        if isinstance(item, IntegrationError):
            raise item
        return item


def authorized(transport: Responses, kind: str = "microsoft_graph"):
    adapter = (GraphConnector if kind == "microsoft_graph" else SentinelConnector)(
        "test", config(kind), transport, DemoSecrets(), sleep=lambda _: None
    )
    adapter.token = "synthetic-access"
    adapter.token_expires = float("inf")
    adapter.start()
    return adapter


@pytest.mark.parametrize("kind", ["microsoft_sentinel", "microsoft_graph"])
def test_oauth_client_credentials_are_sent_only_to_identity_endpoint(kind: str) -> None:
    transport = Responses([response({"access_token": "synthetic-access", "expires_in": 3600})])
    adapter = (SentinelConnector if kind == "microsoft_sentinel" else GraphConnector)(
        "test", config(kind), transport, DemoSecrets()
    )
    adapter.authenticate()
    adapter.authenticate()
    assert len(transport.requests) == 1
    request = transport.requests[0]
    assert request["url"] == f"https://login.microsoftonline.com/{GUID}/oauth2/v2.0/token"
    assert b"grant_type=client_credentials" in request["body"]
    assert "Authorization" not in request["headers"]
    assert "secret" not in str(adapter.health())
    adapter.stop()
    assert not adapter.token


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"access_token": "", "expires_in": 3600},
        {"access_token": "bad\nheader", "expires_in": 3600},
        {"access_token": "synthetic", "expires_in": -1},
        {"access_token": "synthetic", "expires_in": True},
    ],
)
def test_invalid_oauth_response_does_not_create_connection(body: dict) -> None:
    transport = Responses([response(body)])
    adapter = GraphConnector("test", config("microsoft_graph"), transport, DemoSecrets())
    with pytest.raises(IntegrationError, match="invalid"):
        adapter.authenticate()


@pytest.mark.parametrize("kind", ["microsoft_sentinel", "microsoft_graph"])
@pytest.mark.parametrize(
    ("status", "code", "attempts"),
    [
        (401, "authentication_error", 1),
        (403, "forbidden", 1),
        (429, "rate_limited", 3),
        (500, "upstream_error", 3),
        (503, "upstream_error", 3),
    ],
)
def test_bounded_http_failures(kind: str, status: int, code: str, attempts: int) -> None:
    transport = Responses(
        [response({"error": "sensitive upstream response"}, status, {"retry-after": "0"})]
        * attempts
    )
    adapter = authorized(transport, kind)
    with pytest.raises(IntegrationError) as failure:
        adapter.poll(
            SENTINEL_PROFILES[0] if kind == "microsoft_sentinel" else GRAPH_PROFILES[0], {}, NOW
        )
    assert failure.value.code == code
    assert "sensitive" not in str(failure.value)
    assert len(transport.requests) == attempts


@pytest.mark.parametrize("code", ["timeout", "network_error"])
def test_network_errors_are_retried_only_three_times(code: str) -> None:
    transport = Responses([IntegrationError(code)] * 3)
    with pytest.raises(IntegrationError):
        authorized(transport).poll(GRAPH_PROFILES[0], {}, NOW)
    assert len(transport.requests) == 3


def test_long_retry_after_is_deferred_instead_of_ignored() -> None:
    transport = Responses([response({}, 429, {"retry-after": "120"})])
    with pytest.raises(IntegrationError) as failure:
        authorized(transport).poll(GRAPH_PROFILES[0], {}, NOW)
    assert failure.value.retry_after == 120
    assert len(transport.requests) == 1


@pytest.mark.regression
def test_connection_test_cannot_reset_and_extend_the_shared_poll_deadline() -> None:
    transport = Responses([])
    adapter = authorized(transport)
    adapter.deadline = 0
    with pytest.raises(IntegrationError) as failure:
        adapter.test_connection(GRAPH_PROFILES[0], NOW)
    assert failure.value.code == "timeout"
    assert transport.requests == []


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"tables": []},
        {"tables": [{}]},
        {"error": {"code": "PartialError"}, "tables": []},
        {
            "tables": [
                {"name": "PrimaryResult", "columns": [{"name": "x"}, {"name": "x"}], "rows": []}
            ]
        },
        {"tables": [{"name": "PrimaryResult", "columns": [{"name": "x"}], "rows": [[1, 2]]}]},
        {"tables": [{"name": "PrimaryResult", "columns": ["x"], "rows": []}]},
    ],
)
def test_azure_malformed_and_partial_responses_do_not_advance_state(body: dict) -> None:
    with pytest.raises(IntegrationError):
        azure_rows(body)


def test_azure_rows_columns_conversion_and_empty() -> None:
    value = {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [
                    {"name": "TimeGenerated", "type": "datetime"},
                    {"name": "ResultType", "type": "string"},
                ],
                "rows": [["2026-01-15T10:00:00Z", "50126"]],
            }
        ]
    }
    assert azure_rows(value) == [{"TimeGenerated": "2026-01-15T10:00:00Z", "ResultType": "50126"}]
    value["tables"][0]["rows"] = []
    assert azure_rows(value) == []


@pytest.mark.parametrize(
    "link",
    [
        "http://169.254.169.254/metadata",
        "https://evil.example/v1.0/auditLogs/signIns",
        "https://graph.microsoft.com.evil.example/v1.0/auditLogs/signIns",
        "https://graph.microsoft.com/v1.0/users",
        "//graph.microsoft.com/v1.0/auditLogs/signIns",
        "https://user:secret@graph.microsoft.com/v1.0/auditLogs/signIns",
        "https://graph.microsoft.com/v1.0/auditLogs/signIns#fragment",
        42,
    ],
)
@pytest.mark.security
def test_graph_next_link_never_leaks_bearer_to_another_destination(link: Any) -> None:
    transport = Responses([response({"value": [], "@odata.nextLink": link})])
    with pytest.raises(IntegrationError):
        authorized(transport).poll(GRAPH_PROFILES[0], {}, NOW)
    assert len(transport.requests) == 1


@pytest.mark.parametrize("kind", ["microsoft_sentinel", "microsoft_graph"])
def test_actual_mock_http_pagination_overlap_and_empty(kind: str) -> None:
    server = DemoServer()
    try:
        adapter = (SentinelConnector if kind == "microsoft_sentinel" else GraphConnector)(
            "test",
            config(kind, page_size=3),
            SafeHTTPTransport(IntegrationSettings(allow_local_http=True)),
            DemoSecrets(),
            api_base=server.url,
            oauth_base=server.url,
        )
        profile = SENTINEL_PROFILES[0] if kind == "microsoft_sentinel" else GRAPH_PROFILES[0]
        state: dict = {}
        events = []
        for _ in range(6):
            page = adapter.poll(profile, state, NOW)
            events.extend(page.events)
            state = page.state
            if page.complete:
                break
        assert len(events) == 12
        assert len({event.event.id for event in events}) == 12
        assert state == {"checkpoint": NOW.isoformat()}
        assert adapter.poll(profile, state, NOW).events == []
    finally:
        server.close()


@pytest.mark.parametrize("profile", GRAPH_PROFILES)
def test_graph_schema_metadata_and_raw_evidence(profile) -> None:
    raw = deepcopy(demo_fixtures()["graph"][profile.table][0])
    event = normalize_provider(raw, profile, "microsoft_graph", "test")
    assert event.raw_event == raw
    assert event.metadata["provider"] == "microsoft_graph"
    assert event.metadata["source_table"] == profile.table
    assert event.metadata["connector_id"] == "test"
    assert event.event.timestamp.tzinfo == UTC
    assert event.user.name
    if profile.id == "signins":
        assert event.event.outcome == "failure"
        assert event.source.ip == "192.0.2.44"
        assert event.metadata["identity"]["email"] == "analyst01@example.invalid"


def test_missing_cloud_host_is_not_invented_for_iam_grouping() -> None:
    raw = deepcopy(demo_fixtures()["graph"]["directoryAudits"][0])
    del raw["additionalDetails"]
    event = normalize_provider(raw, GRAPH_PROFILES[1], "microsoft_graph", "test")
    assert event.host.name is None


def test_unknown_query_profile_and_arbitrary_kql_rejected(client) -> None:
    result = client.post(
        "/api/integrations/connectors",
        json={
            "name": "Untrusted query",
            "type": "microsoft_sentinel",
            "profiles": [{"id": "signin_logs", "kql": "arbitrary query"}],
        },
    )
    assert result.status_code == 422
    result = client.post(
        "/api/integrations/connectors",
        json={
            "name": "Unknown",
            "type": "microsoft_sentinel",
            "profiles": [{"id": "custom_table"}],
        },
    )
    assert result.status_code == 422


def test_runtime_missing_profile_failure_does_not_block_other_sources(service) -> None:
    runtime = service.integrations
    data = config(
        "microsoft_sentinel",
        mode="demo",
        profiles=[
            QuerySelection(id="windows_security").model_dump(),
            QuerySelection(id="signin_logs").model_dump(),
        ],
    )
    created = runtime.management.save_connector(data, "test")
    result = runtime.poll(created["id"], "test")
    assert result["status"] == "degraded"
    assert result["events_processed"] == 12
    assert result["last_error"] is not None
    assert service.alerts({}, 0, 10)["total"] == 1


def test_missing_sentinel_table_has_an_explicit_non_sensitive_error() -> None:
    transport = Responses(
        [
            response(
                {
                    "error": {
                        "code": "BadArgumentError",
                        "innererror": {
                            "code": "SemanticError",
                            "message": "Failed to resolve table expression named ExampleTable",
                        },
                    }
                },
                400,
            )
        ]
    )
    with pytest.raises(IntegrationError) as failure:
        authorized(transport, "microsoft_sentinel").poll(SENTINEL_PROFILES[0], {}, NOW)
    assert failure.value.code == "table_unavailable"
    assert "ExampleTable" not in failure.value.message


@pytest.mark.security
def test_invalid_provider_data_is_counted_without_killing_worker_or_advancing_state(
    service, monkeypatch
) -> None:
    from app.integrations.normalize import ProviderDataError, normalize_batch
    from app.storage.integrations import CheckpointRecord

    runtime = service.integrations
    body = config(
        "microsoft_graph", mode="demo", profiles=[QuerySelection(id="signins").model_dump()]
    )
    created = runtime.management.save_connector(body, "test")
    raw = deepcopy(demo_fixtures()["graph"]["signIns"][0])
    raw["ipAddress"] = "malformed-sensitive-value"
    with pytest.raises(ProviderDataError) as failure:
        normalize_batch([raw], GRAPH_PROFILES[0], "microsoft_graph", created["id"])
    assert failure.value.received == 1
    transport = Responses([response({"value": [raw]})])
    adapter = authorized(transport)
    monkeypatch.setattr(runtime, "adapter", lambda *_: adapter)
    result = runtime.poll(created["id"], "test")
    assert result["events_failed"] == result["events_received"] == 1
    assert result["events_processed"] == 0
    assert result["last_error"] == "invalid_telemetry"
    assert "malformed-sensitive-value" not in str(result)
    with service.db.session() as session:
        assert session.get(CheckpointRecord, (created["id"], "signins")).state == {}


@pytest.mark.parametrize(
    ("profile_id", "extra", "category", "action"),
    [
        (
            "windows_security",
            {
                "EventID": 4625,
                "Computer": "demo-host",
                "TargetUserName": "synthetic",
                "IpAddress": "192.0.2.10",
            },
            "authentication",
            "login",
        ),
        (
            "syslog",
            {
                "Computer": "demo-host",
                "ProcessName": "sshd",
                "SyslogMessage": "Accepted password for synthetic from 192.0.2.10 port 12345",
            },
            "authentication",
            "login",
        ),
        (
            "common_security",
            {
                "Computer": "demo-host",
                "SourceIP": "192.0.2.10",
                "DestinationIP": "198.51.100.10",
                "DestinationPort": 443,
                "Protocol": "tcp",
            },
            "network",
            "connection",
        ),
        (
            "azure_activity",
            {
                "Caller": "synthetic@example.invalid",
                "CallerIpAddress": "192.0.2.10",
                "OperationNameValue": "Synthetic/read",
            },
            "identity",
            "azure_activity",
        ),
        (
            "defender_device_events",
            {
                "DeviceName": "demo-host",
                "ActionType": "DnsQueryResponse",
                "AdditionalFields": '{"QueryName":"synthetic.invalid"}',
            },
            "network",
            "dns_query",
        ),
        (
            "defender_process",
            {
                "DeviceName": "demo-host",
                "FileName": "notepad.exe",
                "ProcessCommandLine": "notepad.exe",
            },
            "process",
            "process_created",
        ),
        (
            "defender_network",
            {
                "DeviceName": "demo-host",
                "LocalIP": "192.0.2.10",
                "RemoteIP": "198.51.100.10",
                "RemotePort": 443,
            },
            "network",
            "connection",
        ),
        (
            "defender_logon",
            {
                "DeviceName": "demo-host",
                "AccountName": "synthetic",
                "RemoteIP": "192.0.2.10",
                "ActionType": "LogonSuccess",
            },
            "authentication",
            "login",
        ),
    ],
)
def test_optional_sentinel_profile_mappings_preserve_real_fields(
    profile_id, extra, category, action
) -> None:
    profile = next(item for item in SENTINEL_PROFILES if item.id == profile_id)
    raw = {profile.timestamp: NOW.isoformat(), **extra}
    event = normalize_provider(raw, profile, "microsoft_sentinel", "test")
    assert event.event.category == category
    assert event.event.action == action
    assert event.raw_event == raw
    assert event.metadata["source_table"] == profile.table
