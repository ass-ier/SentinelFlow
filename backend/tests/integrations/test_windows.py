import json
from collections import Counter
from copy import deepcopy
from pathlib import Path

import pytest

from app.core.errors import DomainError
from app.integrations.collector import Collector, FixtureEventSource, WindowsEventSource
from app.integrations.demo import demo_fixtures
from app.integrations.normalize import normalize_provider
from app.integrations.profiles import QueryProfile
from app.integrations.schemas import (
    ConnectorConfig,
    CredentialConfig,
    DestinationConfig,
    NotificationPolicy,
)
from app.integrations.transport import HTTPResult, IntegrationError, encoded_json
from app.parsers import parse_content
from app.parsers.windows import WINDOWS_ACTIONS, parse_windows
from app.parsers.windows_xml import windows_xml

pytestmark = [pytest.mark.integration, pytest.mark.connectors]
PROFILE = QueryProfile("windows", "WindowsEvent", "", "windows")


@pytest.mark.parser
@pytest.mark.parametrize(
    "code",
    [4624, 4625, 4740, 4720, 4722, 4725, 4726, 4728, 4732, 4756, 4729, 4733, 4757, 4672, 4688],
)
def test_windows_event_ids_use_documented_semantics(code: int) -> None:
    raw = next(
        row for row in demo_fixtures()["windows"] if row["Event"]["System"]["EventID"] == code
    )
    event = normalize_provider(raw, PROFILE, "windows_wef", "collector")
    assert (event.event.category, event.event.action, event.event.outcome) == WINDOWS_ACTIONS[code]
    assert event.metadata["provider"] == "windows_wef"
    assert event.metadata["source_channel"] == "Security"
    assert event.metadata["identity"]["domain"] == "SYNTHETIC"
    assert event.raw_event == raw


@pytest.mark.parametrize(
    ("channel", "code", "category"),
    [
        ("Microsoft-Windows-PowerShell/Operational", 4104, "process"),
        ("Microsoft-Windows-Sysmon/Operational", 1, "process"),
        ("Microsoft-Windows-Sysmon/Operational", 3, "network"),
        ("Microsoft-Windows-Sysmon/Operational", 22, "network"),
        ("System", 7036, "system"),
        ("Application", 1000, "application"),
    ],
)
def test_all_collector_channels_preserve_provenance(channel, code, category) -> None:
    raw = next(
        row
        for row in demo_fixtures()["windows"]
        if row["Event"]["System"]["EventID"] == code
        and row["Event"]["System"]["Channel"] == channel
    )
    event = normalize_provider(raw, PROFILE, "windows_wef", "collector")
    assert event.event.category == category
    assert event.metadata["source_channel"] == channel
    assert event.metadata["source_host"] == "demo-dc-01"


@pytest.mark.regression
def test_real_windows_subject_user_and_powershell_sid_are_not_lost() -> None:
    raw = deepcopy(
        next(row for row in demo_fixtures()["windows"] if row["Event"]["System"]["EventID"] == 4688)
    )
    del raw["Event"]["EventData"]["TargetUserName"]
    del raw["Event"]["EventData"]["User"]
    raw["Event"]["EventData"]["NewProcessId"] = "0x1a"
    event = normalize_provider(raw, PROFILE, "windows_wef", "test")
    assert event.user.name == "operator01"
    assert event.process.pid == 26
    raw["Event"]["System"]["EventID"] = 4104
    raw["Event"]["System"]["Security"] = {"UserID": "S-1-5-21-1000"}
    raw["Event"]["EventData"] = {"ScriptBlockText": "Write-Output 'synthetic'"}
    assert parse_windows(raw).user.name == "S-1-5-21-1000"


@pytest.mark.regression
def test_system_event_one_is_not_misclassified_as_sysmon_process() -> None:
    row = deepcopy(demo_fixtures()["windows"][-2])
    row["Event"]["System"]["EventID"] = 1
    event = parse_windows(row)
    assert event.event.category == "system"
    assert event.event.action == "windows_event"


@pytest.mark.security
@pytest.mark.parametrize(
    "text",
    [
        "<!DOCTYPE event [<!ENTITY x 'expanded'>]><Event>&x;</Event>",
        "<!ENTITY x SYSTEM 'file:///etc/passwd'><Event/>",
        "<Event>",
        "<Other/>",
        "x" * 65_537,
    ],
)
def test_windows_xml_rejects_entities_malformed_and_oversized(text) -> None:
    with pytest.raises(DomainError):
        windows_xml(text)


def test_windows_native_xml_transport_preserves_named_fields() -> None:
    text = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
        "<EventID>4625</EventID><EventRecordID>72</EventRecordID><Channel>Security</Channel>"
        '<Computer>demo-dc-01</Computer><TimeCreated SystemTime="2026-01-15T10:00:00Z"/>'
        '</System><EventData><Data Name="TargetUserName">analyst01</Data>'
        '<Data Name="IpAddress">192.0.2.55</Data></EventData></Event>'
    )
    raw = windows_xml(text)
    assert raw["raw_xml"] == text
    event = parse_windows(raw)
    assert event.event.action == "login"
    assert event.event.outcome == "failure"
    assert event.source.ip == "192.0.2.55"
    assert event.metadata["windows_record_id"] == "72"


def test_wazuh_adapter_is_offline_and_preserves_raw_evidence() -> None:
    fixture = demo_fixtures()["wazuh"][0]
    event = parse_content(json.dumps(fixture), "wazuh")[0]
    assert event.metadata["provider"] == "wazuh"
    assert event.raw_event == fixture
    assert event.event.action == "login"
    assert event.source.ip == "192.0.2.55"
    assert parse_content(json.dumps(fixture), "json")[0] == event


class APITransport:
    def __init__(self, client):
        self.client = client
        self.outage = False

    def request(self, method, url, **kwargs):
        if self.outage:
            raise IntegrationError("network_error")
        response = self.client.request(
            method, "/api/ingest/windows", headers=kwargs["headers"], content=kwargs["body"]
        )
        return HTTPResult(response.status_code, {}, response.content)


@pytest.mark.end_to_end
@pytest.mark.notifications
def test_collector_spool_authenticated_ingestion_detection_outbox_and_recovery(
    client, tmp_path: Path, monkeypatch
) -> None:
    platform = client.app.state.platform
    runtime = platform.integrations
    connector = runtime.management.save_connector(
        ConnectorConfig(
            name="Offline WEC",
            type="windows_wef",
            mode="demo",
            enabled=True,
        ),
        "test",
    )
    token = "synthetic-collector-token-" + "a" * 32
    monkeypatch.setenv("SENTINEL_INTEGRATION_COLLECTOR", token)
    runtime.management.save_credential(
        CredentialConfig(
            name="WEC collector",
            token_ref="SENTINEL_INTEGRATION_COLLECTOR",
            scopes=["windows:ingest"],
            connector_id=connector["id"],
        ),
        "test",
    )
    target = runtime.management.save_destination(
        DestinationConfig(
            name="Mock notification",
            type="power_automate",
            mode="demo",
            enabled=True,
        ),
        "test",
    )
    runtime.management.save_policy(
        NotificationPolicy(
            name="Windows demo",
            destinations=[target["id"]],
            providers=["windows_wef"],
        ),
        "test",
    )
    transport = APITransport(client)
    transport.outage = True
    path = tmp_path / "spool.sqlite3"
    collector = Collector(
        path,
        connector["id"],
        "https://local.invalid",
        token,
        FixtureEventSource(demo_fixtures()["windows"]),
        transport,
    )
    report = collector.cycle()
    assert report["pending"] == 36
    assert platform.alerts({}, 0, 100)["total"] == 0
    collector.close()
    transport.outage = False
    restored = Collector(
        path,
        connector["id"],
        "https://local.invalid",
        token,
        FixtureEventSource(demo_fixtures()["windows"]),
        transport,
    )
    with restored.db:
        restored.db.execute("UPDATE spool SET due=0")
    assert restored.cycle()["pending"] == 0
    assert (
        Counter(alert["rule_id"] for alert in platform.alerts({}, 0, 100)["items"])
        == demo_fixtures()["expected"]["windows_wef"]["alerts"]
    )
    while runtime.queue.process_one():
        pass
    assert len(runtime.demo.receipts) == 7
    assert restored.cycle()["pending"] == 0
    assert runtime.management.deliveries()["total"] == 7
    restored.close()


@pytest.mark.security
def test_collector_retains_rejected_events_and_does_not_advance_past_full_spool(
    tmp_path: Path,
) -> None:
    class Reject:
        def request(self, *_args, **_kwargs):
            return HTTPResult(401, {}, encoded_json({"error": "unauthorized"}))

    collector = Collector(
        tmp_path / "spool.sqlite3",
        "source",
        "https://local.invalid",
        "synthetic-collector-only-token-12345",
        FixtureEventSource(demo_fixtures()["windows"]),
        Reject(),
        max_spool=2,
        batch_size=2,
    )
    try:
        report = collector.cycle()
        assert report == {"pending": 2, "blocked": 2, "status": "pending"}
        with pytest.raises(DomainError, match="spool is full"):
            collector.cycle()
        assert collector.db.execute("SELECT bookmark FROM checkpoints").fetchone()[0] == "2"
        collector.retry_blocked()
        assert collector.db.execute("SELECT sum(blocked) FROM spool").fetchone()[0] == 0
    finally:
        collector.close()


def test_non_windows_live_collector_is_honestly_unavailable(monkeypatch) -> None:
    import app.integrations.windows_native as module

    monkeypatch.setattr(module.sys, "platform", "darwin")
    with pytest.raises(DomainError, match="requires Windows"):
        WindowsEventSource()


@pytest.mark.regression
def test_collector_invalid_ack_never_discards_the_durable_batch(tmp_path: Path) -> None:
    class InvalidAck:
        def request(self, *_args, **_kwargs):
            return HTTPResult(
                202, {}, encoded_json({"events_stored": True, "duplicates_ignored": 0})
            )

    collector = Collector(
        tmp_path / "spool.sqlite3",
        "source",
        "https://local.invalid",
        "synthetic-collector-only-token-12345",
        FixtureEventSource(demo_fixtures()["windows"][:1]),
        InvalidAck(),
    )
    try:
        assert collector.cycle()["blocked"] == 1
        assert collector.db.execute("SELECT error FROM spool").fetchone()[0] == "invalid_response"
    finally:
        collector.close()


@pytest.mark.regression
def test_collector_losing_lease_never_releases_another_owners_lease(tmp_path: Path) -> None:
    class Steal:
        def read(self, _channel, _bookmark, _limit):
            with collector.db:
                collector.db.execute("UPDATE lease SET owner='other-owner'")
            return []

    collector = Collector(
        tmp_path / "spool.sqlite3",
        "source",
        "https://local.invalid",
        "synthetic-collector-only-token-12345",
        Steal(),
        None,
    )
    try:
        with pytest.raises(DomainError, match="ownership expired"):
            collector.cycle()
        assert collector.db.execute("SELECT owner FROM lease").fetchone()[0] == "other-owner"
        assert collector.db.execute("SELECT count(*) FROM checkpoints").fetchone()[0] == 0
    finally:
        collector.close()


def test_native_event_api_harness_seeks_after_bookmark_and_closes_handles(monkeypatch) -> None:
    import app.integrations.windows_native as module

    calls = []

    class API:
        remaining = 1

        def EvtQuery(self, _session, channel, query, flags):
            calls.append(("query", channel, query, flags))
            return 10

        def EvtCreateBookmark(self, bookmark):
            calls.append(("bookmark", bookmark))
            return 20

        def EvtSeek(self, *args):
            calls.append(("seek", *args))
            return True

        def EvtNext(self, _query, _count, handles, _timeout, _flags, returned):
            if not self.remaining:
                return False
            self.remaining -= 1
            handles[0] = 30
            returned._obj.value = 1
            return True

        def EvtUpdateBookmark(self, *args):
            calls.append(("update", *args))
            return True

        def EvtClose(self, handle):
            calls.append(("close", handle))
            return True

    reader = module.NativeEventLog.__new__(module.NativeEventLog)
    reader.api = API()
    monkeypatch.setattr(module, "last_error", lambda: 259)
    monkeypatch.setattr(
        reader, "render", lambda handle, flag: "event-xml" if flag == 1 else "next-bookmark"
    )
    assert reader.read("ForwardedEvents", "old-bookmark", 2) == [("event-xml", "next-bookmark")]
    assert ("seek", 10, 1, 20, 0, 4 | 0x10000) in calls
    assert ("update", 20, 30) in calls
    assert [item for item in calls if item[0] == "close"] == [
        ("close", 30),
        ("close", 20),
        ("close", 10),
    ]
