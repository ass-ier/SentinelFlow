import json
from copy import deepcopy
from datetime import UTC, datetime

import pytest

from app.core.config import ROOT
from app.core.errors import DomainError
from app.parsers import parse_content
from app.parsers.windows import parse_windows
from app.schemas.events import NormalizedEvent
from app.services.datasets import DatasetStore

CONTRACTS = json.loads((ROOT / "test-data/expected-results/parser-contracts.json").read_text())
pytestmark = pytest.mark.parser


@pytest.mark.parametrize("contract", CONTRACTS, ids=lambda item: item["format"])
def test_exact_normalized_objects(contract: dict) -> None:
    content = (ROOT / "test-data" / contract["path"]).read_text()
    result = parse_content(content, contract["format"])
    assert [event.model_dump(mode="json") for event in result] == contract["expected"]


@pytest.mark.parametrize(
    "dataset_id", ["parser-json", "parser-csv", "parser-windows", "parser-syslog"]
)
def test_normalized_roundtrip_preserves_evidence(datasets: DatasetStore, dataset_id: str) -> None:
    for event in datasets.events(dataset_id):
        restored = parse_content(event.model_dump_json(), "json")[0]
        assert restored == event
        assert restored.event.timestamp.tzinfo == UTC


def test_id_without_explicit_id_is_stable(datasets: DatasetStore) -> None:
    raw = datasets.events("auth-success")[0].model_dump(mode="json")
    del raw["event"]["id"]
    del raw["raw_event"]
    first = parse_content(json.dumps(raw), "json")[0]
    second = parse_content(json.dumps(raw, indent=2), "json")[0]
    assert first.event.id == second.event.id


@pytest.mark.parametrize("value", ["not-an-ip", "999.0.0.1", "1.2.3.4; echo bad"])
def test_invalid_ip_is_controlled(datasets: DatasetStore, value: str) -> None:
    raw = datasets.events("auth-success")[0].model_dump(mode="json")
    raw["source"]["ip"] = value
    with pytest.raises(DomainError, match="source.ip"):
        parse_content(json.dumps(raw), "json")


def test_naive_timestamp_rejected(datasets: DatasetStore) -> None:
    raw = datasets.events("auth-success")[0].model_dump(mode="json")
    raw["event"]["timestamp"] = "2026-01-15T09:00:00"
    with pytest.raises(DomainError, match="timezone"):
        parse_content(json.dumps(raw), "json")


def test_negative_and_out_of_range_ports_rejected(datasets: DatasetStore) -> None:
    raw = datasets.events("auth-success")[0].model_dump(mode="json")
    for port in (-1, 65536):
        raw["destination"]["port"] = port
        with pytest.raises(DomainError, match="destination.port"):
            parse_content(json.dumps(raw), "json")


@pytest.mark.parametrize(
    ("text", "format"),
    [
        ("", "json"),
        ("[]", "json"),
        ("[1,2]", "json"),
        ("{broken", "jsonl"),
        ("a,a\n1,2", "csv"),
        ("timestamp,category\n2026", "csv"),
        ("not a syslog header", "syslog"),
        ("Jan 15 09:00:00 h app: unknown message", "syslog"),
        ('{"EventID":99999}', "windows"),
        ('{"EventID":1,"TimeCreated":"2026-01-15T09:00:00Z"}', "windows"),
    ],
)
def test_malformed_formats_return_domain_errors(text: str, format: str) -> None:
    with pytest.raises(DomainError):
        parse_content(text, format)


def test_syslog_year_is_explicit() -> None:
    text = (ROOT / "test-data/parsers/auth.log").read_text().splitlines()[0]
    result = parse_content(text, "syslog", syslog_year=2025)[0]
    assert result.event.timestamp == datetime(2025, 1, 15, 9, tzinfo=UTC)


def test_bom_and_blank_jsonl_lines(datasets: DatasetStore) -> None:
    raw = (ROOT / "test-data/authentication/normal_login.jsonl").read_text()
    assert parse_content("\ufeff\n" + raw + "\n", "jsonl") == datasets.events("auth-success")


def test_dns_enrichment_cannot_be_spoofed(datasets: DatasetStore) -> None:
    raw = datasets.events("dns-long-label")[0].model_dump(mode="json")
    raw["metadata"]["dns_metrics"] = {"max_label_length": 1}
    event = parse_content(json.dumps(raw), "json")[0]
    assert event.metadata["dns_metrics"]["max_label_length"] == 46


@pytest.mark.regression
def test_public_flat_adapter_preserves_intended_fields(datasets: DatasetStore) -> None:
    events = datasets.events("public-otrf-adapted")
    assert len(events) == 6
    assert [event.event.category for event in events].count("process") == 2
    assert [event.event.action for event in events].count("dns_query") == 3
    process = next(event for event in events if event.metadata["windows_event_id"] == 1)
    assert process.process.name == "SharpView.exe"
    assert process.process.executable == "C:\\Lab\\SharpView.exe"
    assert process.host.name == "public-lab-01"
    assert process.user.name == "PUBLICLAB\\operator01"
    assert process.process.command_line is None  # Arguments were explicitly removed by the adapter.
    assert process.raw_event["PublicAdapter"]["modified"] is True
    assert process.event.timestamp == datetime.fromisoformat("2020-10-29T08:23:20.534+00:00")
    network = next(event for event in events if event.event.action == "connection")
    assert network.source.ip.startswith("192.0.2.")
    assert network.destination.ip.startswith("192.0.2.")
    assert network.destination.port is not None


@pytest.mark.regression
@pytest.mark.parametrize("event_id", [True, 4688.1, None, [], {}])
def test_windows_event_id_is_not_coerced_from_ambiguous_values(event_id: object) -> None:
    with pytest.raises(DomainError):
        parse_windows({"EventID": event_id})


def test_normalized_model_forbids_unknown_top_fields(datasets: DatasetStore) -> None:
    row = deepcopy(datasets.events("auth-success")[0].model_dump(mode="json"))
    row["unknown"] = "not accepted silently"
    with pytest.raises(ValueError):
        NormalizedEvent.model_validate(row)
