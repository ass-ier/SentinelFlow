import json
from copy import deepcopy

import pytest
import yaml
from fastapi.testclient import TestClient

from app.core.config import ROOT
from app.core.errors import DomainError
from app.detection.engine import evaluate
from app.detection.sigma import compile_sigma, sigma_samples
from app.services.datasets import DatasetStore

pytestmark = [pytest.mark.sigma, pytest.mark.integration]


@pytest.mark.parametrize("sample", sigma_samples(), ids=lambda sample: sample["id"])
def test_unchanged_public_sigma_end_to_end(
    sample: dict, datasets: DatasetStore, client: TestClient
) -> None:
    rule = compile_sigma(sample["yaml"])
    assert rule.provenance.author == sample["author"]
    assert rule.provenance.license == "DRL-1.1"
    assert rule.provenance.source_url == sample["source_url"]
    assert rule.provenance.original_yaml == sample["yaml"]
    assert "date:" in rule.provenance.original_yaml
    positive, _ = evaluate(datasets.events(sample["dataset_id"]), [rule])
    negative, _ = evaluate(datasets.events(sample["negative_dataset_id"]), [rule])
    assert len(positive) == 1 and negative == []
    assert positive[0].rule.severity == rule.severity
    assert positive[0].to_dict()["provenance"]["author"] == sample["author"]
    compiled = client.post("/sigma/compile", json={"yaml": sample["yaml"]})
    assert compiled.status_code == 200
    imported = client.post("/sigma/import", json={"yaml": sample["yaml"], "enabled": True})
    assert imported.status_code == 201
    assert imported.json()["id"] == rule.id
    assert client.post("/sigma/import", json={"yaml": sample["yaml"]}).status_code == 409
    tested = client.post(
        "/sigma/test",
        json={
            "yaml": sample["yaml"],
            "dataset_id": sample["dataset_id"],
            "expected_alerts": 1,
        },
    )
    assert tested.json()["status"] == "passed"
    content = json.dumps(
        [event.model_dump(mode="json") for event in datasets.events(sample["dataset_id"])]
    )
    assert client.post("/events", json={"format": "json", "content": content}).status_code == 201
    hit = client.get("/alerts", params={"rule_id": rule.id}).json()["items"][0]
    detail = client.get("/alerts/" + hit["id"]).json()
    assert detail["provenance"]["author"] == sample["author"]
    assert detail["rule_snapshot"]["provenance"]["original_yaml"] == sample["yaml"]
    assert detail["event_count"] == len(detail["evidence"]) == 1


@pytest.mark.regression
def test_upstream_encoding_and_full_parent_image_filters(datasets: DatasetStore) -> None:
    sample = next(item for item in sigma_samples() if item["dataset_id"] == "sigma-encoded")
    rule = compile_sigma(sample["yaml"])
    assert evaluate(datasets.events("sigma-encoded"), [rule])[0]
    assert evaluate(datasets.events("sigma-benign"), [rule])[0] == []
    assert evaluate(datasets.events("sigma-azure"), [rule])[0] == []
    wrong_parent = datasets.events("sigma-azure")[0].model_copy(deep=True)
    wrong_parent.process.parent.executable = "C:\\Windows\\explorer.exe"
    assert len(evaluate([wrong_parent], [rule])[0]) == 1


def base_rule() -> dict:
    return {
        "title": "Subset contract",
        "id": "a1000000-0000-4000-8000-000000000001",
        "description": "Local translator contract",
        "status": "test",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"selection": {"CommandLine|contains": "IEX"}, "condition": "selection"},
        "level": "medium",
        "tags": ["attack.t1059.001"],
        "author": "Synthetic fixture author",
    }


@pytest.mark.parametrize(
    "condition",
    [
        "selection",
        "(selection)",
        "selection or other",
        "selection and not other",
        "1 of selection*",
        "all of selection*",
        "1 of them",
        "(selection or other) and not blocked",
    ],
)
def test_supported_condition_grammar(condition: str, datasets: DatasetStore) -> None:
    definition = base_rule()
    definition["detection"].update(
        {
            "other": {"CommandLine|contains": "nonmatching token"},
            "blocked": {"CommandLine|contains": "not present"},
            "condition": condition,
        }
    )
    rule = compile_sigma(yaml.safe_dump(definition))
    assert len(evaluate(datasets.events("sigma-download"), [rule])[0]) == 1


def test_selection_list_and_all_modifier(datasets: DatasetStore) -> None:
    definition = base_rule()
    definition["detection"]["selection"] = [
        {"CommandLine|contains|all": ["IEX", ".DownloadString("]},
        {"CommandLine|startswith": "not present"},
    ]
    rule = compile_sigma(yaml.safe_dump(definition))
    assert len(evaluate(datasets.events("sigma-download"), [rule])[0]) == 1
    assert evaluate(datasets.events("sigma-encoded"), [rule])[0] == []


def test_supported_value_wildcards_and_logsource_are_not_dropped(datasets: DatasetStore) -> None:
    definition = base_rule()
    definition["detection"]["selection"] = {"Image": "*powershell.exe"}
    rule = compile_sigma(yaml.safe_dump(definition))
    assert len(evaluate(datasets.events("sigma-encoded"), [rule])[0]) == 1
    linux = datasets.events("sigma-encoded")[0].model_copy(deep=True)
    linux.metadata["product"] = "linux"
    assert evaluate([linux], [rule])[0] == []
    absent = datasets.events("sigma-encoded")[0].model_copy(deep=True)
    absent.process.executable = None
    assert evaluate([absent], [rule])[0] == []


@pytest.mark.parametrize(
    "change",
    [
        {"condition": "2 of selection*"},
        {"condition": "selection | count() > 3"},
        {"condition": "unknown_selection"},
        {"condition": "all of absent*"},
        {"condition": ["selection", "selection"]},
        {"selection": {"CommandLine|base64": "IEX"}},
        {"selection": {"CommandLine|re": "IEX.*"}},
        {"selection": {"CommandLine|contains|startswith": "IEX"}},
        {"selection": {"UnknownField": "IEX"}},
        {"selection": ["keyword"]},
        {"selection": {"CommandLine": None}},
        {"selection": {"CommandLine": r"\*escaped"}},
        {"timeframe": "5m"},
    ],
)
def test_unsupported_sigma_detection_is_explicit(change: dict) -> None:
    definition = base_rule()
    definition["detection"].update(change)
    with pytest.raises(DomainError, match="Unsupported Sigma"):
        compile_sigma(yaml.safe_dump(definition))


@pytest.mark.parametrize(
    "change",
    [
        {"correlation": {"type": "event_count"}},
        {"logsource": {"product": "windows", "service": "sysmon", "category": "process_creation"}},
        {"logsource": {"product": "unknown", "category": "process_creation"}},
        {"logsource": {"product": [], "category": "process_creation"}},
        {"logsource": {"product": "windows", "category": "unknown"}},
        {"status": "unsupported"},
    ],
)
def test_unsupported_sigma_scope_is_explicit(change: dict) -> None:
    definition = deepcopy(base_rule())
    definition.update(change)
    with pytest.raises(DomainError):
        compile_sigma(yaml.safe_dump(definition))


def test_import_defaults_disabled_and_unspecified_expectation_is_not_pass(
    client: TestClient,
) -> None:
    sample = sigma_samples()[0]
    imported = client.post("/sigma/import", json={"yaml": sample["yaml"]}).json()
    assert imported["enabled"] is False
    observed = client.post(
        "/rules/" + imported["id"] + "/test",
        json={
            "dataset_id": sample["dataset_id"],
        },
    ).json()
    assert observed["status"] == "observed"
    assert observed["results"][0]["expected"] is None
    failed = client.post(
        "/sigma/test",
        json={
            "yaml": sample["yaml"],
            "dataset_id": sample["dataset_id"],
            "expected_alerts": 0,
        },
    ).json()
    assert failed["status"] == "failed"
    assert client.get("/alerts").json()["total"] == 0


def test_original_license_and_rule_bytes_are_saved() -> None:
    license_text = (ROOT / "test-data/sigma/LICENSE.Detection.Rules.md").read_text()
    assert "messages based on matches" in license_text
    assert len(sigma_samples()) == 2
