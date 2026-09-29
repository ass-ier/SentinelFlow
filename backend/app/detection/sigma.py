import fnmatch
import hashlib
import re
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic import ValidationError

from app.core.config import ROOT
from app.core.errors import DomainError
from app.core.safe import json_loads, yaml_loads
from app.detection.rules import Condition, Provenance, Rule

FIELD_MAP = {
    "Image": "process.executable",
    "ParentImage": "process.parent.executable",
    "CommandLine": "process.command_line",
    "User": "user.name",
    "Computer": "host.name",
    "TargetFilename": "file.path",
    "DestinationIp": "destination.ip",
    "DestinationPort": "destination.port",
    "SourceIp": "source.ip",
    "SourcePort": "source.port",
    "QueryName": "dns.query",
    "EventID": "metadata.windows_event_id",
}
MODIFIERS = {"contains": "contains", "startswith": "starts_with", "endswith": "ends_with"}
METADATA = {
    "title",
    "id",
    "description",
    "status",
    "logsource",
    "detection",
    "level",
    "tags",
    "author",
    "date",
    "modified",
    "references",
    "falsepositives",
    "license",
    "related",
    "regression_tests_path",
}
TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z_][A-Za-z0-9_*]*|1)\s*")


def unsupported(message: str) -> DomainError:
    return DomainError(f"Unsupported Sigma feature: {message}", 422, "unsupported_sigma")


def _url(value: str | None) -> str | None:
    if value and (urlparse(value).scheme not in {"https", "http"} or not urlparse(value).netloc):
        raise DomainError("Provenance URLs must be absolute HTTP(S) URLs")
    return value


def _predicate(field: str, operator: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, str | int | float | bool):
        raise unsupported("null, object, and nested list field values")
    if isinstance(value, str) and ("*" in value or "?" in value):
        if "\\*" in value or "\\?" in value:
            raise unsupported("escaped wildcard values; use explicit non-wildcard strings")
        expression = re.escape(value).replace(r"\*", ".*").replace(r"\?", ".")
        if operator not in {"contains", "ends_with"}:
            expression = "^" + expression
        if operator not in {"contains", "starts_with"}:
            expression += "$"
        return {"field": field, "operator": "regex", "value": expression}
    return {"field": field, "operator": operator, "value": value}


def _selection(value: Any) -> dict[str, Any]:
    if isinstance(value, list):
        if not value or any(not isinstance(item, dict) for item in value):
            raise unsupported("keyword selections; only lists of field maps are supported")
        return {"any": [_selection(item) for item in value]}
    if not isinstance(value, dict) or not value:
        raise unsupported("a selection must be a nonempty field map or list of maps")
    predicates = []
    for key, wanted in value.items():
        parts = key.split("|")
        source_field, modifiers = parts[0], parts[1:]
        if source_field not in FIELD_MAP:
            raise unsupported(f"field {source_field}")
        unknown = set(modifiers) - set(MODIFIERS) - {"all"}
        if unknown or len(modifiers) != len(set(modifiers)):
            raise unsupported(f"modifier on {source_field}: {', '.join(modifiers)}")
        string_modifiers = [modifier for modifier in modifiers if modifier != "all"]
        if len(string_modifiers) > 1:
            raise unsupported("multiple string modifiers")
        operator = MODIFIERS[string_modifiers[0]] if string_modifiers else "equals"
        field = FIELD_MAP[source_field]
        if isinstance(wanted, list):
            if not wanted:
                raise unsupported("empty value lists")
            predicates.append(
                {
                    "all" if "all" in modifiers else "any": [
                        _predicate(field, operator, item) for item in wanted
                    ]
                }
            )
        else:
            if "all" in modifiers:
                raise unsupported("all modifier without a list")
            predicates.append(_predicate(field, operator, wanted))
    return {"all": predicates}


class ConditionParser:
    def __init__(self, text: str, selections: dict[str, dict[str, Any]]) -> None:
        if not text or len(text) > 2048:
            raise unsupported("condition is empty or exceeds 2048 characters")
        self.tokens = []
        position = 0
        while position < len(text):
            match = TOKEN.match(text, position)
            if match is None:
                raise unsupported(f"condition syntax near character {position}")
            self.tokens.append(match.group(1))
            position = match.end()
        if len(self.tokens) > 256:
            raise unsupported("condition contains too many tokens")
        self.index = 0
        self.selections = selections

    def peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise unsupported("incomplete condition")
        self.index += 1
        return token

    def parse(self) -> dict[str, Any]:
        result = self.parse_or(0)
        if self.peek() is not None:
            raise unsupported(f"unexpected condition token {self.peek()}")
        return result

    def parse_or(self, depth: int) -> dict[str, Any]:
        values = [self.parse_and(depth)]
        while self.peek() == "or":
            self.take()
            values.append(self.parse_and(depth))
        return {"any": values} if len(values) > 1 else values[0]

    def parse_and(self, depth: int) -> dict[str, Any]:
        values = [self.parse_atom(depth)]
        while self.peek() == "and":
            self.take()
            values.append(self.parse_atom(depth))
        return {"all": values} if len(values) > 1 else values[0]

    def parse_atom(self, depth: int) -> dict[str, Any]:
        if depth > 8:
            raise unsupported("condition nesting exceeds eight levels")
        term = self.take()
        if term == "not":
            return {"not": self.parse_atom(depth + 1)}
        if term == "(":
            result = self.parse_or(depth + 1)
            if self.take() != ")":
                raise unsupported("unbalanced parentheses")
            return result
        if term in {"all", "1"}:
            if self.take() != "of":
                raise unsupported("quantifier must be 'all of' or '1 of'")
            pattern = self.take()
            names = [
                name
                for name in self.selections
                if pattern == "them" or fnmatch.fnmatchcase(name, pattern)
            ]
            if not names:
                raise unsupported(f"selector pattern {pattern} matched no selections")
            return {"all" if term == "all" else "any": [self.selections[name] for name in names]}
        if term not in self.selections:
            raise unsupported(f"unknown selection {term}")
        return self.selections[term]


def _official_source(text: str) -> dict[str, Any]:
    path = ROOT / "test-data" / "sigma" / "provenance.json"
    if not path.exists():
        return {}
    for item in json_loads(path.read_text()):
        if not isinstance(item, dict):
            raise DomainError("Invalid bundled Sigma provenance", 500, "sigma_provenance")
        if item["sha256"] == hashlib.sha256(text.encode()).hexdigest():
            return item
    return {}


def compile_sigma(
    text: str,
    *,
    source_url: str | None = None,
    license_name: str | None = None,
    license_url: str | None = None,
) -> Rule:
    document = yaml_loads(text)
    unknown = set(document) - METADATA
    if unknown:
        raise unsupported("top-level fields: " + ", ".join(sorted(unknown)))
    required = {"title", "id", "description", "status", "logsource", "detection", "level", "tags"}
    missing = required - set(document)
    if missing:
        raise DomainError("Sigma metadata missing: " + ", ".join(sorted(missing)))
    try:
        uuid.UUID(str(document["id"]))
    except ValueError as exc:
        raise DomainError("Sigma id must be a UUID") from exc
    if not isinstance(document["status"], str) or document["status"] not in {
        "stable",
        "test",
        "experimental",
        "deprecated",
    }:
        raise unsupported("rule status")
    logsource = document["logsource"]
    if not isinstance(logsource, dict) or set(logsource) != {"product", "category"}:
        raise unsupported(
            "logsource requires exactly product and category; services are not supported"
        )
    if any(not isinstance(value, str) for value in logsource.values()):
        raise unsupported("logsource values must be strings")
    if logsource["product"] not in {"windows", "linux"}:
        raise unsupported("logsource product (supported: windows, linux)")
    category_map = {
        "process_creation": ("process", "process_created"),
        "network_connection": ("network", "connection"),
        "dns_query": ("network", "dns_query"),
    }
    if logsource["category"] not in category_map:
        raise unsupported("logsource category")
    category, action = category_map[logsource["category"]]
    detection = document["detection"]
    if not isinstance(detection, dict) or not isinstance(detection.get("condition"), str):
        raise unsupported("detection requires one string condition")
    if "timeframe" in detection:
        raise unsupported("timeframe/correlation")
    raw_selections = {key: value for key, value in detection.items() if key != "condition"}
    if not 1 <= len(raw_selections) <= 64:
        raise unsupported("between 1 and 64 selections are required")
    if any(
        not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
        or key in {"and", "or", "not", "all", "of", "them"}
        for key in raw_selections
    ):
        raise unsupported("selection names")
    selections = {name: _selection(value) for name, value in raw_selections.items()}
    expression = ConditionParser(detection["condition"], selections).parse()
    tags = document["tags"]
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise DomainError("Sigma tags must be a list of strings")
    techniques = [
        tag.removeprefix("attack.").upper()
        for tag in tags
        if re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", tag)
    ]
    official = _official_source(text)
    source_url = official.get("source_url", source_url)
    license_name = official.get("license", license_name or document.get("license"))
    license_url = official.get("license_url", license_url)
    try:
        rule = Rule(
            id=f"SIGMA-{document['id']}",
            name=document["title"],
            description=document["description"],
            severity=document["level"],
            conditions=Condition.model_validate(
                {
                    "all": [
                        {
                            "field": "metadata.product",
                            "operator": "equals",
                            "value": logsource["product"],
                        },
                        {"field": "event.category", "operator": "equals", "value": category},
                        {"field": "event.action", "operator": "equals", "value": action},
                        expression,
                    ]
                }
            ),
            suppression_seconds=0,
            mitre_attack=techniques,
            false_positives=document.get("falsepositives", []),
            provenance=Provenance(
                kind="sigma",
                author=document.get("author"),
                source_url=_url(source_url),
                license=license_name,
                license_url=_url(license_url),
                upstream_id=document["id"],
                status=document["status"],
                logsource=logsource,
                tags=tags,
                references=document.get("references", []),
                original_yaml=text,
            ),
        )
    except ValidationError as exc:
        first = exc.errors(include_input=False)[0]
        raise DomainError(f"Invalid Sigma value: {first['msg']}") from exc
    return rule


def sigma_samples(directory: Path = ROOT / "test-data" / "sigma") -> list[dict[str, Any]]:
    manifest = directory / "provenance.json"
    if not manifest.exists():
        raise DomainError("Bundled Sigma provenance is missing", 503, "missing_sigma")
    items = json_loads(manifest.read_text())
    results = []
    for item in items:
        text = (directory / item["path"]).read_text()
        if hashlib.sha256(text.encode()).hexdigest() != item["sha256"]:
            raise DomainError(
                "Bundled Sigma rule differs from pinned provenance", 409, "sigma_changed"
            )
        rule = compile_sigma(text)
        results.append(
            {
                **item,
                "id": rule.id,
                "name": rule.name,
                "author": rule.provenance.author,
                "yaml": text,
                "expected_alerts": 1,
                "negative_dataset_id": "sigma-benign",
            }
        )
    return results
