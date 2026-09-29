from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, ValidationError, field_validator, model_validator

from app.core.errors import DomainError
from app.core.safe import compile_pattern, regex_search, yaml_loads
from app.schemas.events import Severity, StrictModel, get_field

Operator = Literal[
    "equals",
    "not_equals",
    "contains",
    "starts_with",
    "ends_with",
    "regex",
    "greater_than",
    "less_than",
    "in",
]
FIELDS = {
    "event.id",
    "event.timestamp",
    "event.source",
    "event.category",
    "event.type",
    "event.action",
    "event.outcome",
    "event.severity",
    "host.name",
    "host.ip",
    "user.name",
    "source.ip",
    "source.port",
    "destination.ip",
    "destination.port",
    "process.name",
    "process.command_line",
    "process.executable",
    "process.pid",
    "process.parent.name",
    "process.parent.executable",
    "process.parent.pid",
    "network.protocol",
    "dns.query",
    "file.path",
}
MITRE_NAMES = {
    "T1059": "Command and Scripting Interpreter",
    "T1110": "Brute Force",
    "T1098": "Account Manipulation",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1071.004": "DNS",
    "T1071.001": "Web Protocols",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1204.002": "Malicious File",
}


def validate_field(path: str) -> str:
    if path in FIELDS:
        return path
    if (
        path.startswith("metadata.")
        and len(path) <= 160
        and len(path.split(".")) <= 5
        and all(part.replace("_", "").isalnum() for part in path.split("."))
    ):
        return path
    raise ValueError(f"Unsupported field: {path}")


class Condition(StrictModel):
    field: str | None = None
    operator: Operator | None = None
    value: Any = None
    case_sensitive: bool = False
    all: list["Condition"] | None = Field(default=None, min_length=1, max_length=64)
    any: list["Condition"] | None = Field(default=None, min_length=1, max_length=64)
    not_: "Condition | None" = Field(default=None, alias="not")

    @model_validator(mode="after")
    def valid_expression(self) -> "Condition":
        shapes = sum(
            (
                self.field is not None,
                self.all is not None,
                self.any is not None,
                self.not_ is not None,
            )
        )
        if shapes != 1:
            raise ValueError("Condition must contain exactly one of field/all/any/not")
        if self.field is None:
            if self.operator is not None or self.value is not None or self.case_sensitive:
                raise ValueError("Boolean conditions cannot contain leaf predicate attributes")
            return self
        validate_field(self.field)
        if self.operator is None or self.value is None:
            raise ValueError("Leaf conditions require an operator and a non-null value")
        if self.operator == "in":
            if not isinstance(self.value, list) or not 1 <= len(self.value) <= 100:
                raise ValueError("in requires a nonempty list with at most 100 values")
            if any(not isinstance(item, str | int | float | bool) for item in self.value):
                raise ValueError("in accepts only scalar values")
        elif self.operator in ("greater_than", "less_than"):
            if isinstance(self.value, bool) or not isinstance(self.value, int | float):
                raise ValueError("Numeric comparisons require a number")
        elif self.operator in ("contains", "starts_with", "ends_with", "regex"):
            if not isinstance(self.value, str):
                raise ValueError("String predicates require text")
            if self.operator == "regex":
                compile_pattern(self.value)
                if self.case_sensitive:
                    raise ValueError("Regex matching is case-insensitive in this rule version")
        elif not isinstance(self.value, str | int | float | bool):
            raise ValueError("Equality requires a scalar value")
        return self


class Threshold(StrictModel):
    count: int = Field(default=1, ge=1, le=10_000)
    window_seconds: int = Field(default=300, ge=1, le=86_400)


class Branch(StrictModel):
    name: str = Field(pattern=r"^[a-z0-9_-]+$", min_length=1, max_length=64)
    conditions: Condition
    threshold: Threshold = Field(default_factory=Threshold)
    group_by: list[str] = Field(default_factory=list, max_length=4)

    @field_validator("group_by")
    @classmethod
    def valid_groups(cls, value: list[str]) -> list[str]:
        return [validate_field(field) for field in value]


class Provenance(StrictModel):
    kind: Literal["bundled", "custom", "sigma"] = "custom"
    author: str | None = Field(default=None, max_length=1024)
    source_url: str | None = Field(default=None, max_length=2048)
    license: str | None = Field(default=None, max_length=128)
    license_url: str | None = Field(default=None, max_length=2048)
    upstream_id: str | None = Field(default=None, max_length=128)
    status: str | None = Field(default=None, max_length=100)
    logsource: dict[str, str] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list, max_length=100)
    references: list[str] = Field(default_factory=list, max_length=100)
    original_yaml: str | None = Field(default=None, max_length=65_536)


class Rule(StrictModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_.-]+$", min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1, max_length=4096)
    severity: Severity
    enabled: bool = True
    conditions: Condition
    threshold: Threshold = Field(default_factory=Threshold)
    group_by: list[str] = Field(default_factory=list, max_length=4)
    suppression_seconds: int = Field(default=300, ge=0, le=86_400)
    branches: list[Branch] = Field(default_factory=list, max_length=8)
    mitre_attack: list[str] = Field(default_factory=list, max_length=20)
    false_positives: list[str] = Field(default_factory=list, max_length=20)
    provenance: Provenance = Field(default_factory=Provenance)

    @field_validator("conditions", mode="before")
    @classmethod
    def implicit_and(cls, value: Any) -> Any:
        return {"all": value} if isinstance(value, list) else value

    @field_validator("group_by")
    @classmethod
    def valid_groups(cls, value: list[str]) -> list[str]:
        return [validate_field(field) for field in value]

    @field_validator("mitre_attack")
    @classmethod
    def valid_techniques(cls, value: list[str]) -> list[str]:
        import re

        if any(not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique) for technique in value):
            raise ValueError("MITRE technique IDs must use T0000 or T0000.000 form")
        return value

    @model_validator(mode="after")
    def unique_branches(self) -> "Rule":
        if len({branch.name for branch in self.branches}) != len(self.branches):
            raise ValueError("Branch names must be unique")
        return self


@lru_cache(maxsize=256)
def cached_pattern(pattern: str) -> Any:
    return compile_pattern(pattern)


def matches(condition: Condition, data: dict[str, Any]) -> bool:
    if condition.all is not None:
        return all(matches(child, data) for child in condition.all)
    if condition.any is not None:
        return any(matches(child, data) for child in condition.any)
    if condition.not_ is not None:
        return not matches(condition.not_, data)
    if condition.field is None:
        raise DomainError("Invalid compiled condition", 500, "rule_error")
    actual = get_field(data, condition.field)
    if actual is None:
        return False
    wanted = condition.value
    if condition.operator == "regex":
        return isinstance(actual, str) and regex_search(cached_pattern(wanted), actual)
    if not condition.case_sensitive:
        if isinstance(actual, str):
            actual = actual.casefold()
        if isinstance(wanted, str):
            wanted = wanted.casefold()
        elif isinstance(wanted, list):
            wanted = [item.casefold() if isinstance(item, str) else item for item in wanted]
    operator = condition.operator
    if operator == "equals":
        return bool(type(actual) is type(wanted) and actual == wanted)
    if operator == "not_equals":
        return bool(type(actual) is not type(wanted) or actual != wanted)
    if operator == "in":
        return any(type(actual) is type(item) and actual == item for item in wanted)
    if operator in ("greater_than", "less_than"):
        if isinstance(actual, bool) or not isinstance(actual, int | float):
            return False
        return bool(actual > wanted if operator == "greater_than" else actual < wanted)
    if not isinstance(actual, str) or not isinstance(wanted, str):
        return False
    if operator == "contains":
        return wanted in actual
    if operator == "starts_with":
        return actual.startswith(wanted)
    if operator == "ends_with":
        return actual.endswith(wanted)
    raise DomainError("Unsupported compiled operator", 500, "rule_error")


def load_rule(text: str) -> Rule:
    try:
        return Rule.model_validate(yaml_loads(text))
    except ValidationError as exc:
        first = exc.errors(include_input=False)[0]
        location = ".".join(str(part) for part in first["loc"])
        raise DomainError(f"Invalid rule {location}: {first['msg']}") from exc


def load_bundled_rules(directory: Path) -> list[Rule]:
    rules = [load_rule(path.read_text()) for path in sorted(directory.glob("*.yml"))]
    if not rules or len({rule.id for rule in rules}) != len(rules):
        raise DomainError("Rule directory is empty or contains duplicate IDs", 500, "rule_error")
    return rules
