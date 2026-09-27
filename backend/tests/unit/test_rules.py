import pytest
from pydantic import ValidationError

from app.core.errors import DomainError
from app.core.safe import compile_pattern, regex_search
from app.detection.rules import Condition, load_rule, matches


@pytest.mark.parametrize(
    ("operator", "actual", "wanted", "expected"),
    [
        ("equals", "PowerShell.EXE", "powershell.exe", True),
        ("not_equals", "powershell.exe", "cmd.exe", True),
        ("contains", "run EncodedCommand demo", "encodedcommand", True),
        ("starts_with", "C:\\Windows\\cmd.exe", "c:\\windows", True),
        ("ends_with", "C:\\Windows\\cmd.exe", "\\cmd.exe", True),
        ("regex", "IEX $example", r"\bIEX\b", True),
        ("greater_than", 11, 10, True),
        ("less_than", 9, 10, True),
        ("in", "CMD.EXE", ["cmd.exe", "pwsh.exe"], True),
        ("equals", "x", "y", False),
        ("not_equals", "x", "X", False),
        ("contains", "abc", "xyz", False),
        ("starts_with", "abc", "bc", False),
        ("ends_with", "abc", "ab", False),
        ("regex", "prefixiex", r"\biex\b", False),
        ("greater_than", 10, 10, False),
        ("less_than", "9", 10, False),
        ("in", 1, [True], False),
        ("equals", 1, True, False),
        ("greater_than", True, 0, False),
        ("equals", None, "anything", False),
        ("not_equals", None, "anything", False),
        ("contains", 123, "1", False),
    ],
)
def test_all_predicate_operators(
    operator: str, actual: object, wanted: object, expected: bool
) -> None:
    condition = Condition(field="metadata.example", operator=operator, value=wanted)
    assert matches(condition, {"metadata": {"example": actual}}) is expected


def test_nested_and_or_not_and_case_sensitive() -> None:
    expression = Condition.model_validate(
        {
            "all": [
                {
                    "any": [
                        {"field": "event.action", "operator": "equals", "value": "login"},
                        {"field": "event.action", "operator": "equals", "value": "logout"},
                    ]
                },
                {
                    "not": {
                        "field": "user.name",
                        "operator": "equals",
                        "value": "SERVICE",
                        "case_sensitive": True,
                    }
                },
            ]
        }
    )
    assert matches(expression, {"event": {"action": "LOGIN"}, "user": {"name": "service"}})
    assert not matches(expression, {"event": {"action": "login"}, "user": {"name": "SERVICE"}})


@pytest.mark.parametrize(
    "condition",
    [
        {"field": "raw_event.executable", "operator": "equals", "value": "x"},
        {"all": []},
        {
            "field": "event.action",
            "all": [{"field": "event.action", "operator": "equals", "value": "x"}],
        },
        {"field": "event.action", "operator": "in", "value": []},
        {"field": "event.action", "operator": "contains", "value": 1},
        {"field": "source.port", "operator": "greater_than", "value": True},
        {"field": "event.action", "operator": "equals", "value": None},
        {"field": "event.action", "operator": "execute", "value": "anything"},
        {"not": {"field": "event.action", "operator": "equals", "value": "x"}, "value": "extra"},
    ],
)
def test_invalid_conditions_are_rejected(condition: dict) -> None:
    with pytest.raises((ValidationError, DomainError)):
        Condition.model_validate(condition)


@pytest.mark.security
@pytest.mark.parametrize("pattern", [r"(a)\1", r"(?=secret)", r"(?R)", "[", "x" * 257])
def test_regex_restrictions(pattern: str) -> None:
    with pytest.raises(DomainError):
        compile_pattern(pattern)


@pytest.mark.security
@pytest.mark.regression
def test_regex_timeout_is_explicit_and_bounded() -> None:
    pattern = compile_pattern(r"(a|aa)+$")
    with pytest.raises(DomainError, match="5 ms"):
        regex_search(pattern, "a" * 16_000 + "!")


def test_yaml_changes_really_change_detection_behavior() -> None:
    rule = load_rule("""
id: CUSTOM-001
name: Arbitrary locally authored rule
description: A rule not known to Python.
severity: low
conditions:
  field: event.action
  operator: equals
  value: invented_action
""")
    assert matches(rule.conditions, {"event": {"action": "invented_action"}})
    assert not matches(rule.conditions, {"event": {"action": "login"}})
