from pathlib import Path

import pytest

from app.core.errors import DomainError
from app.core.safe import json_loads, yaml_loads

DATA = Path(__file__).resolve().parents[3] / "test-data" / "security"
pytestmark = pytest.mark.security


@pytest.mark.regression
def test_json_exponent_overflow_is_rejected() -> None:
    with pytest.raises(DomainError, match="finite"):
        json_loads((DATA / "overflow_number.json").read_text())


@pytest.mark.regression
def test_yaml_nonfinite_numbers_are_rejected() -> None:
    with pytest.raises(DomainError, match="finite"):
        yaml_loads((DATA / "nonfinite.yaml").read_text())


@pytest.mark.regression
def test_yaml_dates_remain_strings() -> None:
    data = yaml_loads((DATA / "sigma_dates.yml").read_text())
    assert data["date"] == "2022-03-24"
    assert data["modified"] == "2025-07-18"


@pytest.mark.regression
def test_oversized_integer_is_a_controlled_error() -> None:
    with pytest.raises(DomainError):
        json_loads('{"count":' + "9" * 5000 + "}")


@pytest.mark.parametrize("text", ['{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'])
def test_json_rejects_ambiguous_values(text: str) -> None:
    with pytest.raises(DomainError):
        json_loads(text)


@pytest.mark.parametrize(
    "text",
    [
        "key: 1\nkey: 2",
        "key: &anchor [1, 2]\ncopy: *anchor",
        "!!python/object/apply:os.system ['echo unsafe']",
        "key: .inf",
    ],
)
def test_yaml_rejects_unsafe_values(text: str) -> None:
    with pytest.raises(DomainError):
        yaml_loads(text)
