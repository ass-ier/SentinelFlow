import json
import re

import pytest

from app.core.config import ROOT


@pytest.mark.regression
@pytest.mark.security
@pytest.mark.parametrize(
    ("package", "minimum"),
    [
        ("react-router-dom", (7, 18, 0)),
        ("react-router", (7, 18, 0)),
        ("vite", (7, 3, 6)),
        ("vitest", (4, 1, 11)),
        ("@vitest/mocker", (4, 1, 11)),
        ("@playwright/test", (1, 55, 1)),
        ("playwright", (1, 55, 1)),
        ("playwright-core", (1, 55, 1)),
    ],
)
def test_known_advisory_floors_in_committed_lockfile(
    package: str, minimum: tuple[int, int, int]
) -> None:
    lock = json.loads((ROOT / "frontend" / "package-lock.json").read_text())
    version = lock["packages"][f"node_modules/{package}"]["version"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), "Use a pinned stable package release"
    actual = tuple(int(part) for part in version.split("."))
    assert actual >= minimum, f"{package}@{version} reintroduces a known dependency advisory"
