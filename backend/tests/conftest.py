from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import ROOT, Settings
from app.detection.rules import Rule, load_bundled_rules
from app.main import create_app
from app.services.datasets import DatasetStore
from app.services.platform import Platform


@pytest.fixture
def datasets() -> DatasetStore:
    return DatasetStore()


@pytest.fixture
def rules() -> list[Rule]:
    return load_bundled_rules(ROOT / "rules")


@pytest.fixture
def service(tmp_path: Path) -> Iterator[Platform]:
    platform = Platform(Settings(database_url=f"sqlite:///{tmp_path / 'test.sqlite3'}"))
    yield platform
    platform.close()


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'api.sqlite3'}")
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        markers = {marker.name for marker in item.iter_markers()}
        if "/unit/" in item.nodeid:
            markers.add("unit")
        item.user_properties.append(("categories", ",".join(sorted(markers))))
