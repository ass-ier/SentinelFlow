from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.integrations.settings import IntegrationSettings
from app.main import create_app
from app.services.platform import Platform


@pytest.fixture
def service(tmp_path: Path) -> Iterator[Platform]:
    platform = Platform(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'integrations.sqlite3'}",
            integrations=IntegrationSettings(worker_enabled=False),
        )
    )
    yield platform
    platform.close()


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(
        create_app(
            Settings(
                database_url=f"sqlite:///{tmp_path / 'api.sqlite3'}",
                integrations=IntegrationSettings(worker_enabled=False),
            )
        )
    ) as client:
        yield client
