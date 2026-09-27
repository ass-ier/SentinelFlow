from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from app.core.config import ROOT
from app.core.errors import DomainError
from app.core.safe import json_loads
from app.parsers import parse_content
from app.schemas.events import NormalizedEvent


class DatasetStore:
    def __init__(self, root: Path = ROOT / "test-data") -> None:
        self.root = root.resolve()

    def catalog(self) -> list[dict[str, Any]]:
        manifest = self.root / "manifest.json"
        if not manifest.exists():
            raise DomainError(
                "Dataset manifest missing; run the generator", 503, "missing_datasets"
            )
        value = json_loads(manifest.read_text())
        if not isinstance(value, list):
            raise DomainError("Invalid dataset manifest", 500, "dataset_error")
        return value

    def get(self, dataset_id: str) -> dict[str, Any]:
        for item in self.catalog():
            if item["id"] == dataset_id:
                return item
        raise DomainError("Dataset not found", 404, "not_found")

    def events(self, dataset_id: str) -> list[NormalizedEvent]:
        item = self.get(dataset_id)
        path = (self.root / item["path"]).resolve()
        if not path.is_relative_to(self.root) or not path.is_file():
            raise DomainError("Dataset path is invalid", 422, "dataset_error")
        if path.stat().st_size > 5 * 1024 * 1024:
            raise DomainError("Dataset exceeds 5 MiB", 413, "size_limit")
        content = path.read_text(encoding="utf-8")
        if hashlib.sha256(content.encode()).hexdigest() != item["sha256"]:
            raise DomainError(
                "Dataset checksum mismatch; regenerate fixtures or import as custom telemetry",
                409,
                "dataset_changed",
            )
        events = parse_content(content, item["format"])
        if len(events) != item["event_count"]:
            raise DomainError("Dataset event count differs from manifest", 409, "dataset_changed")
        return events

    def scenarios(self) -> list[dict[str, Any]]:
        value = json_loads((self.root / "expected-results" / "scenarios.json").read_text())
        if not isinstance(value, list):
            raise DomainError("Invalid scenario manifest", 500, "dataset_error")
        return value
