import os
from pathlib import Path

import pytest

from app.core.errors import DomainError
from app.integrations.collector import Collector, FixtureEventSource
from app.integrations.demo import demo_fixtures
from app.integrations.transport import HTTPResult, IntegrationError, encoded_json

pytestmark = [pytest.mark.security, pytest.mark.regression, pytest.mark.connectors]


@pytest.mark.parametrize("corruption", ["{", "null", '{"x":NaN}', '{"x":1,"x":2}'])
def test_corrupt_spool_row_is_quarantined_without_losing_other_events(
    tmp_path: Path, corruption: str
) -> None:
    class Receiver:
        outage = True
        calls = []

        def request(self, _method, _url, **kwargs):
            if self.outage:
                raise IntegrationError("network_error")
            self.calls.append(kwargs["body"])
            return HTTPResult(202, {}, encoded_json({"events_stored": 1, "duplicates_ignored": 0}))

    receiver = Receiver()
    collector = Collector(
        tmp_path / "spool.sqlite3",
        "synthetic",
        "https://receiver.example.invalid",
        "synthetic-collector-key-" + "x" * 32,
        FixtureEventSource(demo_fixtures()["windows"][:2]),
        receiver,
    )
    try:
        assert collector.cycle()["pending"] == 2
        first = collector.db.execute("SELECT id FROM spool ORDER BY created,id LIMIT 1").fetchone()
        with collector.db:
            collector.db.execute("UPDATE spool SET payload=? WHERE id=?", (corruption, first[0]))
            collector.db.execute("UPDATE spool SET due=0")
        receiver.outage = False
        assert collector.cycle() == {"pending": 1, "blocked": 1, "status": "pending"}
        assert len(receiver.calls) == 1
        assert collector.db.execute("SELECT error FROM spool").fetchone()[0] == "invalid_payload"
        assert collector.db.execute("SELECT payload FROM spool").fetchone()[0] == corruption
        assert collector.db.execute("SELECT bookmark FROM checkpoints").fetchone()[0] == "2"
    finally:
        collector.close()


@pytest.mark.parametrize("parent_link", [False, True])
def test_collector_rejects_symlink_targets_before_writing(
    tmp_path: Path, parent_link: bool
) -> None:
    destination = tmp_path / "private"
    destination.mkdir()
    marker = destination / "spool.sqlite3"
    marker.write_bytes(b"test-owned file, never open as a database")
    link = tmp_path / "link"
    link.symlink_to(destination if parent_link else marker, target_is_directory=parent_link)
    with pytest.raises(DomainError, match="symlink"):
        Collector(
            link / "spool.sqlite3" if parent_link else link,
            "source",
            "https://example.invalid",
            "synthetic-only-" + "x" * 32,
            FixtureEventSource([]),
            None,
        )
    assert marker.read_bytes() == b"test-owned file, never open as a database"


def test_collector_uses_private_posix_spool_permissions(tmp_path: Path) -> None:
    path = tmp_path / "spool.sqlite3"
    collector = Collector(
        path,
        "source",
        "https://example.invalid",
        "synthetic-only-" + "x" * 32,
        FixtureEventSource([]),
        None,
    )
    try:
        if os.name == "posix":
            assert path.stat().st_mode & 0o777 == 0o600
        assert collector.cycle()["pending"] == 0
    finally:
        collector.close()
