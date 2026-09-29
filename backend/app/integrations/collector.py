"""Durable Windows collector spool, also usable by the platform-independent fixture harness."""

import hashlib
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from app.core.errors import DomainError
from app.core.safe import json_loads
from app.integrations.transport import (
    HTTPTransport,
    IntegrationError,
    encoded_json,
    require_success,
)
from app.parsers.windows_xml import windows_xml

CHANNELS = (
    "ForwardedEvents",
    "Security",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Sysmon/Operational",
    "System",
    "Application",
)


@dataclass(frozen=True)
class CollectedEvent:
    raw: dict[str, Any]
    bookmark: str


class EventSource(Protocol):
    def read(self, channel: str, bookmark: str | None, limit: int) -> list[CollectedEvent]: ...


class WindowsEventSource:
    def __init__(self) -> None:
        from app.integrations.windows_native import NativeEventLog

        self.native = NativeEventLog()

    def read(self, channel: str, bookmark: str | None, limit: int) -> list[CollectedEvent]:
        return [
            CollectedEvent(windows_xml(xml), checkpoint)
            for xml, checkpoint in self.native.read(channel, bookmark, limit)
        ]


class FixtureEventSource:
    def __init__(self, events: list[dict[str, Any]]) -> None:
        self.events = events

    def read(self, channel: str, bookmark: str | None, limit: int) -> list[CollectedEvent]:
        selected = [
            item
            for item in self.events
            if channel == "ForwardedEvents" or item["Event"]["System"].get("Channel") == channel
        ]
        start = int(bookmark or "0")
        return [
            CollectedEvent(row, str(index + 1))
            for index, row in enumerate(selected[start : start + limit], start)
        ]


class Collector:
    def __init__(
        self,
        spool: Path,
        connector_id: str,
        endpoint: str,
        token: str,
        source: EventSource,
        transport: HTTPTransport,
        *,
        channels: tuple[str, ...] = ("ForwardedEvents",),
        batch_size: int = 100,
        max_spool: int = 100_000,
    ) -> None:
        if (
            not channels
            or any(channel not in CHANNELS for channel in channels)
            or not 1 <= batch_size <= 200
            or not 1 <= max_spool <= 100_000
            or not 32 <= len(token) <= 256
            or not token.isascii()
            or any(c.isspace() for c in token)
        ):
            raise DomainError("Invalid collector configuration")
        if spool.is_symlink() or spool.parent.is_symlink():
            raise DomainError("Collector spool must not use symlinks", 422, "spool_path")
        spool.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            if spool.parent.stat().st_mode & 0o022:
                raise DomainError(
                    "Collector spool directory must not be writable by other users",
                    422,
                    "spool_path",
                )
            descriptor = os.open(spool, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
        self.db = sqlite3.connect(spool)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript(
            "CREATE TABLE IF NOT EXISTS checkpoints "
            "(channel TEXT PRIMARY KEY, bookmark TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS spool (id TEXT PRIMARY KEY, channel TEXT NOT NULL, "
            "payload TEXT NOT NULL, created REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, "
            "due REAL NOT NULL DEFAULT 0, error TEXT, blocked INTEGER NOT NULL DEFAULT 0);"
            "CREATE INDEX IF NOT EXISTS spool_due ON spool(blocked, due);"
            "CREATE TABLE IF NOT EXISTS lease "
            "(id INTEGER PRIMARY KEY CHECK (id=1), expires REAL NOT NULL);"
        )
        if "owner" not in {row[1] for row in self.db.execute("PRAGMA table_info(lease)")}:
            self.db.execute("ALTER TABLE lease ADD COLUMN owner TEXT NOT NULL DEFAULT ''")
        self.owner = uuid.uuid4().hex
        self.connector_id, self.endpoint, self.token = connector_id, endpoint, token
        self.source, self.transport = source, transport
        self.channels, self.batch_size, self.max_spool = channels, batch_size, max_spool

    def cycle(self) -> dict[str, Any]:
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO lease(id, expires) VALUES(1, 0)")
            claimed = self.db.execute(
                "UPDATE lease SET expires=?,owner=? WHERE id=1 AND expires<=?",
                (time.time() + 60, self.owner, time.time()),
            )
            if claimed.rowcount != 1:
                raise DomainError("Another collector owns this spool", 409, "collector_busy")
        try:
            self.flush()
            for channel in self.channels:
                self._renew()
                count = self.db.execute("SELECT count(*) FROM spool").fetchone()[0]
                if count >= self.max_spool:
                    raise DomainError(
                        "Collector spool is full; delivery must recover before reading more events",
                        503,
                        "spool_full",
                    )
                checkpoint = self.db.execute(
                    "SELECT bookmark FROM checkpoints WHERE channel=?", (channel,)
                ).fetchone()
                events = self.source.read(
                    channel,
                    checkpoint[0] if checkpoint else None,
                    min(self.batch_size, self.max_spool - count),
                )
                self._renew()
                with self.db:
                    for event in events:
                        payload = encoded_json(event.raw).decode()
                        identifier = hashlib.sha256(payload.encode()).hexdigest()
                        self.db.execute(
                            "INSERT OR IGNORE INTO spool(id,channel,payload,created) "
                            "VALUES(?,?,?,?)",
                            (identifier, channel, payload, time.time()),
                        )
                    if events:
                        self.db.execute(
                            "INSERT INTO checkpoints(channel,bookmark) VALUES(?,?) "
                            "ON CONFLICT(channel) DO UPDATE SET bookmark=excluded.bookmark",
                            (channel, events[-1].bookmark),
                        )
            self.flush()
            count, blocked = self.db.execute(
                "SELECT count(*),coalesce(sum(blocked),0) FROM spool"
            ).fetchone()
            return {
                "pending": count,
                "blocked": blocked,
                "status": "pending" if count else "delivered",
            }
        finally:
            with self.db:
                self.db.execute(
                    "UPDATE lease SET expires=0,owner='' WHERE id=1 AND owner=?", (self.owner,)
                )

    def _renew(self) -> None:
        with self.db:
            result = self.db.execute(
                "UPDATE lease SET expires=? WHERE id=1 AND owner=? AND expires>?",
                (time.time() + 60, self.owner, time.time()),
            )
            if result.rowcount != 1:
                raise DomainError(
                    "Collector spool ownership expired; retry the cycle", 409, "collector_busy"
                )

    def flush(self) -> None:
        self._renew()
        rows = self.db.execute(
            "SELECT id,payload,attempts FROM spool WHERE blocked=0 AND due<=? "
            "ORDER BY created,id LIMIT ?",
            (time.time(), self.batch_size),
        ).fetchall()
        if not rows:
            return
        batch: list[dict[str, Any]] = []
        selected: list[tuple[str, str, int]] = []
        for row in rows:
            try:
                payload = json_loads(row[1])
                if not isinstance(payload, dict):
                    raise DomainError("Collector payload must be an event object")
            except DomainError:
                with self.db:
                    self.db.execute(
                        "UPDATE spool SET blocked=1,error='invalid_payload' WHERE id=?", (row[0],)
                    )
                continue
            candidate = [*batch, payload]
            if (
                len(encoded_json({"connector_id": self.connector_id, "events": candidate}))
                > 500 * 1024
            ):
                if not selected:
                    with self.db:
                        self.db.execute(
                            "UPDATE spool SET blocked=1,error='size_limit' WHERE id=?", (row[0],)
                        )
                break
            batch, selected = candidate, [*selected, row]
        if not selected:
            return
        try:
            response = require_success(
                self.transport.request(
                    "POST",
                    self.endpoint,
                    body=encoded_json({"connector_id": self.connector_id, "events": batch}),
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {self.token}",
                    },
                    timeout=5,
                    max_bytes=32_768,
                )
            ).json()
            stored, duplicate = response.get("events_stored"), response.get("duplicates_ignored")
            if (
                type(stored) is not int
                or type(duplicate) is not int
                or stored + duplicate != len(selected)
                or min(stored, duplicate) < 0
            ):
                raise IntegrationError("invalid_response")
        except IntegrationError as exc:
            with self.db:
                for identifier, _, attempts in selected:
                    attempts += 1
                    blocked = not exc.transient or attempts >= 10
                    delay = (
                        exc.retry_after
                        if exc.retry_after is not None
                        else min(300, 2 ** min(attempts, 8))
                    )
                    self.db.execute(
                        "UPDATE spool SET attempts=?, due=?, error=?, blocked=? WHERE id=?",
                        (attempts, time.time() + delay, exc.code, int(blocked), identifier),
                    )
            return
        with self.db:
            self._renew()
            self.db.executemany("DELETE FROM spool WHERE id=?", [(row[0],) for row in selected])

    def retry_blocked(self) -> None:
        with self.db:
            self.db.execute("UPDATE spool SET blocked=0,due=0 WHERE blocked=1")

    def close(self) -> None:
        self.db.close()
