from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.storage.migrations import migrate


class Database:
    def __init__(self, url: str) -> None:
        sqlite = url.startswith("sqlite:")
        if sqlite and ":memory:" not in url:
            path = Path(url.removeprefix("sqlite:///"))
            path.parent.mkdir(parents=True, exist_ok=True)
        options = {"check_same_thread": False, "timeout": 30} if sqlite else {}
        if ":memory:" in url:
            self.engine = create_engine(url, connect_args=options, poolclass=StaticPool)
        else:
            self.engine = create_engine(url, connect_args=options)
        if sqlite:
            event.listen(self.engine, "connect", _configure_sqlite)
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)
        migrate(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        with self.sessions.begin() as session:
            yield session

    def close(self) -> None:
        self.engine.dispose()


def _configure_sqlite(connection: object, _: object) -> None:
    import sqlite3

    if isinstance(connection, sqlite3.Connection):
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")


def dispose(engine: Engine) -> None:
    engine.dispose()
