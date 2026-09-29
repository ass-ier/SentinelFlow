import asyncio
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

from app.core.errors import DomainError
from app.core.security import BodyLimitMiddleware
from app.storage.migrations import migrate

pytestmark = [pytest.mark.security, pytest.mark.regression]


def test_many_small_request_frames_are_coalesced_under_the_byte_limit() -> None:
    async def exercise():
        sent = 0
        received = []

        async def app(_scope, receive, _send):
            received.append(await receive())

        async def receive():
            nonlocal sent
            sent += 1
            return {"type": "http.request", "body": b"x", "more_body": sent < 2000}

        async def send(_message):
            pytest.fail("Successful input should reach the application")

        await BodyLimitMiddleware(app, max_bytes=2000)(
            {"type": "http", "path": "/events", "headers": []}, receive, send
        )
        assert received == [{"type": "http.request", "body": b"x" * 2000, "more_body": False}]

    asyncio.run(exercise())


def test_stalled_request_body_has_a_finite_deadline() -> None:
    async def exercise():
        messages = []

        async def app(*_args):
            pytest.fail("Timed-out input must not invoke the application")

        async def receive():
            await asyncio.sleep(10)
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            messages.append(message)

        middleware = BodyLimitMiddleware(app, max_bytes=2000, timeout_seconds=0.02)
        await asyncio.wait_for(
            middleware({"type": "http", "path": "/events", "headers": []}, receive, send), 1
        )
        assert messages[0]["status"] == 408
        assert b"request_timeout" in messages[1]["body"]

    asyncio.run(exercise())


@pytest.mark.parametrize("value", [b"-1", b"+1", b" 1", b"1.0", b"invalid"])
def test_invalid_content_length_fails_before_consuming_a_body(value: bytes) -> None:
    async def exercise():
        messages = []

        async def app(*_args):
            pytest.fail("Invalid framing must not invoke the application")

        async def receive():
            pytest.fail("Invalid Content-Length should be rejected before consuming input")

        async def send(message):
            messages.append(message)

        await BodyLimitMiddleware(app, max_bytes=2000)(
            {"type": "http", "path": "/events", "headers": [(b"content-length", value)]},
            receive,
            send,
        )
        assert messages[0]["status"] == 400

    asyncio.run(exercise())


@pytest.mark.migration
def test_incomplete_existing_table_is_rejected_before_any_schema_mutation(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'partial.sqlite3'}")
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE events (id TEXT PRIMARY KEY)"))
            connection.execute(text("INSERT INTO events VALUES ('preserve-this-row')"))
        with pytest.raises(DomainError) as failure:
            migrate(engine)
        assert failure.value.code == "schema_integrity"
        assert inspect(engine).get_table_names() == ["events"]
        with engine.connect() as connection:
            assert connection.execute(text("SELECT id FROM events")).scalar() == "preserve-this-row"
    finally:
        engine.dispose()


@pytest.mark.migration
def test_missing_additive_tables_are_restored_without_changing_legacy_rows(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'interrupted.sqlite3'}")
    try:
        migrate(engine)
        with engine.begin() as connection:
            connection.execute(text("DROP TABLE connector_checkpoints"))
        migrate(engine)
        assert "connector_checkpoints" in inspect(engine).get_table_names()
    finally:
        engine.dispose()
