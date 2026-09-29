"""Version 1 adopts the original schema; version 2 adds optional integrations."""

from sqlalchemy import Engine, insert, inspect, select

from app.core.errors import DomainError
from app.storage.integrations import SchemaRevision
from app.storage.models import Base


def migrate(engine: Engine) -> None:
    with engine.begin() as connection:
        inspector = inspect(connection)
        for name in set(inspector.get_table_names()) & Base.metadata.tables.keys():
            required = {column.name for column in Base.metadata.tables[name].columns}
            present = {column["name"] for column in inspector.get_columns(name)}
            if required - present:
                raise DomainError(
                    "Database schema is incomplete; restore a verified backup before retrying",
                    503,
                    "schema_integrity",
                )
        versions = (
            set(connection.scalars(select(SchemaRevision.version)))
            if inspect(connection).has_table(SchemaRevision.__tablename__)
            else set()
        )
        if versions - {1, 2}:
            raise DomainError(
                "Database schema is newer than this application", 503, "schema_version"
            )
        # Additive, idempotent DDL: existing events, alerts and rule snapshots are not rewritten.
        Base.metadata.create_all(connection)
        for version in (1, 2):
            if version not in versions:
                connection.execute(insert(SchemaRevision).values(version=version))
