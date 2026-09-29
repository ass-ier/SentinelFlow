import secrets
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import select

from app.core.errors import DomainError
from app.integrations.schemas import CredentialConfig
from app.integrations.settings import EnvironmentSecrets
from app.storage.integrations import CredentialRecord

if TYPE_CHECKING:
    from app.services.platform import Platform


def scoped_identity(
    platform: "Platform", authorization: str | None
) -> tuple[str, CredentialConfig] | None:
    if not authorization or not authorization.startswith("Bearer ") or not authorization.isascii():
        return None
    supplied = authorization[7:]
    if not 32 <= len(supplied) <= 256:
        return None
    with platform.db.session() as session:
        records = list(session.scalars(select(CredentialRecord)))
    matches = []
    for row in records:
        config = CredentialConfig.model_validate(row.definition)
        if not config.enabled or (
            config.expires_at is not None and config.expires_at <= datetime.now(UTC)
        ):
            continue
        try:
            expected = EnvironmentSecrets().read(config.token_ref)
        except DomainError as exc:
            if exc.code == "secret_unavailable":
                continue
            raise
        if expected.isascii() and secrets.compare_digest(supplied, expected):
            matches.append((f"integration:{row.id}", config))
    if len(matches) > 1:
        raise DomainError(
            "Integration token configuration is ambiguous", 401, "credential_conflict"
        )
    return matches[0] if matches else None


def require_scope(
    platform: "Platform", authorization: str | None, scope: str, connector_id: str | None = None
) -> str:
    if platform.settings.public_demo:
        raise DomainError(
            "External integration APIs are disabled in public demo mode",
            403,
            "public_demo_restricted",
        )
    identity = scoped_identity(platform, authorization)
    if identity is None:
        raise DomainError("A valid scoped integration token is required", 401, "unauthorized")
    actor, config = identity
    if scope not in config.scopes or (
        connector_id is not None and config.connector_id != connector_id
    ):
        raise DomainError("Integration token does not grant this operation", 403, "scope_denied")
    return actor
