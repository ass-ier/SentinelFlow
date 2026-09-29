import os
import re
from dataclasses import dataclass
from ipaddress import ip_network
from typing import Protocol
from urllib.parse import urlsplit

from app.core.errors import DomainError

REFERENCE_PATTERN = (
    r"^(?:SENTINEL_INTEGRATION_[A-Z0-9_]{1,80}|SENTINEL_CLIENT_SECRET|GRAPH_CLIENT_SECRET)$"
)


def flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name, str(default)).lower()
    if value not in {"true", "false", "1", "0"}:
        raise ValueError(f"{name} must be true or false")
    return value in {"true", "1"}


class SecretStore(Protocol):
    def read(self, reference: str) -> str: ...


class EnvironmentSecrets:
    def read(self, reference: str) -> str:
        if not re.fullmatch(REFERENCE_PATTERN, reference):
            raise DomainError("Unsupported server-side secret reference", 422, "secret_reference")
        value = os.getenv(reference, "")
        if not value or len(value) > 8192 or "\r" in value or "\n" in value:
            raise DomainError(
                "Configure the referenced secret in the server environment",
                409,
                "secret_unavailable",
            )
        return value


@dataclass(frozen=True)
class IntegrationSettings:
    sentinel_enabled: bool = False
    graph_enabled: bool = False
    windows_enabled: bool = False
    notifications_enabled: bool = False
    worker_enabled: bool = True
    allow_local_http: bool = False
    allowed_networks: tuple[str, ...] = ()
    public_base_url: str = ""

    def __post_init__(self) -> None:
        for network in self.allowed_networks:
            ip_network(network, strict=True)
        if self.public_base_url:
            parsed = urlsplit(self.public_base_url)
            local = self.allow_local_http and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
            if (
                parsed.scheme not in ({"https", "http"} if local else {"https"})
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or not self.public_base_url.isascii()
                or any(c.isspace() for c in self.public_base_url)
            ):
                raise ValueError("PUBLIC_BASE_URL must be an explicit HTTPS application URL")

    @property
    def external_enabled(self) -> bool:
        return any(
            (
                self.sentinel_enabled,
                self.graph_enabled,
                self.windows_enabled,
                self.notifications_enabled,
            )
        )

    @classmethod
    def from_env(cls) -> "IntegrationSettings":
        return cls(
            sentinel_enabled=flag("SENTINEL_ENABLED"),
            graph_enabled=flag("GRAPH_ENABLED"),
            windows_enabled=flag("WINDOWS_COLLECTOR_ENABLED"),
            notifications_enabled=flag("NOTIFICATIONS_ENABLED"),
            worker_enabled=flag("SENTINEL_INTEGRATION_WORKER", True),
            allow_local_http=flag("SENTINEL_INTEGRATION_LOCAL_TEST"),
            allowed_networks=tuple(
                item.strip()
                for item in os.getenv("SENTINEL_WEBHOOK_ALLOWED_NETWORKS", "").split(",")
                if item.strip()
            ),
            public_base_url=os.getenv("PUBLIC_BASE_URL", "").rstrip("/"),
        )
