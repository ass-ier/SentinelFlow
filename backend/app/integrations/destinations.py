import hashlib
import hmac
import time
from typing import Any, Protocol

from app.integrations.schemas import DestinationConfig
from app.integrations.settings import IntegrationSettings, SecretStore
from app.integrations.transport import (
    HTTPResult,
    HTTPTransport,
    checked_url,
    encoded_json,
    require_success,
)


class NotificationDestination(Protocol):
    def send(self, payload: dict[str, Any], idempotency_key: str) -> HTTPResult: ...
    def test(self, idempotency_key: str) -> HTTPResult: ...
    def health(self) -> dict[str, str]: ...


def signature(secret: str, timestamp: str, body: bytes) -> str:
    return (
        "sha256="
        + hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    )


def verify_signature(
    secret: str, timestamp: str, body: bytes, supplied: str, *, now: float, tolerance: int = 300
) -> bool:
    if (
        not secret
        or not timestamp.isascii()
        or not timestamp.isdecimal()
        or len(timestamp) > 12
        or not supplied.isascii()
        or len(supplied) != 71
    ):
        return False
    return abs(now - int(timestamp)) <= tolerance and hmac.compare_digest(
        signature(secret, timestamp, body), supplied
    )


class WebhookDestination:
    def __init__(
        self,
        config: DestinationConfig,
        transport: HTTPTransport,
        secrets: SecretStore,
        policy: IntegrationSettings,
        *,
        demo_url: str | None = None,
    ) -> None:
        self.config, self.transport, self.secrets, self.policy = config, transport, secrets, policy
        self.demo_url = demo_url

    def send(self, payload: dict[str, Any], idempotency_key: str) -> HTTPResult:
        url = (
            self.demo_url
            if self.config.mode == "demo"
            else self.secrets.read(self.config.url_ref or "")
        )
        if url is None:
            from app.integrations.transport import IntegrationError

            raise IntegrationError("configuration_error")
        checked_url(url, self.policy, query=self.config.type == "power_automate")
        body = encoded_json(payload)
        headers = {"Content-Type": "application/json", "Idempotency-Key": idempotency_key}
        if self.config.authentication != "none":
            secret = self.secrets.read(self.config.auth_ref or "")
            if self.config.authentication == "bearer":
                headers["Authorization"] = f"Bearer {secret}"
            else:
                timestamp = str(int(time.time()))
                headers["X-SentinelFlow-Timestamp"] = timestamp
                headers["X-SentinelFlow-Signature"] = signature(secret, timestamp, body)
        return require_success(
            self.transport.request(
                "POST",
                url,
                headers=headers,
                body=body,
                timeout=self.config.timeout_seconds,
                max_bytes=8192,
            )
        )

    def test(self, idempotency_key: str) -> HTTPResult:
        return self.send(
            {"event": "notification_test", "version": "1.0", "mock": self.config.mode == "demo"},
            idempotency_key,
        )

    def health(self) -> dict[str, str]:
        return {"status": "configured", "type": self.config.type}
