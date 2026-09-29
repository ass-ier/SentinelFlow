import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Protocol
from urllib.parse import SplitResult, urlsplit

from app.core.errors import DomainError
from app.core.safe import json_loads
from app.integrations.settings import IntegrationSettings

DNS_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="integration-dns")
DNS_SLOTS = threading.BoundedSemaphore(2)
MESSAGES = {
    "configuration_error": "Integration configuration is incomplete or invalid",
    "authentication_error": "Upstream authentication failed; check server-side credentials",
    "forbidden": "Upstream permission was denied; check assigned read permissions",
    "rate_limited": "Upstream rate limit reached; retry is scheduled",
    "upstream_error": "Upstream service returned an error",
    "network_error": "Outbound connection failed",
    "timeout": "Outbound operation exceeded its deadline",
    "response_limit": "Upstream response exceeded the configured size limit",
    "invalid_response": "Upstream returned an invalid or incomplete response",
    "redirect_denied": "Outbound redirects are not followed",
    "ssrf_denied": "Destination address is not permitted by the outbound network policy",
    "table_unavailable": "Query table is unavailable; enable only tables present in the workspace",
    "pagination_limit": "Polling budget reached; the saved continuation will resume next cycle",
}


class IntegrationError(DomainError):
    def __init__(
        self, code: str, *, http_status: int | None = None, retry_after: float | None = None
    ) -> None:
        super().__init__(MESSAGES[code], 502, code)
        self.http_status = http_status
        self.retry_after = retry_after

    @property
    def transient(self) -> bool:
        return self.code in {"network_error", "timeout", "rate_limited"} or (
            self.http_status is not None and self.http_status >= 500
        )


@dataclass(frozen=True)
class HTTPResult:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> dict[str, Any]:
        try:
            value = json_loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, DomainError) as exc:
            raise IntegrationError("invalid_response") from exc
        if not isinstance(value, dict):
            raise IntegrationError("invalid_response")
        return value


class HTTPTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        timeout: float = 5,
        max_bytes: int = 1_048_576,
    ) -> HTTPResult: ...


def retry_after(value: str | None, now: datetime | None = None) -> float | None:
    if not value:
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:
            stamp = parsedate_to_datetime(value)
            seconds = (stamp - (now or datetime.now(UTC))).total_seconds()
        except (ValueError, TypeError, OverflowError):
            return None
    if not 0 <= seconds <= 3600:
        return 3600 if seconds > 3600 else None
    return seconds


def require_success(result: HTTPResult) -> HTTPResult:
    if 200 <= result.status < 300:
        return result
    codes = {
        401: "authentication_error",
        403: "forbidden",
        429: "rate_limited",
    }
    code = (
        "redirect_denied"
        if 300 <= result.status < 400
        else codes.get(result.status, "upstream_error")
    )
    raise IntegrationError(
        code, http_status=result.status, retry_after=retry_after(result.headers.get("retry-after"))
    )


def encoded_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def checked_url(value: str, policy: IntegrationSettings, *, query: bool = True) -> SplitResult:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise IntegrationError("configuration_error") from exc
    if (
        len(value) > 8192
        or not value.isascii()
        or any(ord(char) < 33 or ord(char) == 127 for char in value)
        or "\\" in value
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (parsed.query and not query)
        or parsed.scheme not in {"https", "http"}
        or (parsed.scheme == "http" and not policy.allow_local_http)
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise IntegrationError("configuration_error")
    return parsed


def permitted_address(address: str, policy: IntegrationSettings, *, http: bool = False) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and (
        ip.sixtofour is not None or ip.teredo is not None or ip.is_site_local
    ):
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return policy.allow_local_http
    if http or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return False
    if ip.is_global:
        return True
    return any(ip in ipaddress.ip_network(network) for network in policy.allowed_networks)


def resolve_addresses(host: str, port: int, timeout: float) -> list[str]:
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    if not DNS_SLOTS.acquire(blocking=False):
        raise IntegrationError("network_error")
    future = DNS_POOL.submit(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM)
    future.add_done_callback(lambda _: DNS_SLOTS.release())
    try:
        return list(dict.fromkeys(str(item[4][0]) for item in future.result(timeout=timeout)))
    except TimeoutError as exc:
        future.cancel()
        raise IntegrationError("timeout") from exc
    except OSError as exc:
        raise IntegrationError("network_error") from exc


class PinnedConnection(http.client.HTTPConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float, tls: bool) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self.address = address
        self.tls = tls

    def connect(self) -> None:
        sock = socket.create_connection((self.address, self.port), self.timeout)
        if self.tls:
            try:
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.host)
            except (OSError, ValueError):
                sock.close()
                raise
        self.sock = sock


class SafeHTTPTransport:
    def __init__(self, policy: IntegrationSettings) -> None:
        self.policy = policy

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        timeout: float = 5,
        max_bytes: int = 1_048_576,
    ) -> HTTPResult:
        parsed = checked_url(url, self.policy)
        host = parsed.hostname
        assert host is not None
        deadline = time.monotonic() + min(15, max(0.1, timeout))
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = resolve_addresses(host, port, min(2, timeout))
        if not addresses or any(
            not permitted_address(address, self.policy, http=parsed.scheme == "http")
            for address in addresses
        ):
            raise IntegrationError("ssrf_denied")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise IntegrationError("timeout")
        connection = PinnedConnection(host, addresses[0], port, remaining, parsed.scheme == "https")
        timed_out = threading.Event()

        def interrupt() -> None:
            timed_out.set()
            if connection.sock:
                try:
                    connection.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass  # The request may have closed its socket concurrently.
                connection.close()

        timer = threading.Timer(remaining, interrupt)
        timer.daemon = True
        timer.start()
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        try:
            connection.request(
                method,
                target,
                body=body,
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    **(headers or {}),
                },
            )
            response = connection.getresponse()
            chunks: list[bytes] = []
            size = 0
            while True:
                if timed_out.is_set():
                    raise IntegrationError("timeout")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise IntegrationError("timeout")
                if connection.sock:
                    connection.sock.settimeout(remaining)
                chunk = response.read1(min(16_384, max_bytes - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise IntegrationError("response_limit")
                chunks.append(chunk)
            if response.getheader("Content-Encoding", "identity") != "identity":
                raise IntegrationError("invalid_response")
            return HTTPResult(
                response.status,
                {"retry-after": response.getheader("Retry-After", "")},
                b"".join(chunks),
            )
        except TimeoutError as exc:
            raise IntegrationError("timeout") from exc
        except (OSError, http.client.HTTPException, UnicodeError, ValueError) as exc:
            raise IntegrationError("timeout" if timed_out.is_set() else "network_error") from exc
        finally:
            timer.cancel()
            connection.close()
