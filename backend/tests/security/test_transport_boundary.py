import shutil
import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.integrations.settings import IntegrationSettings
from app.integrations.transport import IntegrationError, SafeHTTPTransport, permitted_address

pytestmark = [pytest.mark.security, pytest.mark.regression, pytest.mark.integration]


@pytest.mark.parametrize(
    "address",
    [
        "64:ff9b::7f00:1",
        "64:ff9b::a9fe:a9fe",
        "64:ff9b:1::a00:1",
        "2002:7f00:1::",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "fec0::1",
    ],
)
def test_translation_and_tunneling_ranges_never_bypass_network_policy(address: str) -> None:
    assert not permitted_address(address, IntegrationSettings(allowed_networks=("::/0",)))


@pytest.mark.parametrize(
    "host",
    ["2130706433", "0x7f000001", "0177.0.0.1", "127.1", "localhost.", "metadata.example.invalid"],
)
def test_alternate_host_spellings_are_checked_after_resolution(host: str, monkeypatch) -> None:
    import app.integrations.transport as module

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
    )
    monkeypatch.setattr(socket, "create_connection", lambda *_a, **_kw: pytest.fail("No connect"))
    with pytest.raises(IntegrationError) as failure:
        module.SafeHTTPTransport(IntegrationSettings()).request("POST", f"https://{host}/alerts")
    assert failure.value.code == "ssrf_denied"


@pytest.fixture
def tls_receiver(tmp_path: Path):
    executable = shutil.which("openssl")
    assert executable is not None, "OpenSSL CLI is required for the local TLS security harness"
    cert, key = tmp_path / "certificate.pem", tmp_path / "private-key.pem"
    subprocess.run(  # noqa: S603 - fixed local fixture command; no log or HTTP input.
        [
            executable,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=receiver.example.invalid",
            "-addext",
            "subjectAltName=DNS:receiver.example.invalid",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
        timeout=15,
    )
    key.chmod(0o600)
    received = []
    names = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def do_POST(self):
            received.append(
                {
                    "host": self.headers["Host"],
                    "body": self.rfile.read(int(self.headers["Content-Length"])),
                }
            )
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.set_servername_callback(lambda _sock, name, _context: names.append(name))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, cert, received, names
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("trusted", [True, False])
def test_real_tls_verification_dns_pinning_and_proxy_environment(
    tls_receiver, monkeypatch, trusted: bool
) -> None:
    import app.integrations.transport as module

    port, cert, received, names = tls_receiver
    create_context = ssl.create_default_context
    monkeypatch.setattr(
        module.ssl,
        "create_default_context",
        lambda: create_context(cafile=str(cert) if trusted else None),
    )
    answers = []

    def resolve(host, requested_port, _timeout):
        answers.append((host, requested_port))
        return ["127.0.0.1"]

    monkeypatch.setattr(module, "resolve_addresses", resolve)
    for variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.setenv(variable, "http://127.0.0.1:9")
    transport = SafeHTTPTransport(IntegrationSettings(allow_local_http=True))
    url = f"https://receiver.example.invalid:{port}/alerts"
    if trusted:
        assert transport.request("POST", url, body=b'{"synthetic":true}').status == 202
        assert received == [
            {"host": f"receiver.example.invalid:{port}", "body": b'{"synthetic":true}'}
        ]
    else:
        with pytest.raises(IntegrationError) as failure:
            transport.request("POST", url, body=b"{}")
        assert failure.value.code == "network_error"
        assert received == []
    assert answers == [("receiver.example.invalid", port)]
    assert names == ["receiver.example.invalid"]


def test_tls_hostname_verification_cannot_be_replaced_by_a_trusted_wrong_name(
    tls_receiver, monkeypatch
) -> None:
    import app.integrations.transport as module

    port, cert, received, names = tls_receiver
    create_context = ssl.create_default_context
    monkeypatch.setattr(module.ssl, "create_default_context", lambda: create_context(cafile=cert))
    monkeypatch.setattr(module, "resolve_addresses", lambda *_: ["127.0.0.1"])
    with pytest.raises(IntegrationError) as failure:
        SafeHTTPTransport(IntegrationSettings(allow_local_http=True)).request(
            "POST", f"https://wrong.example.invalid:{port}", body=b"{}"
        )
    assert failure.value.code == "network_error"
    assert received == []
    assert names == ["wrong.example.invalid"]
