import importlib
import importlib.metadata
import os
import re
import sys
import urllib.error
from http.client import RemoteDisconnected
from pathlib import Path
from unittest.mock import Mock

import pytest
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from app.core import config
from app.core.config import PUBLIC_DEMO_FILENAME, ROOT, Settings
from app.core.evidence import source_fingerprint
from app.services.platform import Platform

pytestmark = pytest.mark.regression


@pytest.fixture
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "load_dotenv", lambda _: False)
    for key in list(os.environ):
        if key.startswith(("SENTINEL_", "RENDER_")) or key == "PORT":
            monkeypatch.delenv(key)


@pytest.mark.usefixtures("clean_environment")
def test_render_hostname_and_explicit_production_origins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_PUBLIC_DEMO", "true")
    monkeypatch.setenv("RENDER_EXTERNAL_HOSTNAME", "backend-example.onrender.com")
    monkeypatch.setenv(
        "SENTINEL_ALLOWED_ORIGINS", "https://frontend.example.test,https://custom.example.test/"
    )
    settings = Settings.from_env()
    assert settings.public_demo is True
    assert settings.database_url.endswith("/" + PUBLIC_DEMO_FILENAME)
    assert settings.allowed_origins == (
        "https://frontend.example.test",
        "https://custom.example.test",
        "https://backend-example.onrender.com",
    )
    assert "backend-example.onrender.com" in settings.allowed_hosts
    assert "testserver" not in settings.allowed_hosts


@pytest.mark.usefixtures("clean_environment")
def test_local_defaults_and_relative_public_database_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert Settings.from_env().public_demo is False
    monkeypatch.setenv("SENTINEL_PUBLIC_DEMO", "1")
    monkeypatch.setenv("SENTINEL_DATABASE_URL", f"sqlite:///data/{PUBLIC_DEMO_FILENAME}")
    assert Settings.from_env().database_url == f"sqlite:///{ROOT / 'data' / PUBLIC_DEMO_FILENAME}"


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "null",
        "https://*.example.test",
        "https://example.test/path",
        "https://user:password@example.test",
        "https://example.test?query=1",
        "https://example.test#fragment",
        "https://example.test:70000",
        "javascript:invalid",
        "https://example.test\r\n",
    ],
)
def test_unsafe_or_ambiguous_origins_are_rejected(origin: str) -> None:
    with pytest.raises(ValueError, match="origins"):
        Settings(allowed_origins=(origin,))


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://FRONTEND.example.test:443/", "https://frontend.example.test"),
        ("http://localhost:80/", "http://localhost"),
        ("http://[::1]:18875/", "http://[::1]:18875"),
    ],
)
def test_origins_match_browser_case_and_default_port_normalization(
    value: str, expected: str
) -> None:
    assert Settings(allowed_origins=(value,)).allowed_origins == (expected,)


@pytest.mark.parametrize("host", ["*", "*.example.test", "https://example.test", "host:9000", ""])
def test_hosts_are_explicit_not_wildcards_or_urls(host: str) -> None:
    with pytest.raises(ValueError, match="hosts"):
        Settings(allowed_hosts=(host,))


@pytest.mark.parametrize(
    "url",
    [
        "sqlite:///:memory:",
        "sqlite:///data/sentinelflow-demo.sqlite3",
        f"sqlite:///data/{PUBLIC_DEMO_FILENAME}?mode=ro",
    ],
)
def test_public_mode_requires_dedicated_database(url: str) -> None:
    with pytest.raises(ValueError, match="dedicated SQLite"):
        Settings(public_demo=True, database_url=url)


def test_local_mode_refuses_public_database_filename(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="SENTINEL_PUBLIC_DEMO=true"):
        Settings(database_url=f"sqlite:///{tmp_path / PUBLIC_DEMO_FILENAME}")


@pytest.mark.usefixtures("clean_environment")
def test_invalid_public_mode_is_not_silently_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_PUBLIC_DEMO", "tru")
    with pytest.raises(ValueError, match="SENTINEL_PUBLIC_DEMO"):
        Settings.from_env()


@pytest.mark.usefixtures("clean_environment")
def test_production_entrypoint_binds_port_and_preserves_proxy_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    serve = importlib.import_module("serve")
    calls = []
    monkeypatch.setenv("PORT", "18965")
    monkeypatch.setattr(serve.uvicorn, "run", lambda app, **kwargs: calls.append(kwargs))
    serve.main()
    assert calls == [
        {
            "host": "0.0.0.0",  # noqa: S104 - assert the required production listener.
            "port": 18965,
            "workers": 1,
            "proxy_headers": False,
            "access_log": False,
            "server_header": False,
            "limit_concurrency": 64,
        }
    ]


@pytest.mark.usefixtures("clean_environment")
@pytest.mark.parametrize("port", ["0", "65536", "invalid", ""])
def test_invalid_production_port_is_rejected(monkeypatch: pytest.MonkeyPatch, port: str) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    serve = importlib.import_module("serve")
    monkeypatch.setenv("PORT", port)
    with pytest.raises(ValueError, match="PORT"):
        serve.main()


@pytest.mark.parametrize(
    "filename", ["Dockerfile.backend", "render.yaml", ".env.public-demo.example", ".gitignore"]
)
def test_deployment_configuration_participates_in_validation_freshness(
    tmp_path: Path, filename: str
) -> None:
    before = source_fingerprint(tmp_path)
    (tmp_path / filename).write_text("configuration changed\n")
    assert source_fingerprint(tmp_path) != before


@pytest.mark.usefixtures("clean_environment")
def test_offline_reset_honors_the_configured_public_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SENTINEL_PUBLIC_DEMO", "true")
    monkeypatch.setenv("SENTINEL_DATABASE_URL", f"sqlite:///{tmp_path / PUBLIC_DEMO_FILENAME}")
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    reset = importlib.import_module("demo_reset")
    monkeypatch.setattr(reset, "generate", lambda: None)
    monkeypatch.setattr(reset, "generate_integrations", lambda: None)

    def stopped_server(*args: object) -> None:
        raise urllib.error.URLError("Deliberately stopped test server")

    monkeypatch.setattr(reset, "request", stopped_server)
    monkeypatch.setattr(sys, "argv", ["demo_reset.py", "--offline", "--seed"])
    reset.main()
    service = Platform(Settings.from_env())
    try:
        assert service.dashboard()["events_processed"] == 56
        assert service.dashboard()["total_alerts"] == 7
        assert len(service.runs()) == 1
    finally:
        service.close()


@pytest.mark.parametrize("machine", ["x86_64", "aarch64"])
def test_hash_lock_covers_sqlalchemy_runtime_dependencies_on_linux(machine: str) -> None:
    environment = {
        **default_environment(),
        "os_name": "posix",
        "sys_platform": "linux",
        "platform_system": "Linux",
        "platform_machine": machine,
        "python_version": "3.13",
        "python_full_version": "3.13.7",
        "extra": "",
    }
    pins = {
        canonicalize_name(name): version
        for name, version in re.findall(
            r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", (ROOT / "requirements.lock").read_text(), re.M
        )
    }
    for text in importlib.metadata.requires("SQLAlchemy") or []:
        requirement = Requirement(text)
        if requirement.marker is None or requirement.marker.evaluate(environment):
            name = canonicalize_name(requirement.name)
            assert name in pins, (
                f"Linux/{machine} runtime dependency {name} is missing from hash lock"
            )
            assert pins[name] in requirement.specifier


def test_readiness_wait_retries_transient_docker_port_resets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    verification = importlib.import_module("verify_deployment")
    process = Mock()
    process.poll.return_value = None
    request = Mock(
        side_effect=[
            RemoteDisconnected("Container port proxy not ready"),
            ConnectionResetError("ASGI server still starting"),
            {"status": "ok"},
        ]
    )
    monkeypatch.setattr(verification, "request", request)
    monkeypatch.setattr(verification.time, "sleep", lambda _: None)
    verification.wait_ready(process, "http://127.0.0.1:18866/health")
    assert request.call_count == 3
    request.assert_called_with("http://127.0.0.1:18866/health", timeout=2)


def test_readiness_wait_never_reports_an_exited_process_as_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    verification = importlib.import_module("verify_deployment")
    process = Mock()
    process.poll.return_value = 1
    request = Mock()
    monkeypatch.setattr(verification, "request", request)
    with pytest.raises(RuntimeError, match="exited during startup"):
        verification.wait_ready(process, "http://127.0.0.1:18866/health")
    request.assert_not_called()


def test_rehearsal_command_preserves_real_output_when_a_phase_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    verification = importlib.import_module("verify_deployment")
    monkeypatch.setattr(verification, "ROOT", tmp_path)
    log = tmp_path / "commands.log"
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("COV_CORE_", "COVERAGE_"))
    }
    with pytest.raises(RuntimeError, match="failed \\(7\\)"):
        verification.command(
            [sys.executable, "-c", "print('real output before failure'); raise SystemExit(7)"],
            log,
            env=environment,
            timeout=10,
        )
    assert "real output before failure" in log.read_text()
