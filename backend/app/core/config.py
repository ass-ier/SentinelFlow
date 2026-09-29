import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv
from sqlalchemy.engine import make_url

from app.integrations.settings import IntegrationSettings

ROOT = Path(__file__).resolve().parents[3]
DEMO_DB = ROOT / "data" / "sentinelflow-demo.sqlite3"
PUBLIC_DEMO_FILENAME = "sentinelflow-public-demo.sqlite3"
PUBLIC_DEMO_RUN_LIMIT = 20


def checked_origin(value: str) -> str:
    message = "Allowed origins must be explicit HTTP(S) origins without credentials or paths"
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(message) from exc
    if (
        not value.isascii()
        or any(character.isspace() for character in value)
        or parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(r"[A-Za-z0-9.:\[\]-]+", parsed.netloc)
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError(message)
    host = parsed.hostname.lower()
    authority = f"[{host}]" if ":" in host else host
    if port is not None and port != (443 if parsed.scheme == "https" else 80):
        authority += f":{port}"
    return f"{parsed.scheme}://{authority}"


def checked_host(value: str) -> str:
    if (
        len(value) > 253
        or ".." in value
        or not re.fullmatch(r"(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[::1\])", value)
    ):
        raise ValueError("Allowed hosts must be explicit hostnames without wildcards or ports")
    return value.lower()


@dataclass(frozen=True)
class Settings:
    database_url: str = f"sqlite:///{DEMO_DB}"
    api_token: str = ""
    allowed_origins: tuple[str, ...] = ("http://127.0.0.1:5173", "http://localhost:5173")
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "[::1]", "testserver")
    public_demo: bool = False
    max_upload_bytes: int = 5 * 1024 * 1024
    max_events: int = 10_000
    max_replay_jobs: int = 2
    integrations: IntegrationSettings = field(default_factory=IntegrationSettings)

    def __post_init__(self) -> None:
        if self.api_token and (
            not self.api_token.isascii()
            or any(char.isspace() for char in self.api_token)
            or not self.api_token.isprintable()
            or len(self.api_token) > 256
        ):
            raise ValueError(
                "API token must be printable ASCII without whitespace, at most 256 characters"
            )
        object.__setattr__(
            self, "allowed_origins", tuple(checked_origin(value) for value in self.allowed_origins)
        )
        if not self.allowed_hosts:
            raise ValueError("At least one allowed host is required")
        object.__setattr__(
            self, "allowed_hosts", tuple(checked_host(value) for value in self.allowed_hosts)
        )
        if not 1 <= self.max_upload_bytes <= 5 * 1024 * 1024:
            raise ValueError("Upload limit must be between 1 byte and 5 MiB")
        if not 1 <= self.max_events <= 10_000 or not 1 <= self.max_replay_jobs <= 2:
            raise ValueError("Event limit must be 1-10000 and replay concurrency must be 1-2")
        database = make_url(self.database_url)
        public_file = bool(
            database.database and Path(database.database).name == PUBLIC_DEMO_FILENAME
        )
        if self.public_demo:
            if self.integrations.external_enabled:
                raise ValueError("External integrations are forbidden in the shared public demo")
            if (
                database.drivername != "sqlite"
                or not public_file
                or database.query
                or self.max_events < 56
            ):
                raise ValueError(
                    "Public demo requires a dedicated SQLite file named "
                    f"{PUBLIC_DEMO_FILENAME}, no URL query, and capacity for 56 seed events"
                )
        elif public_file:
            raise ValueError("The public demo database requires SENTINEL_PUBLIC_DEMO=true")

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv(ROOT / ".env")
        mode = os.getenv("SENTINEL_PUBLIC_DEMO", "false").lower()
        if mode not in {"true", "false", "1", "0"}:
            raise ValueError("SENTINEL_PUBLIC_DEMO must be true or false")
        public_demo = mode in {"true", "1"}
        frontend_port = int(os.getenv("SENTINEL_FRONTEND_PORT", "5173"))
        if not 1 <= frontend_port <= 65535:
            raise ValueError("Frontend port must be between 1 and 65535")
        default_origins = f"http://127.0.0.1:{frontend_port},http://localhost:{frontend_port}"
        default_db = ROOT / "data" / PUBLIC_DEMO_FILENAME if public_demo else DEMO_DB
        url = os.getenv("SENTINEL_DATABASE_URL", f"sqlite:///{default_db}")
        if url.startswith("sqlite:///") and not url.startswith("sqlite:////"):
            relative = url.removeprefix("sqlite:///")
            if relative != ":memory:":
                url = f"sqlite:///{ROOT / relative}"
        origins = tuple(
            value.strip()
            for value in os.getenv(
                "SENTINEL_ALLOWED_ORIGINS",
                default_origins,
            ).split(",")
            if value.strip()
        )
        hosts = tuple(
            value.strip()
            for value in os.getenv("SENTINEL_ALLOWED_HOSTS", "127.0.0.1,localhost,[::1]").split(",")
            if value.strip()
        )
        render_host = os.getenv("RENDER_EXTERNAL_HOSTNAME", "")
        if render_host:
            render_host = checked_host(render_host)
            hosts = tuple(dict.fromkeys((*hosts, render_host)))
            origins = tuple(dict.fromkeys((*origins, f"https://{render_host}")))
        return cls(
            database_url=url,
            api_token=os.getenv("SENTINEL_API_TOKEN", ""),
            allowed_origins=origins,
            allowed_hosts=hosts,
            public_demo=public_demo,
            max_upload_bytes=int(os.getenv("SENTINEL_MAX_UPLOAD_BYTES", "5242880")),
            max_events=int(os.getenv("SENTINEL_MAX_EVENTS", "10000")),
            integrations=IntegrationSettings.from_env(),
        )
