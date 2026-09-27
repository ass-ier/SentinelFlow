import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[3]
DEMO_DB = ROOT / "data" / "sentinelflow-demo.sqlite3"


@dataclass(frozen=True)
class Settings:
    database_url: str = f"sqlite:///{DEMO_DB}"
    api_token: str = ""
    allowed_origins: tuple[str, ...] = ("http://127.0.0.1:5173", "http://localhost:5173")
    max_upload_bytes: int = 5 * 1024 * 1024
    max_events: int = 10_000
    max_replay_jobs: int = 2

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

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv(ROOT / ".env")
        frontend_port = int(os.getenv("SENTINEL_FRONTEND_PORT", "5173"))
        if not 1 <= frontend_port <= 65535:
            raise ValueError("Frontend port must be between 1 and 65535")
        default_origins = f"http://127.0.0.1:{frontend_port},http://localhost:{frontend_port}"
        url = os.getenv("SENTINEL_DATABASE_URL", f"sqlite:///{DEMO_DB}")
        if url.startswith("sqlite:///") and not url.startswith("sqlite:////"):
            relative = url.removeprefix("sqlite:///")
            if relative != ":memory:":
                url = f"sqlite:///{ROOT / relative}"
        return cls(
            database_url=url,
            api_token=os.getenv("SENTINEL_API_TOKEN", ""),
            allowed_origins=tuple(
                value.strip()
                for value in os.getenv(
                    "SENTINEL_ALLOWED_ORIGINS",
                    default_origins,
                ).split(",")
                if value.strip()
            ),
            max_upload_bytes=int(os.getenv("SENTINEL_MAX_UPLOAD_BYTES", "5242880")),
            max_events=int(os.getenv("SENTINEL_MAX_EVENTS", "10000")),
        )
