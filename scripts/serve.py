import os

import uvicorn

from app.core.config import Settings
from app.main import create_app


def main() -> None:
    settings = Settings.from_env()
    try:
        port = int(os.getenv("PORT", "10000"))
    except ValueError as exc:
        raise ValueError("PORT must be an integer between 1 and 65535") from exc
    if not 1 <= port <= 65535:
        raise ValueError("PORT must be an integer between 1 and 65535")
    uvicorn.run(
        create_app(settings),
        host="0.0.0.0",  # noqa: S104 - required container/Render listener; API boundaries still apply.
        port=port,
        workers=1,
        proxy_headers=False,
        access_log=False,
        server_header=False,
        limit_concurrency=64,
    )


if __name__ == "__main__":
    main()
