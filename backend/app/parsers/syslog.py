import re
from datetime import UTC, datetime

from app.core.errors import DomainError
from app.parsers.normalize import normalize_record
from app.schemas.events import NormalizedEvent

HEADER = re.compile(
    r"^(?:<\d{1,3}>)?(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|"
    r"\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s+(?P<program>[\w./-]+)"
    r"(?:\[\d+\])?:\s+(?P<message>.+)$"
)
LOGIN = re.compile(
    r"(?P<result>Failed|Accepted) (?:password|publickey) for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
SESSION = re.compile(r"session (?P<state>opened|closed) for user (?P<user>[\w.-]+)")
LOCKOUT = re.compile(r"account (?P<user>[\w.-]+) locked(?: from (?P<ip>\S+))?")
PASSWORD = re.compile(r"password changed for (?P<user>[\w.-]+)")


def parse_syslog(line: str, year: int = 2026) -> NormalizedEvent:
    header = HEADER.fullmatch(line)
    if not header:
        raise DomainError("Unsupported syslog header")
    values = header.groupdict()
    stamp = values["stamp"]
    try:
        timestamp = (
            datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            if "T" in stamp
            else datetime.strptime(f"{year} {stamp}", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
        )
    except ValueError as exc:
        raise DomainError("Invalid syslog timestamp") from exc
    message = values["message"]
    match = LOGIN.search(message)
    source: dict[str, str | int | None] = {}
    if match:
        user = match["user"]
        action = "login"
        outcome = "failure" if match["result"] == "Failed" else "success"
        source = {"ip": match["ip"], "port": int(match["port"])}
    elif match := SESSION.search(message):
        user = match["user"]
        action = "logout" if match["state"] == "closed" else "login"
        outcome = "success"
    elif match := LOCKOUT.search(message):
        user = match["user"]
        action, outcome = "account_lockout", "failure"
        source = {"ip": match["ip"]}
    elif match := PASSWORD.search(message):
        user = match["user"]
        action, outcome = "password_change", "success"
    else:
        raise DomainError("Unsupported authentication syslog message")
    return normalize_record(
        {
            "event": {
                "timestamp": timestamp,
                "source": values["program"],
                "category": "authentication",
                "action": action,
                "outcome": outcome,
            },
            "host": {"name": values["host"]},
            "user": {"name": user},
            "source": source,
        },
        "syslog",
        raw=line,
    )
