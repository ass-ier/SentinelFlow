"""Generate exclusively invented Microsoft/Windows telemetry and expected integration counts."""

import argparse
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1] / "test-data" / "integrations"
ORIGIN = datetime(2026, 1, 15, 10, tzinfo=UTC)


def fixtures() -> dict[str, Any]:
    signins = [
        {
            "id": f"synthetic-signin-{index:03}",
            "createdDateTime": (ORIGIN + timedelta(seconds=index * 10)).isoformat(),
            "userPrincipalName": "analyst01@example.invalid",
            "userId": "synthetic-user-01",
            "ipAddress": "192.0.2.44",
            "status": {"errorCode": 50126 if index < 10 else 0},
            "appDisplayName": "Synthetic Portal",
            "deviceDetail": {"displayName": "demo-workstation-01"},
            "authenticationRequirement": "singleFactorAuthentication",
        }
        for index in range(12)
    ]
    audits = [
        {
            "id": "synthetic-audit-001",
            "activityDateTime": (ORIGIN + timedelta(seconds=140)).isoformat(),
            "activityDisplayName": "Add member to group",
            "result": "success",
            "loggedByService": "Core Directory",
            "additionalDetails": [{"key": "Computer", "value": "demo-dc-01"}],
            "initiatedBy": {
                "user": {
                    "id": "synthetic-operator",
                    "userPrincipalName": "operator01@example.invalid",
                }
            },
            "targetResources": [
                {"id": "synthetic-admin-group", "type": "Group", "displayName": "Administrators"}
            ],
        }
    ]
    windows = []

    def window(code: int, data: dict[str, Any], channel: str = "Security") -> None:
        provider = (
            "Microsoft-Windows-Sysmon"
            if "Sysmon" in channel
            else "Microsoft-Windows-PowerShell"
            if "PowerShell" in channel
            else "Microsoft-Windows-Security-Auditing"
            if channel == "Security"
            else "SyntheticProvider"
        )
        index = len(windows)
        windows.append(
            {
                "Event": {
                    "System": {
                        "EventID": code,
                        "EventRecordID": index + 1,
                        "Channel": channel,
                        "Provider": {"Name": provider},
                        "Computer": "demo-dc-01",
                        "TimeCreated": {
                            "SystemTime": (ORIGIN + timedelta(seconds=index * 3)).isoformat()
                        },
                    },
                    "EventData": {
                        "TargetUserName": "analyst01",
                        "SubjectUserName": "operator01",
                        "User": "operator01",
                        "TargetDomainName": "SYNTHETIC",
                        **data,
                    },
                }
            }
        )

    for code in (
        4624,
        4625,
        4740,
        4720,
        4722,
        4725,
        4726,
        4728,
        4732,
        4756,
        4729,
        4733,
        4757,
        4672,
        4688,
    ):
        data: dict[str, Any] = {"IpAddress": "192.0.2.55"}
        if code in {4728, 4732, 4756, 4729, 4733, 4757}:
            data.update(TargetUserName="Domain Admins", MemberName="SYNTHETIC\\analyst01")
        if code == 4688:
            data.update(
                NewProcessName="C:\\Windows\\System32\\notepad.exe", CommandLine="notepad.exe"
            )
        window(code, data)
    for _ in range(9):
        window(4625, {"IpAddress": "192.0.2.55"})
    for _ in range(2):
        window(4740, {})
    window(
        4104,
        {
            "ScriptBlockText": (
                "powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAxAA=="
            )
        },
        "Microsoft-Windows-PowerShell/Operational",
    )
    window(
        1,
        {
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "ParentImage": "C:\\Office\\WINWORD.EXE",
            "CommandLine": "cmd.exe /c echo synthetic",
        },
        "Microsoft-Windows-Sysmon/Operational",
    )
    for _ in range(3):
        window(
            3,
            {
                "SourceIp": "192.0.2.55",
                "DestinationIp": "198.51.100.25",
                "DestinationPort": "4444",
                "Protocol": "tcp",
            },
            "Microsoft-Windows-Sysmon/Operational",
        )
    for _ in range(3):
        window(
            22,
            {
                "SourceIp": "192.0.2.55",
                "QueryName": "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl.synthetic.invalid",
            },
            "Microsoft-Windows-Sysmon/Operational",
        )
    window(7036, {"ServiceName": "SyntheticService"}, "System")
    window(1000, {"ApplicationName": "SyntheticApplication"}, "Application")
    sentinel = {
        "SigninLogs": [
            {
                "Id": row["id"],
                "TimeGenerated": row["createdDateTime"],
                "UserPrincipalName": row["userPrincipalName"],
                "UserId": row["userId"],
                "IPAddress": row["ipAddress"],
                "ResultType": str(row["status"]["errorCode"]),
                "AppDisplayName": row["appDisplayName"],
                "DeviceDetail": row["deviceDetail"],
            }
            for row in signins
        ],
        "AuditLogs": [
            {
                "Id": row["id"],
                "TimeGenerated": row["activityDateTime"],
                "OperationName": row["activityDisplayName"],
                "Result": row["result"],
                "LoggedByService": row["loggedByService"],
                "AdditionalDetails": row["additionalDetails"],
                "InitiatedBy": row["initiatedBy"],
                "TargetResources": row["targetResources"],
            }
            for row in audits
        ],
    }
    benign_graph = {"signIns": deepcopy(signins[10:]), "directoryAudits": deepcopy(audits)}
    benign_graph["directoryAudits"][0]["targetResources"][0]["displayName"] = "Readers"
    benign_sentinel = {
        "SigninLogs": deepcopy(sentinel["SigninLogs"][10:]),
        "AuditLogs": deepcopy(sentinel["AuditLogs"]),
    }
    benign_sentinel["AuditLogs"][0]["TargetResources"][0]["displayName"] = "Readers"
    return {
        "sentinel": sentinel,
        "graph": {"signIns": signins, "directoryAudits": audits},
        "windows": windows,
        "benign": {
            "sentinel": benign_sentinel,
            "graph": benign_graph,
            "windows": [
                row
                for row in windows
                if row["Event"]["System"]["EventID"] in {4624, 4688, 7036, 1000}
            ],
            "expected": {
                "microsoft_sentinel": {"events": 3, "alerts": {}},
                "microsoft_graph": {"events": 3, "alerts": {}},
                "windows_wef": {"events": 4, "alerts": {}},
            },
        },
        "wazuh": [
            {
                "timestamp": signins[0]["createdDateTime"],
                "agent": {"id": "001", "name": "demo-dc-01"},
                "data": {
                    "win": {
                        "system": {
                            "eventID": "4625",
                            "systemTime": signins[0]["createdDateTime"],
                            "computer": "demo-dc-01",
                            "providerName": "Microsoft-Windows-Security-Auditing",
                        },
                        "eventdata": {"targetUserName": "analyst01", "ipAddress": "192.0.2.55"},
                    }
                },
            }
        ],
        "expected": {
            "microsoft_sentinel": {"events": 13, "alerts": {"AUTH-001": 1, "IAM-001": 1}},
            "microsoft_graph": {"events": 13, "alerts": {"AUTH-001": 1, "IAM-001": 1}},
            "windows_wef": {
                "events": len(windows),
                "alerts": {
                    "AUTH-001": 1,
                    "AUTH-002": 1,
                    "PROC-001": 1,
                    "PROC-002": 1,
                    "IAM-001": 1,
                    "DNS-001": 1,
                    "NET-001": 1,
                },
            },
        },
    }


def generate(*, check: bool = False) -> None:
    from app.integrations.payloads import NotificationPayload

    outputs = {
        "microsoft-windows.json": fixtures(),
        "notification.schema.json": NotificationPayload.model_json_schema(),
    }
    for name, value in outputs.items():
        content = json.dumps(value, indent=2) + "\n"
        path = ROOT / name
        if check:
            if not path.exists() or path.read_text() != content:
                raise SystemExit(f"Integration fixture differs from its generator: {name}")
            print(f"Integration fixture matches its deterministic generator: {name}")
        else:
            ROOT.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            print(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    generate(check=args.check)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
