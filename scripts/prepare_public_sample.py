"""Reproduce a bounded, privacy-reduced OTRF export; never execute archived telemetry."""

import hashlib
import io
import json
import ntpath
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from app.core.safe import json_loads

ROOT = Path(__file__).resolve().parents[1]
REVISION = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
ARCHIVE_PATH = "datasets/atomic/windows/execution/host/cmd_sharpview_pcre_net.zip"
BASE_URL = f"https://raw.githubusercontent.com/OTRF/Security-Datasets/{REVISION}"
CHECKSUM = "314b1d08b9038dd327c8769c82564a44fd26fa1ba17ffa79e52b4683e2821dac"
MEMBER = "cmd_sharpview_pcre_net_2020-10-2920232423.json"


def download(url: str, limit: int) -> bytes:
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 - fixed HTTPS URLs
        result = response.read(limit + 1)
    if len(result) > limit:
        raise ValueError("Public source exceeds its documented size limit")
    return result


def adapt(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    names: dict[str, str] = {}
    addresses: dict[str, str] = {}
    for ordinal, row in enumerate(records):
        code = row.get("EventID")
        if code not in {1, 3, 22, 4688}:
            continue
        provider = row.get("SourceName")
        if code in {1, 3, 22} and provider != "Microsoft-Windows-Sysmon":
            raise ValueError("Ambiguous event provider in the selected public source")
        payload: dict[str, Any] = {}
        for key in ("Image", "NewProcessName", "ParentImage", "ParentProcessName"):
            if row.get(key):
                payload[key] = "C:\\Lab\\" + ntpath.basename(row[key])
        if row.get("User") or row.get("SubjectUserName"):
            payload["User"] = "PUBLICLAB\\operator01"
        if row.get("QueryName"):
            name = row["QueryName"]
            names.setdefault(name, f"service{len(names) + 1}.example.test")
            payload["QueryName"] = names[name]
        for key in ("SourceIp", "DestinationIp"):
            if row.get(key):
                value = row[key]
                addresses.setdefault(value, f"192.0.2.{10 + len(addresses)}")
                payload[key] = addresses[value]
        for key in ("SourcePort", "DestinationPort", "Protocol"):
            if row.get(key) is not None:
                payload[key] = row[key]
        result.append(
            {
                "System": {
                    "EventID": code,
                    "Provider": {"Name": provider},
                    "TimeCreated": {"SystemTime": row["TimeCreated"]},
                    "Computer": "public-lab-01",
                    "EventRecordID": ordinal,
                },
                "EventData": payload,
                "PublicAdapter": {
                    "source_row": ordinal,
                    "modified": True,
                    "scope": "privacy-reduced export; not byte-for-byte upstream evidence",
                },
            }
        )
    return result


def main() -> None:
    content = download(f"{BASE_URL}/{ARCHIVE_PATH}", 40_000)
    if hashlib.sha256(content).hexdigest() != CHECKSUM:
        raise ValueError("Pinned public archive checksum differs")
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        info = archive.getinfo(MEMBER)
        if info.file_size > 1_000_000:
            raise ValueError("Public archive expands beyond 1 MB")
        raw = archive.read(info)
    records = [json_loads(line.decode("utf-8")) for line in raw.splitlines() if line.strip()]
    if len(records) != 267:
        raise ValueError("Pinned public source record count differs")
    sample = adapt(records)
    if len(sample) != 6:
        raise ValueError("Curated public subset no longer has the expected six source events")
    destination = ROOT / "test-data" / "public"
    destination.mkdir(exist_ok=True)
    text = json.dumps(sample, indent=2) + "\n"
    (destination / "otrf_adapted.json").write_text(text)
    license_text = download(f"{BASE_URL}/LICENSE", 16_000).decode()
    if "MIT License" not in license_text or "Open Threat Research Forge" not in license_text:
        raise ValueError("Pinned upstream license no longer matches the verified MIT notice")
    (destination / "LICENSE.OTRF").write_text(license_text)
    provenance = {
        "dataset": "OTRF Security Datasets: cmd_sharpview_pcre_net",
        "source_url": f"https://github.com/OTRF/Security-Datasets/blob/{REVISION}/{ARCHIVE_PATH}",
        "download_url": f"{BASE_URL}/{ARCHIVE_PATH}",
        "revision": REVISION,
        "obtained": "2026-09-27",
        "license": "MIT at the pinned root LICENSE",
        "license_url": f"{BASE_URL}/LICENSE",
        "license_caveat": (
            "The root LICENSE and README badge identify MIT. The same README has an older "
            "GPL-3.0 footer. This small sample relies on the explicit root MIT license "
            "at the recorded revision; the discrepancy is disclosed, not erased."
        ),
        "source_archive_sha256": CHECKSUM,
        "source_archive_bytes": len(content),
        "source_member": MEMBER,
        "source_records": len(records),
        "included_records": len(sample),
        "included_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "source_context": "Public controlled attack-simulation lab, not benign enterprise traffic.",
        "preprocessing": [
            "Select EventID 1, 3, 22 and 4688 only; discard unsupported event categories.",
            "Wrap flat SourceName, EventID and TimeCreated "
            "into explicit Windows provider envelopes.",
            "Retain source row index, EventID, TimeCreated, process basenames, ports and protocol.",
            "Use TimeCreated with explicit Z, not the source's discrepant timezone-naive UtcTime.",
            "Replace hosts and users; map IPs to TEST-NET-1 and DNS names to .test consistently.",
            "Replace path prefixes with C:\\Lab; retain process/parent basenames.",
            "Omit Message, command-line arguments, SID/GUID/hash/domain fields "
            "and every unlisted field.",
            "Raw evidence in SentinelFlow is this adapted export, NOT untouched upstream evidence.",
        ],
        "validation_scope": (
            "Parser interoperability and evidence preservation after explicit adaptation only. "
            "Zero included-rule matches are expected and do not establish benignness, "
            "attack detection success, or a false-positive rate."
        ),
    }
    (destination / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    manifest = [
        {
            "id": "public-otrf-adapted",
            "path": "public/otrf_adapted.json",
            "name": "Privacy-reduced public lab telemetry (parser interoperability)",
            "format": "windows",
            "event_count": len(sample),
            "expected": [],
            "kind": "public",
            "synthetic": False,
            "source": "OTRF public lab; adapted; see public/provenance.json",
            "license": "MIT at pinned revision (README caveat documented)",
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
        }
    ]
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(
        f"Verified {len(content)} archive bytes, {len(records)} source rows; "
        f"saved {len(sample)} adapted rows."
    )


if __name__ == "__main__":
    main()
