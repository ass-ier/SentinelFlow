"""Record exact hashes of unchanged, locally saved licensed upstream rules."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REVISION = "07ec293a51695cb1131a2e05260247872b31e1e1"
LICENSE_REVISION = "bcbdc605172d00390572cd774ba395ec9e975dfc"


def main() -> None:
    base = ROOT / "test-data" / "sigma"
    records = []
    for filename, dataset, author in [
        (
            "proc_creation_win_powershell_download_iex.yml",
            "sigma-download",
            "Florian Roth (Nextron Systems)",
        ),
        ("proc_creation_win_powershell_encode.yml", "sigma-encoded", "frack113"),
    ]:
        path = base / "rules" / filename
        records.append(
            {
                "path": f"rules/{filename}",
                "source_url": f"https://github.com/SigmaHQ/sigma/blob/{REVISION}/rules/windows/process_creation/{filename}",
                "download_url": f"https://raw.githubusercontent.com/SigmaHQ/sigma/{REVISION}/rules/windows/process_creation/{filename}",
                "revision": REVISION,
                "obtained": "2026-09-27",
                "license": "DRL-1.1",
                "license_url": f"https://github.com/SigmaHQ/Detection-Rule-License/blob/{LICENSE_REVISION}/LICENSE.Detection.Rules.md",
                "author": author,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "preprocessing": "None; upstream rule bytes are preserved unchanged.",
                "dataset_id": dataset,
            }
        )
    (base / "provenance.json").write_text(json.dumps(records, indent=2) + "\n")
    print(f"Recorded exact provenance for {len(records)} unchanged Sigma rules.")


if __name__ == "__main__":
    main()
