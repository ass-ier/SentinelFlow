"""Copy locked, licensed Swagger assets for an offline Python-only deployment."""

import argparse
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "swagger-ui-bundle.js",
    "swagger-ui-bundle.js.LICENSE.txt",
    "swagger-ui.css",
    "LICENSE",
    "NOTICE",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    source = ROOT / "frontend/node_modules/swagger-ui-dist"
    target = ROOT / "backend/app/static/swagger"
    package = json.loads((source / "package.json").read_text())
    lock = json.loads((ROOT / "frontend/package-lock.json").read_text())
    locked = lock["packages"]["node_modules/swagger-ui-dist"]
    if package["version"] != locked["version"]:
        raise SystemExit("Installed Swagger version differs from the npm lock")
    files = {name: digest(source / name) for name in FILES}
    manifest = {
        "name": "swagger-ui-dist",
        "version": package["version"],
        "license": package["license"],
        "source": locked["resolved"],
        "integrity": locked["integrity"],
        "files": files,
        "generated_by": "scripts/vendor_swagger.py",
    }
    if args.check:
        if json.loads((target / "provenance.json").read_text()) != manifest:
            raise SystemExit("Swagger provenance is stale; rerun scripts/vendor_swagger.py")
        if any(digest(target / name) != value for name, value in files.items()):
            raise SystemExit("Shipped Swagger assets differ from the locked package")
    else:
        target.mkdir(parents=True, exist_ok=True)
        for name in FILES:
            shutil.copyfile(source / name, target / name)
        (target / "provenance.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Verified offline Swagger UI {package['version']}: {len(files)} licensed assets")


if __name__ == "__main__":
    main()
