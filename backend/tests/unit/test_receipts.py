from pathlib import Path

from app.core.evidence import source_fingerprint


def test_receipt_fingerprint_is_path_independent_and_ignores_installed_packages(
    tmp_path: Path,
) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    for root in (first, second):
        (root / "backend/app").mkdir(parents=True)
        (root / "backend/app/example.py").write_text("value = 1\n")
    assert source_fingerprint(first) == source_fingerprint(second)
    installed = second / "backend/project.egg-info"
    installed.mkdir()
    (installed / "PKG-INFO").write_text("Environment-specific build metadata")
    modules = second / "frontend/node_modules/dependency"
    modules.mkdir(parents=True)
    (modules / "index.js").write_text("untracked dependency content")
    assert source_fingerprint(first) == source_fingerprint(second)
    (second / "backend/app/example.py").write_text("value = 2\n")
    assert source_fingerprint(first) != source_fingerprint(second)
