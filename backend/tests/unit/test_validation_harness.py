import importlib
import io
import sys

import pytest


def test_failed_subprocess_cannot_be_reported_as_success() -> None:
    validator = importlib.import_module("scripts.validate")
    report = {"steps": []}
    log = io.StringIO()
    with pytest.raises(RuntimeError, match="exit status 7"):
        validator.execute(
            "Intentional harness failure",
            [sys.executable, "-c", "print('intentional failure'); raise SystemExit(7)"],
            report,
            log,
        )
    assert report["steps"][0]["status"] == "failed"
    assert report["steps"][0]["exit_code"] == 7
    assert "intentional failure" in log.getvalue()
