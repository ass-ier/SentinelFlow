import importlib
import io
import json
import subprocess
import sys
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.config import ROOT

pytestmark = [pytest.mark.security, pytest.mark.regression]


@pytest.fixture
def gate(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("security_scan")


@pytest.mark.parametrize(
    ("function", "value"),
    [
        ("audit_python", {}),
        ("audit_python", {"dependencies": []}),
        ("audit_python", {"dependencies": [{"name": "unknown", "skip_reason": "unavailable"}]}),
        ("audit_node", {"error": "registry unavailable"}),
        ("audit_node", {"vulnerabilities": {}, "metadata": {"dependencies": {"total": 0}}}),
        ("audit_osv", {"results": []}),
        ("audit_osv", {"results": [{"packages": []}]}),
        ("trivy_findings", {}),
        ("trivy_findings", {"Results": [{"Target": "empty", "Vulnerabilities": []}]}),
    ],
)
def test_missing_or_unavailable_scans_never_count_as_clean(gate, function, value) -> None:
    with pytest.raises(RuntimeError):
        getattr(gate, function)(value)


def test_known_dependency_finding_is_retained_without_severity_suppression(gate) -> None:
    result = gate.audit_python(
        {
            "dependencies": [
                {"name": "synthetic-library", "version": "1.0", "vulns": [{"id": "TEST-001"}]}
            ]
        }
    )
    assert result == [{"package": "synthetic-library", "version": "1.0", "id": "TEST-001"}]


def test_incomplete_python_dependency_coverage_is_not_a_clean_result(gate) -> None:
    data = {"dependencies": [{"name": "synthetic-library", "version": "1.0", "vulns": []}]}
    with pytest.raises(RuntimeError, match="expected lock"):
        gate.audit_python(data, {"another-required-library": "2.0"})


def test_new_secret_match_is_blocking_even_when_named_like_a_test(gate) -> None:
    result = gate.secret_triage(
        [{"Fingerprint": "new", "File": "backend/tests/example.py", "StartLine": 1}], history=False
    )
    assert result[0]["status"] == "Release blocker"


@pytest.mark.parametrize("value", ["", '""', '"synthetic-nonempty-must-still-block"'])
def test_historical_secret_review_requires_actual_empty_assignment(
    gate, monkeypatch, value: str
) -> None:
    text = "\n" * 30 + f"SENTINEL_CLIENT_SECRET={value}\nSENTINEL_POLL_INTERVAL_SECONDS=60\n"
    monkeypatch.setattr(gate.subprocess, "check_output", lambda *_args, **_kwargs: text)
    finding = {
        "Fingerprint": "reviewed-template",
        "Commit": "27d1d39bb5fb6a14baf089f7e91ba727bcd152d7",
        "File": ".env.example",
        "RuleID": "generic-api-key",
        "StartLine": 31,
        "EndLine": 32,
    }
    expected = "False positive" if value in {"", '""'} else "Release blocker"
    assert gate.secret_triage([finding], history=True)[0]["status"] == expected


@pytest.mark.parametrize("history", [False, True])
@pytest.mark.parametrize(
    "relative",
    [
        "docs/results/security/final/image-backend.json",
        "backend/tests/security/test_release_gate.py",
    ],
)
@pytest.mark.parametrize(
    ("value", "match", "expected"),
    [
        (
            "7169605F62C751356D054A26A821E680E5FA6305",
            'GPG_KEY=REDACTED"',
            "False positive",
        ),
        ("A" * 40, 'GPG_KEY=REDACTED"', "Release blocker"),
        (
            "7169605F62C751356D054A26A821E680E5FA6305",
            'SENTINEL_API_TOKEN=REDACTED"',
            "Release blocker",
        ),
    ],
)
def test_image_key_review_requires_the_exact_public_value_and_match(
    gate, monkeypatch, tmp_path: Path, history, relative, value, match, expected
) -> None:
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    text = f'"GPG_KEY={value}",\n'
    path.write_text(text)
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    monkeypatch.setattr(gate.subprocess, "check_output", lambda *_args, **_kwargs: text)
    finding = {
        "Fingerprint": "public-key-metadata",
        "Commit": "b987e6d7526b9a643bf9813fe816ada21c706b55",
        "File": relative,
        "RuleID": "generic-api-key",
        "Match": match,
        "StartLine": 1,
        "EndLine": 1,
    }
    assert gate.secret_triage([finding], history=history)[0]["status"] == expected


@pytest.mark.parametrize("absolute", [False, True])
def test_image_key_review_reads_the_actual_scanned_snapshot(
    gate, monkeypatch, tmp_path: Path, absolute
) -> None:
    relative = "docs/results/security/final/image-backend.json"
    snapshot = tmp_path / "scan"
    path = snapshot / relative
    path.parent.mkdir(parents=True)
    path.write_text('"GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305",\n')
    monkeypatch.setattr(gate, "ROOT", tmp_path / "different-worktree")
    finding = {
        "Fingerprint": "snapshot-public-key",
        "File": str(path) if absolute else relative,
        "RuleID": "generic-api-key",
        "Match": 'GPG_KEY=REDACTED"',
        "StartLine": 1,
        "EndLine": 1,
    }
    assert (
        gate.secret_triage([finding], history=False, source_root=snapshot)[0]["status"]
        == "False positive"
    )
    path.write_text('"GPG_KEY=unreviewed-value",\n')
    assert (
        gate.secret_triage([finding], history=False, source_root=snapshot)[0]["status"]
        == "Release blocker"
    )


def test_historical_security_archives_are_not_container_runtime_dependencies() -> None:
    assert "docs/results/security" in (ROOT / ".dockerignore").read_text().splitlines()
    assert "COPY docs ./docs" in (ROOT / "Dockerfile").read_text()


def test_sast_review_stops_applying_when_source_changes(gate, tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("synthetic first version\n")
    report = {
        "errors": [],
        "results": [
            {"filename": "app.py", "line_number": 1, "test_id": "B999", "issue_severity": "HIGH"}
        ],
    }
    initial = gate.triage_sast("bandit", report, tmp_path, {})
    assert initial[0]["status"] == "Release blocker"
    reviews = {
        initial[0]["id"]: {"status": "Not applicable", "reason": "Test-only source-bound review"}
    }
    assert gate.triage_sast("bandit", report, tmp_path, reviews)[0]["status"] == "Not applicable"
    source.write_text("changed implementation\n")
    assert gate.triage_sast("bandit", report, tmp_path, reviews)[0]["status"] == "Release blocker"


def test_command_failure_and_missing_binary_are_recorded_without_a_success_receipt(
    gate, tmp_path: Path
) -> None:
    assessment = gate.Assessment(tmp_path / "failed-command")
    with pytest.raises(RuntimeError, match="exited 7"):
        assessment.run("failure", [sys.executable, "-c", "raise SystemExit(7)"])
    assert assessment.report["commands"][-1]["exit_code"] == 7
    with pytest.raises(FileNotFoundError):
        assessment.run("missing", [str(tmp_path / "does-not-exist")])
    assert "error" in assessment.report["commands"][-1]
    assert json.loads((assessment.output / "summary.json").read_text())["status"] == "RUNNING"
    assert assessment.finish()["status"] == "BLOCKED"


def test_scanner_artifacts_and_local_environment_snapshot_are_owner_only(
    gate, monkeypatch, tmp_path: Path
) -> None:
    assessment = gate.Assessment(tmp_path / "private-assessment")
    source = tmp_path / "source-input"
    source.mkdir()
    (source / ".env").write_text("SENTINEL_CLIENT_SECRET=synthetic\n")
    monkeypatch.setattr(gate, "ROOT", source)
    monkeypatch.setattr(gate.subprocess, "check_output", lambda *_args, **_kwargs: b"")
    snapshot = assessment.snapshot()
    assert (snapshot / ".env").read_text() == "SENTINEL_CLIENT_SECRET=synthetic\n"
    assert assessment.output.stat().st_mode & 0o077 == 0
    assert snapshot.stat().st_mode & 0o077 == 0


def test_stale_or_failed_validation_receipt_is_refused(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    release = importlib.import_module("security_release")
    path = tmp_path / "receipt.json"
    for value in (
        {"status": "failed", "source_fingerprint": "current"},
        {"status": "validated", "source_fingerprint": "old"},
    ):
        path.write_text(json.dumps(value))
        with pytest.raises(RuntimeError, match="stale"):
            release.verify_receipt(path, "current", "validated")


@pytest.mark.parametrize(
    "script",
    ["validate.py", "verify_deployment.py", "security_release.py", "container_security_probe.py"],
)
def test_verification_refuses_disabled_assertions(script: str) -> None:
    result = subprocess.run(  # noqa: S603 - fixed local scripts; exits before mutating evidence.
        [sys.executable, "-O", str(ROOT / "scripts" / script)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode != 0
    assert "assertions" in result.stderr


@pytest.fixture
def container_probe(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    probe = importlib.import_module("container_security_probe")
    failures, sleeps, clock = [], [], [0.0]
    counts = {"microsoft_sentinel": (13, 2), "microsoft_graph": (13, 2), "windows_wef": (36, 7)}

    class Response(io.BytesIO):
        status = 200

    def sleep(delay):
        sleeps.append(delay)
        clock[0] += delay

    def urlopen(request, timeout):
        assert timeout == 30
        if request.full_url.endswith("/integrations/demo"):
            if failures:
                status, code = failures.pop(0)
                raise urllib.error.HTTPError(
                    request.full_url,
                    status,
                    "Synthetic probe response",
                    {},
                    io.BytesIO(json.dumps({"error": {"code": code}}).encode()),
                )
            source = json.loads(request.data)["source"]
            events, alerts = counts[source]
            data = {
                "events_processed": events,
                "run_id": source,
                "deliveries": [{"id": f"{source}-{index}"} for index in range(alerts)],
            }
        elif "/alerts?run_id=" in request.full_url:
            data = {"total": counts[request.full_url.split("=")[-1]][1]}
        else:
            assert "/notifications/deliveries/" in request.full_url
            data = {"id": request.full_url.rsplit("/", 1)[-1], "status": "delivered"}
        return Response(json.dumps(data).encode())

    monkeypatch.setattr(probe.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(probe, "time", SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep))
    monkeypatch.setattr(
        probe,
        "os",
        SimpleNamespace(
            getenv=lambda _key, default: default,
            environ={"SENTINEL_API_TOKEN": "synthetic-local-probe"},
            getuid=lambda: 10001,
            statvfs=lambda _path: SimpleNamespace(f_flag=1),
            ST_RDONLY=1,
        ),
    )
    monkeypatch.setattr(
        probe,
        "Path",
        lambda _path: SimpleNamespace(
            read_text=lambda: "CapEff:\t0000000000000000\nNoNewPrivs:\t1\n",
            exists=lambda: False,
        ),
    )
    monkeypatch.setattr(
        probe, "importlib", SimpleNamespace(util=SimpleNamespace(find_spec=lambda _name: None))
    )
    return SimpleNamespace(module=probe, failures=failures, sleeps=sleeps)


def test_container_probe_respects_rate_and_lease_limits(container_probe, capsys) -> None:
    container_probe.failures.extend([(409, "integration_busy"), (429, "integration_rate_limit")])
    container_probe.module.main()
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "passed"
    assert result["rate_limit_enforced_and_recovered"] is True
    assert result["retries"] == {"integration_busy": 1, "integration_rate_limit": 1}
    assert len(result["flows"]) == 3
    assert container_probe.sleeps == [1, 61]


@pytest.mark.parametrize(
    ("status", "code"),
    [(401, "auth_required"), (409, "unexpected_conflict"), (429, "unknown_limit"), (500, "error")],
)
def test_container_probe_never_retries_unexpected_errors(container_probe, status, code) -> None:
    container_probe.failures.append((status, code))
    with pytest.raises(RuntimeError, match=f"HTTP {status}"):
        container_probe.module.main()
    assert container_probe.sleeps == []


def test_container_probe_retries_have_a_real_deadline(container_probe) -> None:
    container_probe.failures.extend([(429, "integration_rate_limit")] * 2)
    with pytest.raises(RuntimeError, match="retry deadline exhausted"):
        container_probe.module.main()
    assert container_probe.sleeps == [61]


def test_container_probe_fails_if_rate_enforcement_is_not_observed(container_probe) -> None:
    with pytest.raises(AssertionError):
        container_probe.module.main()
