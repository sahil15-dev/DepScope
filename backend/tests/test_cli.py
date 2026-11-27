import json
from pathlib import Path

import pytest
from depscope.cli import Exit, main
from depscope.storage.database import sqlite_engine, worker_lock

from .test_phase4 import _affected, _live_scan
from .test_storage import migrate


@pytest.mark.parametrize(
    ("sample", "threshold", "expected", "findings"),
    [
        ("requirements-vulnerable.txt", "high", Exit.OK, 1),
        ("requirements-vulnerable.txt", "medium", Exit.POLICY, 1),
        ("requirements-clean.txt", "low", Exit.OK, 0),
        ("requirements-mixed.txt", "critical", Exit.INCOMPLETE, 1),
        ("requirements-partial.txt", "low", Exit.INCOMPLETE, 2),
    ],
)
def test_scan_policy_json(
    capsys: pytest.CaptureFixture[str],
    sample: str,
    threshold: str,
    expected: Exit,
    findings: int,
) -> None:
    result = main(
        ["scan", f"samples/{sample}", "--offline", "--format", "json", "--fail-on", threshold]
    )
    output = capsys.readouterr()
    assert output.err == ""
    payload = json.loads(output.out)
    assert result == payload["exit_code"] == expected
    assert payload["provenance"] == "offline_fixture"
    assert len(payload["findings"]) == findings


def test_manifest_limits_cli_help_and_output(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = Path("samples/requirements-vulnerable.txt").resolve()
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "report.json"
    args = ["scan", str(sample), "--offline", "--format", "json", "--output", str(output)]
    assert main(args) == Exit.OK
    assert json.loads(capsys.readouterr().out) == json.loads(output.read_text())
    assert main(args) == Exit.OPERATION
    assert capsys.readouterr().err.startswith("export_failed:")
    assert main([*args[:3], "--max-bytes", "1"]) == Exit.INPUT
    assert "input_too_large" in capsys.readouterr().err
    for invalid, code in [(["--help"], 0), (["--version"], 0), (["scan", str(sample)], 2)]:
        with pytest.raises(SystemExit) as end:
            main(invalid)
        assert end.value.code == code
    assert "DepScope 0.5.0" in capsys.readouterr().out


def test_saved_reports_and_baseline_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Copy only the public samples used by the CLI into an isolated workspace.
    samples = tmp_path / "samples"
    samples.mkdir()
    for name in ("clean", "vulnerable", "partial", "mixed"):
        input_file = Path(f"samples/requirements-{name}.txt")
        (samples / input_file.name).write_bytes(input_file.read_bytes())
    path = tmp_path / "scan history #1.sqlite3"
    engine = sqlite_engine(path)
    migrate(engine)
    database = ["--database", str(path), "--format", "json"]
    live_scan = _live_scan(engine, b"alpha==1", _affected())
    engine.dispose()
    monkeypatch.chdir(tmp_path)

    def save(name: str, expected: Exit = Exit.OK) -> str:
        code = main(["scan", f"samples/requirements-{name}.txt", "--offline", "--save", *database])
        captured = capsys.readouterr()
        assert captured.err == "" and code == expected
        identifier: str = json.loads(captured.out)["scan_id"]
        return identifier

    clean, old, same = (save(name) for name in ("clean", "vulnerable", "vulnerable"))
    partial, mixed = (save(name, Exit.INCOMPLETE) for name in ("partial", "mixed"))
    for baseline, target, expected, kind in [
        (clean, old, Exit.POLICY, "newly_detected"),
        (old, same, Exit.OK, "unchanged"),
        (old, clean, Exit.OK, "no_longer_detected"),
        (old, partial, Exit.INCOMPLETE, "unchanged"),
        (mixed, old, Exit.INCOMPLETE, "unchanged"),
    ]:
        args = ["compare", baseline, target, "--fail-on", "medium", *database]
        assert main(args) == expected
        payload = json.loads(capsys.readouterr().out)
        assert payload["exit_code"] == expected
        assert kind in {finding["kind"] for finding in payload["findings"]}
    assert main(["compare", old, live_scan, *database]) == Exit.INPUT
    assert "invalid_pair" in capsys.readouterr().err
    assert main(["history", "--page-size", "1", "--provenance", "offline_fixture", *database]) == 0
    history = json.loads(capsys.readouterr().out)
    assert history["total"] == 5 and len(history["items"]) == 1
    assert main(["report", old, *database]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["scan"]["id"] == old
    assert report["packages"][0]["fixable_count"] == 1
    with worker_lock(path):
        assert main(["history", *database]) == 0
        capsys.readouterr()
        assert (
            main(["scan", "samples/requirements-clean.txt", "--offline", "--save", *database]) == 4
        )
        assert "operation_failed" in capsys.readouterr().err


def test_unknown_severity_blocks_policy_even_when_lookups_complete(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # The published demo includes one discovery-only unknown. An injected live provider
    # reproduces the separate case of hydrated advisory data without supported severity.
    from depscope import cli
    from depscope.models import Assessment, LookupStatus, ManifestFormat, ScanResult
    from depscope.scanner import Scanner

    from .helpers import ALPHA
    from .test_scanner import Provider, _observation

    async def run(*args: object) -> ScanResult:
        provider = Provider(
            Assessment(ALPHA, LookupStatus.COMPLETE, (_observation("TEST-UNKNOWN"),))
        )
        return await Scanner(provider).scan(b"alpha==1", ManifestFormat.REQUIREMENTS)

    monkeypatch.setattr(cli, "run_scan", run)
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("alpha==1")
    args = ["scan", str(manifest), "--offline", "--format", "json"]
    assert main(args) == Exit.OK
    assert json.loads(capsys.readouterr().out)["risk"]["severity_counts"]["unknown"] == 1
    assert main([*args, "--fail-on", "critical"]) == Exit.INCOMPLETE
    assert json.loads(capsys.readouterr().out)["status"] == "complete"


def test_compare_policy_checks_threshold_increases_across_advisory_aliases(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from depscope.models import (
        Assessment,
        Coordinate,
        Ecosystem,
        LookupStatus,
        ManifestFormat,
        Provenance,
    )
    from depscope.storage.models import ScanSource
    from depscope.storage.repository import ScanInput, ScanRepository

    from .test_scanner import _observation, _package

    path = tmp_path / "policy.sqlite3"
    engine = sqlite_engine(path)
    migrate(engine)
    identifiers = []
    for version, identifier, severity in (
        ("1", "CVE-TEST-1", "HIGH"),
        ("2", "GHSA-TEST", "CRITICAL"),
    ):
        observation = _observation(
            identifier,
            aliases=["CVE-TEST-1"] if identifier != "CVE-TEST-1" else [],
            affected=[_package(versions=[version])],
            database_specific={"severity": severity},
        )
        assessment = Assessment(
            Coordinate(Ecosystem.PYPI, "alpha", version), LookupStatus.COMPLETE, (observation,)
        )
        identifiers.append(_live_scan(engine, f"alpha=={version}".encode(), assessment))
    repository = ScanRepository(engine)
    interrupted = repository.create(
        ScanInput(ManifestFormat.REQUIREMENTS, ScanSource.UPLOAD, Provenance.LIVE_OSV)
    )
    repository.fail(interrupted.id, "interrupted")
    engine.dispose()
    monkeypatch.chdir(tmp_path)
    base, target = identifiers
    for threshold, expected in (("high", Exit.OK), ("critical", Exit.POLICY)):
        args = ["compare", base, target, "--database", str(path), "--format", "json"]
        assert main([*args, "--fail-on", threshold]) == expected
        (finding,) = json.loads(capsys.readouterr().out)["findings"]
        assert finding["kind"] == "unchanged"
        assert (finding["before_severity"], finding["after_severity"]) == ("high", "critical")
    assert main(["compare", base, interrupted.id, "--database", str(path)]) == Exit.INCOMPLETE
    assert "scan_result_unavailable" in capsys.readouterr().err
