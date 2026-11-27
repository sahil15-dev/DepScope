import asyncio
import json
from collections.abc import Iterable
from pathlib import Path

import pytest
from depscope.__main__ import main
from depscope.advisories import parse_advisory
from depscope.demo import FixtureProvider
from depscope.matching import match_assessment
from depscope.models import (
    Assessment,
    Coordinate,
    Discovery,
    Ecosystem,
    LookupStatus,
    ManifestFormat,
    Observation,
    Provenance,
    Severity,
)
from depscope.scanner import Scanner
from depscope.scoring import summarize_risk
from depscope.serialization import to_json

from .helpers import ALPHA, BETA, NOW, advisory

SAMPLES = Path("samples")


class Provider:
    provenance = Provenance.OFFLINE_FIXTURE

    def __init__(self, *items: Assessment) -> None:
        self.items = items
        self.asked: tuple[Coordinate, ...] | None = None

    async def lookup(self, coordinates: Iterable[Coordinate]) -> tuple[Assessment, ...]:
        self.asked = tuple(coordinates)
        return self.items


def _observation(identifier: str, name: str = "alpha", **fields: object) -> Observation:
    return Observation(
        Discovery(identifier, NOW), parse_advisory(advisory(identifier, name, **fields), identifier)
    )


def test_aliases_group_exact_matches_and_keep_related_advisories_separate() -> None:
    items = (
        _observation("GHSA-A", aliases=["CVE-A", "CVE-B"], database_specific={"severity": "HIGH"}),
        _observation("GHSA-B", aliases=["CVE-B"]),
        _observation("GHSA-C", related=["CVE-A"], upstream=["GHSA-A"]),
        _observation("GHSA-D", "different", aliases=["CVE-A"]),
        Observation(Discovery("CVE-A", None), error="request_failed"),
    )
    status, findings = match_assessment(Assessment(ALPHA, LookupStatus.PARTIAL, items))
    assert status.status is LookupStatus.PARTIAL
    assert "advisory_scope_unconfirmed" in status.diagnostics
    assert len(findings) == 3
    combined = next(f for f in findings if f.advisory_id == "GHSA-A")
    assert combined.observed_ids == ("CVE-A", "GHSA-A", "GHSA-B")
    assert combined.aliases == ("CVE-A", "CVE-B", "GHSA-B")
    assert combined.priority.severity is Severity.HIGH
    assert combined.priority.severity_advisory_id == "GHSA-A"
    ambiguous = next(f for f in findings if f.advisory_id == "GHSA-D")
    assert ambiguous.aliases == ()
    assert ambiguous.evidence_level == "discovery_only" and not ambiguous.fixes


def test_withdrawn_records_remain_observable_without_affecting_risk() -> None:
    withdrawn = "2025-01-01T00:00:00Z"
    provider = Provider(
        Assessment(
            ALPHA, LookupStatus.COMPLETE, (_observation("TEST-WITHDRAWN", withdrawn=withdrawn),)
        )
    )
    result = asyncio.run(
        Scanner(provider).scan(b"alpha==1.0\nalpha>=1", ManifestFormat.REQUIREMENTS)
    )
    assert not result.findings and result.risk.index == 0
    assert result.coverage.unresolved_occurrences == 1 and provider.asked == (ALPHA,)
    assert result.assessments[0].diagnostics == ("withdrawn_advisory_ignored",)
    document = json.loads(to_json(result))
    assert document["advisories"]["TEST-WITHDRAWN"]["withdrawn"] == withdrawn
    assert document["observed_at"].endswith("Z")


@pytest.mark.parametrize(
    ("scheme", "vector", "score", "severity"),
    [
        ("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, Severity.CRITICAL),
        ("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, Severity.NONE),
        (
            "CVSS_V4",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U",
            9.3,
            Severity.CRITICAL,
        ),
        ("CVSS_V2", "AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0, Severity.HIGH),
        ("CVSS_V3", "CVSS:3.1/AV:N", None, Severity.UNKNOWN),
        ("CVSS_V4", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", None, Severity.UNKNOWN),
    ],
)
def test_cvss_evidence_preserves_vectors_and_numeric_provenance(
    scheme: str,
    vector: str,
    score: float | None,
    severity: Severity,
) -> None:
    data = advisory("TEST-1", severity=[{"type": scheme, "score": vector, "source": "upstream"}])
    (evidence,) = parse_advisory(data, "TEST-1").severity
    assert (evidence.scheme, evidence.vector, evidence.score, evidence.severity) == (
        scheme,
        vector,
        score,
        severity,
    )
    assert evidence.upstream_source == "upstream"
    assert evidence.score_basis == ("base_vector" if score is not None else None)


def _package(
    *, name: str = "alpha", ecosystem: str = "PyPI", **fields: object
) -> dict[str, object]:
    return {"package": {"name": name, "ecosystem": ecosystem}, **fields}


def _range(*events: dict[str, str], kind: str = "ECOSYSTEM") -> dict[str, object]:
    return {"type": kind, "events": list(events)}


def test_applicable_range_and_scoped_severity_precede_global_evidence() -> None:
    matched = _package(
        name="Alpha",
        ecosystem_specific={"severity": "LOW"},
        ranges=[
            _range({"fixed": "4.0"}, {"introduced": "2.0"}, {"fixed": "1.5"}, {"introduced": "0"})
        ],
    )
    other_branch = _package(
        ranges=[_range({"introduced": "8"}, {"fixed": "9"})],
        database_specific={"severity": "CRITICAL"},
    )
    other_name = _package(name="other", ranges=[_range({"introduced": "0"}, {"fixed": "99"})])
    observation = _observation(
        "TEST-1",
        affected=[matched, other_branch, other_name],
        database_specific={"severity": "HIGH"},
    )
    coordinate = Coordinate(Ecosystem.PYPI, "alpha", "3")
    _, (finding,) = match_assessment(Assessment(coordinate, LookupStatus.COMPLETE, (observation,)))
    assert [item.version for item in finding.fixes] == ["4.0"]
    assert finding.fixes[0].introduced == "2.0"
    assert finding.priority.severity is Severity.LOW
    assert finding.priority.severity_evidence is not None
    assert finding.priority.severity_evidence.source == "affected.ecosystem_specific.severity"


def test_aliased_advisory_can_contradict_a_fix() -> None:
    primary = _observation(
        "TEST-1",
        aliases=["TEST-2"],
        affected=[
            _package(ranges=[_range({"introduced": "0"}, {"fixed": "2"})]),
        ],
    )
    contradictory = _observation("TEST-2", affected=[_package(versions=["1", "2"])])
    _, (finding,) = match_assessment(
        Assessment(ALPHA, LookupStatus.COMPLETE, (contradictory, primary))
    )
    assert finding.observed_ids == ("TEST-1", "TEST-2")
    assert not finding.fixes and not finding.priority.fix_available


@pytest.mark.parametrize(
    ("ranges", "versions", "fixes", "status"),
    [
        ([_range({"introduced": "0"}, {"last_affected": "1"})], [], [], LookupStatus.COMPLETE),
        (
            [_range({"introduced": "0"}, {"fixed": "2"}, {"limit": "1"})],
            [],
            [],
            LookupStatus.PARTIAL,
        ),
        (
            [_range({"introduced": "0"}, {"fixed": "2"}, {"limit": "1.5"})],
            [],
            [],
            LookupStatus.COMPLETE,
        ),
        (
            [_range({"introduced": "0"}, {"fixed": "2"}, {"limit": "*"})],
            [],
            ["2"],
            LookupStatus.COMPLETE,
        ),
        (
            [_range({"introduced": "0"}, {"fixed": "2"}, {"limit": "0.8"}, {"limit": "2"})],
            [],
            ["2"],
            LookupStatus.COMPLETE,
        ),
        ([_range({"introduced": "0"}, {"fixed": "2"})], ["2.0"], [], LookupStatus.COMPLETE),
        (
            [_range({"introduced": "a"}, {"fixed": "b"}, kind="GIT")],
            ["1.0"],
            [],
            LookupStatus.COMPLETE,
        ),
        (
            [_range({"introduced": "0"}, {"fixed": "2"}, {"last_affected": "3"})],
            [],
            [],
            LookupStatus.PARTIAL,
        ),
        ([_range({"fixed": "2"})], [], [], LookupStatus.PARTIAL),
        ([_range({"introduced": "0"}, {"unknown": "2"})], [], [], LookupStatus.PARTIAL),
        ([_range({"introduced": "0"}, {"fixed": "invalid-version"})], [], [], LookupStatus.PARTIAL),
        ([_range({"introduced": "0"}, {"introduced": "2"})], [], [], LookupStatus.PARTIAL),
        ([_range({"introduced": "0"})], [], [], LookupStatus.COMPLETE),
    ],
)
def test_fix_evidence_requires_an_applicable_unambiguous_fixed_boundary(
    ranges: list[dict[str, object]],
    versions: list[str],
    fixes: list[str],
    status: LookupStatus,
) -> None:
    observation = _observation("TEST-1", affected=[_package(ranges=ranges, versions=versions)])
    row, (finding,) = match_assessment(Assessment(ALPHA, LookupStatus.COMPLETE, (observation,)))
    assert row.status is status
    assert [item.version for item in finding.fixes] == fixes


def test_untrusted_references_are_filtered_and_authoritative_links_are_retained() -> None:
    references = [
        {"type": "WEB", "url": "javascript:alert(1)"},
        {"type": "WEB", "url": "https://user@invalid.invalid/secret"},
        {"type": "WEB", "url": "https://[malformed"},
        {"type": "WEB", "url": "https://invalid.invalid/with space"},
        {"type": "EVIDENCE", "url": "https://invalid.invalid/evidence"},
        {"type": "ADVISORY", "url": "https://example.test/correct"},
    ]
    result = parse_advisory(advisory("TEST-1", references=references), "TEST-1")
    assert [item.url for item in result.references] == [
        "https://example.test/correct",
        "https://osv.dev/vulnerability/TEST-1",
    ]


def test_scoring_is_deterministic_and_coalesces_identical_versions() -> None:
    observations = (
        _observation("TEST-1", database_specific={"severity": "HIGH"}),
        _observation(
            "TEST-2",
            database_specific={"severity": "HIGH"},
            affected=[
                _package(ranges=[_range({"introduced": "0"}, {"fixed": "2"})]),
            ],
        ),
        _observation("TEST-3"),
    )
    provider = Provider(Assessment(ALPHA, LookupStatus.COMPLETE, observations))
    reverse = Provider(Assessment(ALPHA, LookupStatus.COMPLETE, observations[::-1]))
    payload = b"alpha==1.0\nALPHA==1.0.0\nalpha>1\n"
    result = asyncio.run(Scanner(provider).scan(payload, ManifestFormat.REQUIREMENTS))
    reversed_result = asyncio.run(Scanner(reverse).scan(payload, ManifestFormat.REQUIREMENTS))
    assert result.findings == reversed_result.findings
    assert [item.advisory_id for item in result.findings] == ["TEST-2", "TEST-1", "TEST-3"]
    assert result.risk.index == 20
    assert result.risk.severity_counts[Severity.UNKNOWN] == 1
    assert result.coverage.occurrences == 3 and result.coverage.exact_coordinates == 1
    assert summarize_risk([result.findings[0]] * 20, 1).index == 100
    assert summarize_risk([result.findings[-1]], 1).index is None


@pytest.mark.parametrize(
    "rows",
    [
        (),
        (Assessment(BETA, LookupStatus.COMPLETE),),
        (
            Assessment(ALPHA, LookupStatus.COMPLETE),
            Assessment(ALPHA, LookupStatus.COMPLETE),
        ),
    ],
)
def test_absent_or_uncorrelated_provider_rows_cannot_be_reported_as_clean(
    rows: tuple[Assessment, ...],
) -> None:
    result = asyncio.run(Scanner(Provider(*rows)).scan(b"alpha==1", ManifestFormat.REQUIREMENTS))
    assert result.status is LookupStatus.FAILED and result.risk.index is None
    assert result.assessments[0].diagnostics == ("uncorrelated_provider_result",)


def test_unresolved_only_scan_skips_osv_and_risk_is_unavailable() -> None:
    provider = Provider()
    result = asyncio.run(Scanner(provider).scan(b"alpha>=1\nbeta", ManifestFormat.REQUIREMENTS))
    assert provider.asked is None
    assert result.coverage.unresolved_occurrences == 2
    assert result.status is LookupStatus.COMPLETE and result.risk.index is None
    assert "no_exact_versions" in result.limitations


def test_export_reuses_advisory_data_across_multiple_coordinates() -> None:
    shared = _observation(
        "TEST-1", affected=[_package(versions=["1"]), _package(name="beta", versions=["2"])]
    )
    provider = Provider(
        Assessment(ALPHA, LookupStatus.COMPLETE, (shared,)),
        Assessment(BETA, LookupStatus.COMPLETE, (shared,)),
    )
    result = asyncio.run(Scanner(provider).scan(b"alpha==1\nbeta==2", ManifestFormat.REQUIREMENTS))
    payload = json.loads(to_json(result))
    assert payload["schema_version"] == 1
    assert payload["findings"][0]["priority"]["severity"] == "unknown"
    assert len(payload["advisories"]) == 1
    assert len(payload["assessments"]) == 2
    assert payload["assessments"][1]["observations"][0]["advisory_id"] == "TEST-1"


@pytest.mark.parametrize(
    ("filename", "kind", "status", "count", "risk"),
    [
        ("requirements-vulnerable.txt", ManifestFormat.REQUIREMENTS, LookupStatus.COMPLETE, 1, 4),
        ("requirements-clean.txt", ManifestFormat.REQUIREMENTS, LookupStatus.COMPLETE, 0, 0),
        ("requirements-mixed.txt", ManifestFormat.REQUIREMENTS, LookupStatus.COMPLETE, 1, 4),
        ("requirements-partial.txt", ManifestFormat.REQUIREMENTS, LookupStatus.PARTIAL, 2, 4),
        ("package-lock-vulnerable.json", ManifestFormat.NPM_LOCK, LookupStatus.COMPLETE, 1, 10),
    ],
)
def test_reproducible_bundled_demo(
    filename: str, kind: ManifestFormat, status: LookupStatus, count: int, risk: int
) -> None:
    scanner = Scanner(FixtureProvider(SAMPLES / "osv.json"))
    result = asyncio.run(scanner.scan((SAMPLES / filename).read_bytes(), kind))
    assert (result.provenance, result.status, len(result.findings), result.risk.index) == (
        Provenance.OFFLINE_FIXTURE,
        status,
        count,
        risk,
    )
    assert "bundled_fixture_subset" in result.limitations


def test_unknown_offline_coordinate_is_unassessed() -> None:
    provider = FixtureProvider(SAMPLES / "osv.json")
    result = asyncio.run(Scanner(provider).scan(b"offline-missing==1", ManifestFormat.REQUIREMENTS))
    assert result.status is LookupStatus.FAILED and result.risk.index is None
    assert result.assessments[0].diagnostics == ("fixture_coordinate_unavailable",)


def test_developer_interface_summary_json_and_exclusive_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "report.json"
    args = [str(SAMPLES / "requirements-vulnerable.txt"), "--offline", "--json", str(output)]
    assert main(args) == 0
    summary = capsys.readouterr().out
    assert "offline_fixture | complete" in summary and "GHSA-h5c8-rqwp-cp95" in summary
    original = output.read_text(encoding="utf-8")
    document = json.loads(original)
    assert document["findings"][0]["fixes"][0]["version"] == "3.1.3"
    assert main(args) == 2
    assert "export_failed" in capsys.readouterr().err
    assert output.read_text(encoding="utf-8") == original


def test_developer_interface_error_codes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(SAMPLES / "requirements-partial.txt"), "--offline"]) == 1
    assert main([str(SAMPLES / "package-lock-malformed.json"), "--offline"]) == 2
    assert "invalid_lockfile" in capsys.readouterr().err
    assert main(["unsupported.data", "--offline"]) == 2
    assert "unsupported_format" in capsys.readouterr().err
    assert main(["missing.data", "--format", "requirements", "--offline"]) == 2
    assert "unreadable_manifest" in capsys.readouterr().err
    monkeypatch.setenv("DEPSCOPE_MAX_FILE_BYTES", "0")
    assert main([str(SAMPLES / "requirements-clean.txt"), "--offline"]) == 2
    assert "invalid_file_limit" in capsys.readouterr().err
