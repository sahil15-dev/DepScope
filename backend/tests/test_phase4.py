import asyncio
import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from depscope.matching import match_assessment
from depscope.models import (
    Assessment,
    Coordinate,
    Ecosystem,
    LookupStatus,
    ManifestFormat,
    Observation,
    Provenance,
)
from depscope.scanner import Scanner
from depscope.scoring import summarize_risk
from depscope.service.api import create_app
from depscope.settings import Settings
from depscope.storage.database import sqlite_engine
from depscope.storage.models import ScanSource
from depscope.storage.repository import ScanInput, ScanRepository
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from .helpers import ALPHA, BETA
from .test_api import LocalProvider, wait_finished
from .test_scanner import Provider, _observation, _package, _range
from .test_storage import migrate

_FIX = _range({"introduced": "0"}, {"fixed": "1.2"})
_ALPHA_NEW = Coordinate(Ecosystem.PYPI, "alpha", "1.2")


@pytest.fixture
def database(tmp_path: Path) -> Iterator[tuple[Path, Engine]]:
    path = tmp_path / "phase4.sqlite3"
    engine = sqlite_engine(path)
    try:
        migrate(engine)
        yield path, engine
    finally:
        engine.dispose()


def _live_scan(
    engine: Engine,
    content: bytes,
    *assessments: Assessment,
    manifest_format: ManifestFormat = ManifestFormat.REQUIREMENTS,
) -> str:
    class LiveFixture(Provider):
        provenance = Provenance.LIVE_OSV

    repository = ScanRepository(engine)
    scan = repository.create(ScanInput(manifest_format, ScanSource.PASTE, Provenance.LIVE_OSV))
    repository.start(scan.id)
    result = asyncio.run(Scanner(LiveFixture(*assessments)).scan(content, manifest_format))
    repository.finish(scan.id, result)
    return scan.id


def _affected() -> Assessment:
    return Assessment(
        ALPHA,
        LookupStatus.COMPLETE,
        (
            _observation(
                "TEST-ALPHA",
                aliases=["CVE-TEST-1"],
                affected=[_package(ranges=[_FIX])],
                database_specific={"severity": "HIGH"},
            ),
            _observation("TEST-OTHER", database_specific={"severity": "LOW"}),
        ),
    )


def test_package_paging_filters_and_report_totals(database: tuple[Path, Engine]) -> None:
    path, engine = database
    affected = _affected()
    withdrawn: Observation = _observation("TEST-WITHDRAWN", withdrawn="2025-01-01T00:00:00Z")
    identifier = _live_scan(
        engine,
        b"Alpha==1.0\nbeta==2\ngamma>=1",
        Assessment(ALPHA, LookupStatus.COMPLETE, (*affected.observations, withdrawn)),
        Assessment(
            BETA,
            LookupStatus.COMPLETE,
            (_observation("TEST-BETA", "beta", affected=[_package(name="beta", versions=["2"])]),),
        ),
    )
    with TestClient(
        create_app(Settings(database_path=path)), base_url="http://localhost:8000"
    ) as client:
        base = f"/api/scans/{identifier}"
        groups = client.get(base + "/packages?page_size=1&sort=findings").raise_for_status().json()
        assert (groups["total"], groups["finding_count"], groups["fixable_count"]) == (2, 3, 1)
        (alpha,) = groups["items"]
        assert (
            alpha["coordinate"]["version"],
            alpha["highest_severity"],
            alpha["severity_counts"]["low"],
        ) == ("1", "high", 1)
        page2 = client.get(base + "/packages?page_size=1&page=2").raise_for_status().json()
        assert page2["items"][0]["coordinate"]["name"] == "beta"
        assert client.get(base + "/packages?severity=low&fix_available=true").json()["total"] == 0
        assert client.get(base + "/packages?package=%25").json()["total"] == 0
        findings = (
            client.get(base + "/findings?ecosystem=PyPI&name=alpha&version=1")
            .raise_for_status()
            .json()
        )
        assert findings["total"] == 2
        review = client.get(base + "/review").raise_for_status().json()
        assert review["total"] == 1 and review["items"][0]["name"] == "gamma"
        response = client.get(base + "/report?download=true").raise_for_status()
        report = response.json()
        assert (
            response.headers["content-disposition"]
            == f'attachment; filename="depscope-{identifier}.json"'
        )
        assert response.headers["cache-control"] == "no-store"
        assert (
            sum(item["finding_count"] for item in report["packages"])
            == sum(report["scan"]["severity_counts"].values())
            == 3
        )
        assert report["packages"][0]["findings"] == findings["items"]
        assert report["advisories"]["TEST-WITHDRAWN"]["withdrawn"] is not None
        assert any(
            item["discovery"]["id"] == "TEST-WITHDRAWN"
            for item in report["assessments"][0]["observations"]
        )
        assert report["scan"]["coverage"]["unresolved_occurrences"] == review["total"]
        assert "Alpha==1.0" not in response.text


def test_upgrade_checks_use_latest_same_source_complete_lookup(
    database: tuple[Path, Engine],
) -> None:
    path, engine = database
    origin = _live_scan(engine, b"alpha==1", _affected())
    with TestClient(
        create_app(Settings(database_path=path)), base_url="http://localhost:8000"
    ) as client:
        url = f"/api/scans/{origin}/candidates?ecosystem=PyPI&name=Alpha&version=1.0"
        assert client.get(url).json()[0]["evidence"] == "insufficient_evidence"
        verified = _live_scan(engine, b"alpha==1.2", Assessment(_ALPHA_NEW, LookupStatus.COMPLETE))
        candidate = client.get(url).raise_for_status().json()[0]
        assert (candidate["evidence"], candidate["finding_count"], candidate["scan_id"]) == (
            "no_known_findings",
            0,
            verified,
        )
        _live_scan(engine, b"alpha==1.2", Assessment(_ALPHA_NEW, LookupStatus.FAILED))
        assert client.get(url).json()[0]["evidence"] == "insufficient_evidence"
        _live_scan(
            engine,
            b"Alpha==1.2.0",
            Assessment(
                _ALPHA_NEW,
                LookupStatus.COMPLETE,
                (_observation("TEST-STILL", affected=[_package(versions=["1.2"])]),),
            ),
        )
        assert client.get(url).json()[0]["evidence"] == "known_findings"
        assert client.get(url.replace("version=1.0", "version=%3E1")).status_code == 422


def test_comparison_identity_severity_and_coverage(database: tuple[Path, Engine]) -> None:
    path, engine = database
    before = _live_scan(
        engine, b"alpha==1\nbeta==2", _affected(), Assessment(BETA, LookupStatus.COMPLETE)
    )
    gamma = Coordinate(Ecosystem.PYPI, "gamma", "3")
    after = _live_scan(
        engine,
        b"gamma==3\nAlpha==1.2.0\nalpha>=1",
        Assessment(
            gamma,
            LookupStatus.COMPLETE,
            (
                _observation(
                    "TEST-GAMMA", "gamma", affected=[_package(name="gamma", versions=["3"])]
                ),
            ),
        ),
        Assessment(
            _ALPHA_NEW,
            LookupStatus.COMPLETE,
            (
                _observation(
                    "CVE-TEST-1",
                    aliases=["TEST-ALPHA"],
                    affected=[_package(versions=["1.2"])],
                    database_specific={"severity": "CRITICAL"},
                ),
            ),
        ),
    )
    with TestClient(
        create_app(Settings(database_path=path)), base_url="http://localhost:8000"
    ) as client:
        url = f"/api/scans/{before}/comparison/{after}"
        comparison = client.get(url).raise_for_status().json()
        assert comparison["risk_delta"] == 9
        assert {item["kind"] for item in comparison["dependencies"]} == {
            "added",
            "removed",
            "changed",
        }
        unchanged = next(item for item in comparison["findings"] if item["kind"] == "unchanged")
        assert (
            unchanged["before_severity"],
            unchanged["after_severity"],
            unchanged["context"],
        ) == ("high", "critical", "versions_changed")
        missing = next(
            item for item in comparison["findings"] if item["kind"] == "no_longer_detected"
        )
        assert missing["context"] == "incomplete_coverage"
        assert (
            next(item for item in comparison["findings"] if item["kind"] == "newly_detected")[
                "context"
            ]
            == "package_absent"
        )
        fixture = client.post("/api/scans?sample_id=python-clean").raise_for_status().json()["id"]
        assert client.get(f"/api/scans/{before}/comparison/{fixture}").status_code == 409


def test_comparison_rejects_a_failure_without_inventory(database: tuple[Path, Engine]) -> None:
    path, engine = database
    good = _live_scan(engine, b"alpha==1", _affected())
    repository = ScanRepository(engine)
    interrupted = repository.create(
        ScanInput(ManifestFormat.REQUIREMENTS, ScanSource.UPLOAD, Provenance.LIVE_OSV)
    )
    repository.fail(interrupted.id, "interrupted")
    with TestClient(
        create_app(Settings(database_path=path)), base_url="http://localhost:8000"
    ) as client:
        compare = client.get(f"/api/scans/{good}/comparison/{interrupted.id}")
        assert compare.status_code == 409
        assert compare.json()["error"]["code"] == "scan_result_unavailable"
        report = client.get(f"/api/scans/{interrupted.id}/report").raise_for_status().json()
        assert report["scan"]["error_code"] == "interrupted"
        assert report["scan"]["coverage"] is None


def test_pillow_explicit_version_outside_fixed_interval() -> None:
    pillow = Coordinate(Ecosystem.PYPI, "pillow", "8.2")
    observation = _observation(
        "PYSEC-2022-42980",
        "pillow",
        aliases=["CVE-2022-45199"],
        affected=[
            _package(
                name="pillow",
                versions=["8.2.0", "9.2.0"],
                ranges=[
                    _range({"introduced": "9.2.0"}, {"fixed": "9.3.0"}),
                ],
            ),
        ],
    )
    assessment, (finding,) = match_assessment(
        Assessment(pillow, LookupStatus.COMPLETE, (observation,))
    )
    assert assessment.status == LookupStatus.COMPLETE
    assert finding.evidence_level == "hydrated" and finding.fixes == ()


@pytest.mark.parametrize(("count", "expected"), [(1, 10), (9, 90), (10, 100), (40, 100)])
def test_scoring_cap_preserves_revision_one(count: int, expected: int) -> None:
    _, findings = match_assessment(_affected())
    high = next(item for item in findings if item.advisory_id == "TEST-ALPHA")
    assert summarize_risk([high] * count, 1).index == expected


def test_groups_preserve_distinct_lockfile_versions(database: tuple[Path, Engine]) -> None:
    path, engine = database
    versions = ["1.2.0", "2.3.0"]
    lockfile = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/alpha": {"version": versions[0]},
                "node_modules/parent/node_modules/alpha": {"version": versions[1]},
            },
        }
    ).encode()
    observation = _observation(
        "GHSA-TEST",
        aliases=["CVE-TEST"],
        affected=[_package(ecosystem="npm", versions=versions)],
    )
    scan_id = _live_scan(
        engine,
        lockfile,
        *(
            Assessment(
                Coordinate(Ecosystem.NPM, "alpha", version), LookupStatus.COMPLETE, (observation,)
            )
            for version in versions
        ),
        manifest_format=ManifestFormat.NPM_LOCK,
    )
    with TestClient(
        create_app(Settings(database_path=path)), base_url="http://localhost:8000"
    ) as client:
        groups = client.get(f"/api/scans/{scan_id}/packages?sort=package").raise_for_status().json()
        assert groups["total"] == 2
        assert [
            (row["coordinate"]["version"], row["finding_count"]) for row in groups["items"]
        ] == [(version, 1) for version in versions]


def test_upload_bytes_normalize_without_persisting_the_body(database: tuple[Path, Engine]) -> None:
    path, engine = database
    engine.dispose()
    provider = LocalProvider()
    marker = b"unpersisted body marker"
    with TestClient(
        create_app(Settings(database_path=path), live_provider=provider),
        base_url="http://localhost:8000",
    ) as client:
        response = client.post(
            "/api/scans",
            params={"format": "requirements", "source": "upload", "live": "true"},
            headers={"Content-Type": "text/plain; charset=utf-8"},
            content=b"\xef\xbb\xbfMy_Package==1.2.0\r\nother>=2\r\n# " + marker + b"\r\n",
        )
        location = response.raise_for_status().headers["Location"]
        wait_finished(client, location)
        report = client.get(f"{location}/report").raise_for_status().json()
        assert provider.queries == [(Coordinate(Ecosystem.PYPI, "my-package", "1.2"),)]
        assert report["scan"]["coverage"]["exact_coordinates"] == 1
        assert report["scan"]["coverage"]["unresolved_occurrences"] == 1
    assert marker not in path.read_bytes()
