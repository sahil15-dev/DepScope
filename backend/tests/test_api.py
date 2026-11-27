import asyncio
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from time import monotonic, sleep
from uuid import uuid4

import httpx
import pytest
from depscope.models import Assessment, Coordinate, LookupStatus, Provenance
from depscope.service.api import create_app
from depscope.settings import Settings
from depscope.storage.database import sqlite_engine
from depscope.storage.repository import ScanRepository
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from .test_storage import SAMPLE, migrate

_LIVE = {"format": "requirements", "source": "paste", "live": "true"}
_HEADERS = {"Content-Type": "text/plain; charset=utf-8"}
_BASE = "http://localhost:8000"


class LocalProvider:
    provenance = Provenance.LIVE_OSV

    def __init__(self, *, blocked: bool = False, fail: bool = False) -> None:
        self.ready = Event()
        self.release = Event()
        self.blocked = blocked
        self.fail = fail
        self.active = 0
        self.peak = 0
        self.queries: list[tuple[Coordinate, ...]] = []

    async def lookup(self, coordinates: Iterable[Coordinate]) -> tuple[Assessment, ...]:
        keys = tuple(coordinates)
        self.queries.append(keys)
        self.active += 1
        self.peak = max(self.peak, self.active)
        self.ready.set()
        try:
            while self.blocked and not self.release.is_set():
                await asyncio.sleep(0.01)
            if self.fail:
                return tuple(
                    Assessment(key, LookupStatus.FAILED, diagnostics=("request_failed",))
                    for key in keys
                )
            return tuple(Assessment(key, LookupStatus.COMPLETE) for key in keys)
        finally:
            self.active -= 1


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "api.sqlite3"
    engine = sqlite_engine(path)
    migrate(engine)
    engine.dispose()
    return path


def wait_finished(client: TestClient, location: str) -> dict[str, object]:
    deadline = monotonic() + 5
    while monotonic() < deadline:
        result = client.get(location)
        result.raise_for_status()
        payload: dict[str, object] = result.json()
        if result.json()["scan"]["status"] in ("complete", "partial", "failed"):
            return payload
        sleep(0.015)
    pytest.fail(f"Scan did not reach a terminal status at {location}")


def _sample(client: TestClient, identifier: str) -> str:
    submission: httpx.Response = client.post("/api/scans", params={"sample_id": identifier})
    assert submission.status_code == 202, submission.text
    location = submission.headers["Location"]
    assert submission.json() == {
        "id": location.rsplit("/", 1)[-1],
        "status": "queued",
        "status_url": location,
    }
    return location


def test_scan_endpoints_filter_pagination_and_provenance(db_path: Path) -> None:
    live = LocalProvider()
    with TestClient(
        create_app(Settings(database_path=db_path), live_provider=live), base_url=_BASE
    ) as client:
        assert client.get("/api/health").json() == {"status": "ready", "database": "ready"}
        assert client.get("/openapi.json").json()["paths"]["/api/scans"]["post"]["requestBody"][
            "content"
        ]
        assert client.get("/api/scans").json()["total"] == 0
        assert client.get("/api/overview").json()["latest_result"] is None

        partial = _sample(client, "python-partial")
        partial_report = wait_finished(client, partial)
        detail = client.get(partial, params={"page_size": 1, "page": 2}).json()
        assert detail["scan"]["status"] == "partial"
        assert detail["scan"]["provenance"] == "offline_fixture"
        assert detail["scan"]["coverage"]["partial_coordinates"] == 1
        assert detail["dependencies"]["total"] == 2 and len(detail["dependencies"]["items"]) == 1
        assert detail["assessments"]["total"] == 2 and len(detail["assessments"]["items"]) == 1

        finding_page = client.get(partial + "/findings", params={"page_size": 1}).json()
        finding = finding_page["items"][0]["finding"]
        assert finding_page["total"] == 2
        assert finding["fixes"][0]["version"] == "3.1.3"
        assert "GHSA-h5c8-rqwp-cp95" in finding_page["advisories"]
        discovery = client.get(
            partial + "/findings",
            params={"severity": "unknown", "fix_available": "false", "sort": "package"},
        ).json()
        assert discovery["items"][0]["observations"][0]["error_code"] == "advisory_not_found"
        assert discovery["advisories"] == {}
        assert client.get(partial + "/findings", params={"ecosystem": "npm"}).json()["total"] == 0
        assert client.get(partial + "/findings", params={"package": "%"}).json()["total"] == 0
        assert (
            client.get(
                partial + "/findings", params={"package": "jinja", "fix_available": "true"}
            ).json()["total"]
            == 1
        )

        npm = _sample(client, "npm-vulnerable")
        wait_finished(client, npm)
        raw = client.post("/api/scans", params=_LIVE, content=b"other==1", headers=_HEADERS)
        assert raw.status_code == 202
        wait_finished(client, raw.headers["Location"])
        assert len(live.queries) == 1

        history = client.get(
            "/api/scans", params={"provenance": "offline_fixture", "sort": "risk", "page_size": 1}
        ).json()
        assert history["total"] == 2
        assert history["items"][0]["id"] == npm.rsplit("/", 1)[1]
        history = client.get(
            "/api/scans", params={"sort": "oldest", "status": "partial", "format": "requirements"}
        ).json()
        assert history["items"] == [partial_report["scan"]]
        assert client.get(npm + "/findings").json()["total"] == 1
        live_overview = client.get("/api/overview").json()
        assert live_overview["status_counts"]["complete"] == 1
        assert live_overview["latest_result"]["provenance"] == "live_osv"
        demo_overview = client.get(
            "/api/overview", params={"provenance": "offline_fixture", "limit": 1}
        ).json()
        assert demo_overview["status_counts"]["partial"] == 1
        assert len(demo_overview["risk_trend"]) == 1
        assert demo_overview["latest_result"]["id"] == npm.rsplit("/", 1)[1]


def test_validation_security_and_no_raw_manifest_in_database(
    db_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    live = LocalProvider()
    text_input = b"public==1\n-r ../phase2-private-path.txt\nother @ https://user:phase2-secret@invalid.invalid/a"
    with TestClient(
        create_app(Settings(database_path=db_path, max_file_bytes=160), live_provider=live),
        base_url=_BASE,
    ) as client:
        unavailable = client.get(f"/api/scans/{uuid4()}")
        assert (
            unavailable.status_code == 404
            and unavailable.json()["error"]["code"] == "scan_not_found"
        )
        assert client.get(f"/api/scans/{uuid4()}/findings").status_code == 404
        assert client.get("/api/scans/phase2-secret").json()["error"]["code"] == "invalid_request"
        assert client.get("/api/scans", params={"page_size": 51}).status_code == 422
        assert (
            client.get("/api/health", headers={"Host": "phase2-secret.invalid"}).json()["error"][
                "code"
            ]
            == "invalid_host"
        )
        assert (
            client.post(
                "/api/scans",
                params=_LIVE,
                headers={**_HEADERS, "Origin": "https://invalid.invalid"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/scans", params={"sample_id": "../../phase2-private-path.txt"}
            ).status_code
            == 422
        )
        assert (
            client.post("/api/scans", params={"sample_id": "python-clean"}, content=b"X").json()[
                "error"
            ]["code"]
            == "unexpected_body"
        )
        assert (
            client.post("/api/scans", params={"sample_id": "python-clean", **_LIVE}).status_code
            == 422
        )
        assert (
            client.post(
                "/api/scans", params={"source": "paste", "format": "requirements"}
            ).status_code
            == 422
        )
        assert client.post("/api/scans", params=_LIVE, json={"body": "invalid"}).status_code == 415
        assert (
            client.post(
                "/api/scans", params=_LIVE, headers={**_HEADERS, "Content-Encoding": "gzip"}
            ).status_code
            == 415
        )
        assert (
            client.post(
                "/api/scans", params=_LIVE, headers=_HEADERS, content=b"X" * 161
            ).status_code
            == 413
        )
        assert (
            client.post(
                "/api/scans", params=_LIVE, headers=_HEADERS, content=iter([b"X" * 81, b"Y" * 80])
            ).status_code
            == 413
        )
        assert (
            client.post(
                "/api/scans",
                params=_LIVE,
                headers={**_HEADERS, "Content-Length": "2"},
                content=b"X",
            ).status_code
            == 400
        )
        assert client.get("/api/scans").json()["total"] == 0

        accepted = client.post(
            "/api/scans", params=_LIVE, headers={**_HEADERS, "Origin": _BASE}, content=text_input
        )
        assert accepted.status_code == 202
        assert accepted.headers["access-control-expose-headers"] == "Location, Retry-After"
        wait_finished(client, accepted.headers["Location"])
        report = client.get(accepted.headers["Location"])
        assert report.json()["scan"]["coverage"]["unresolved_occurrences"] == 2
        assert [coordinate.name for coordinate in live.queries[0]] == ["public"]
        assert "phase2-secret" not in report.text
    for search in (b"phase2-secret", b"phase2-private-path", text_input):
        assert search not in db_path.read_bytes()
        assert search.decode() not in caplog.text


def test_concurrent_submissions_and_queue_recovery(db_path: Path) -> None:
    live = LocalProvider(blocked=True)
    settings = Settings(database_path=db_path, max_pending_jobs=1)
    with TestClient(create_app(settings, live_provider=live), base_url=_BASE) as client:

        def submit() -> httpx.Response:
            response: httpx.Response = client.post(
                "/api/scans", params=_LIVE, headers=_HEADERS, content=b"alpha==1"
            )
            return response

        first = submit()
        assert first.status_code == 202 and live.ready.wait(3)
        assert client.get(first.headers["Location"]).json()["scan"]["status"] == "running"
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(lambda _: submit(), range(4)))
        assert sorted(response.status_code for response in responses) == [202, 503, 503, 503]
        second = next(response for response in responses if response.status_code == 202)
        denied = next(response for response in responses if response.status_code == 503)
        assert denied.json()["error"]["code"] == "scan_queue_full"
        assert client.get(second.headers["Location"]).json()["scan"]["status"] == "queued"
        live.release.set()
        for response in (first, second):
            wait_finished(client, response.headers["Location"])
        assert live.peak == 1 and len(live.queries) == 2


def test_rate_limit_and_advisory_failure_diagnostics(db_path: Path) -> None:
    live = LocalProvider(fail=True)
    with TestClient(
        create_app(Settings(database_path=db_path, submissions_per_minute=1), live_provider=live),
        base_url=_BASE,
    ) as client:
        accepted = client.post("/api/scans", params=_LIVE, headers=_HEADERS, content=b"alpha==1")
        assert accepted.status_code == 202
        wait_finished(client, accepted.headers["Location"])
        detail = client.get(accepted.headers["Location"]).json()
        assert detail["scan"]["error_code"] == "advisory_lookup_failed"
        assert detail["scan"]["risk_index"] is None
        assert detail["assessments"]["items"][0]["diagnostics"] == ["request_failed"]
        limited = client.post("/api/scans", params={"sample_id": "python-clean"})
        assert limited.status_code == 429 and int(limited.headers["Retry-After"]) > 0
        assert limited.json()["error"]["code"] == "submission_rate_limited"


def test_job_timeout_cancels_lookup_and_releases_capacity(db_path: Path) -> None:
    live = LocalProvider(blocked=True)
    settings = Settings(database_path=db_path, max_pending_jobs=0, job_timeout=1)
    with TestClient(create_app(settings, live_provider=live), base_url=_BASE) as client:
        accepted = client.post("/api/scans", params=_LIVE, headers=_HEADERS, content=b"a==1")
        assert accepted.status_code == 202 and live.ready.wait(3)
        assert client.post("/api/scans", params={"sample_id": "python-clean"}).status_code == 503
        wait_finished(client, accepted.headers["Location"])
        assert (
            client.get(accepted.headers["Location"]).json()["scan"]["error_code"] == "job_timeout"
        )
        assert live.active == 0
        clean = _sample(client, "python-clean")
        wait_finished(client, clean)
        assert client.get(clean).json()["scan"]["status"] == "complete"


def test_restart_reconciles_pending_jobs_and_preserves_terminal_results(db_path: Path) -> None:
    settings = Settings(database_path=db_path)
    live = LocalProvider(blocked=True)
    with TestClient(create_app(settings, live_provider=live), base_url=_BASE) as client:
        complete = _sample(client, "python-vulnerable")
        saved = wait_finished(client, complete)
        saved_findings = client.get(complete + "/findings").json()
        assert saved_findings["total"] == 1
        assert saved_findings["items"][0]["finding"]["fixes"][0]["version"] == "3.1.3"
        active = client.post("/api/scans", params=_LIVE, headers=_HEADERS, content=b"active==1")
        assert active.status_code == 202 and live.ready.wait(3)
        queued = _sample(client, "python-vulnerable")
        with (
            pytest.raises(RuntimeError, match="Another DepScope worker"),
            TestClient(create_app(settings), base_url=_BASE),
        ):
            pytest.fail("Concurrent worker startup should fail")
    engine = sqlite_engine(db_path)
    repository = ScanRepository(engine)
    abandoned = repository.create(SAMPLE)
    running = repository.create(SAMPLE)
    repository.start(running.id)
    engine.dispose()

    with TestClient(create_app(settings), base_url=_BASE) as client:
        for location in (
            active.headers["Location"],
            queued,
            f"/api/scans/{abandoned.id}",
            f"/api/scans/{running.id}",
        ):
            scan = client.get(location).json()["scan"]
            assert (scan["status"], scan["error_code"], scan["coverage"]) == (
                "failed",
                "interrupted",
                None,
            )
        assert client.get(complete).json() == saved
        assert client.get(complete + "/findings").json() == saved_findings
        assert client.get("/api/health").status_code == 200


def test_database_errors_rollback_and_hide_internal_details(
    db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = sqlite_engine(db_path)
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TRIGGER reject_finding BEFORE INSERT ON findings "
            "BEGIN SELECT RAISE(ABORT, 'phase2-secret'); END"
        )
    engine.dispose()
    with TestClient(create_app(Settings(database_path=db_path)), base_url=_BASE) as client:
        stopped = _sample(client, "python-vulnerable")
        wait_finished(client, stopped)
        report = client.get(stopped).json()
        assert report["scan"]["error_code"] == "storage_failure"
        assert report["dependencies"]["total"] == 0
        assert client.get(stopped + "/findings").json()["total"] == 0
        clean = _sample(client, "python-clean")
        wait_finished(client, clean)
        assert client.get(clean).json()["scan"]["status"] == "complete"

        def broken(*args: object, **kwargs: object) -> None:
            raise SQLAlchemyError("phase2-secret")

        monkeypatch.setattr(ScanRepository, "list_scans", broken)
        error = client.get("/api/scans")
        assert error.status_code == 503 and "phase2-secret" not in error.text


def test_malformed_manifest_and_bad_database_revision(db_path: Path) -> None:
    with TestClient(create_app(Settings(database_path=db_path)), base_url=_BASE) as client:
        result = client.post(
            "/api/scans",
            params={**_LIVE, "format": "npm-lock"},
            headers={"Content-Type": "application/json"},
            content=b"{",
        )
        assert result.status_code == 202
        wait_finished(client, result.headers["Location"])
        assert (
            client.get(result.headers["Location"]).json()["scan"]["error_code"]
            == "invalid_lockfile"
        )
        engine = sqlite_engine(db_path)
        with engine.begin() as connection:
            connection.execute(text("UPDATE alembic_version SET version_num='unknown'"))
        engine.dispose()
        assert client.get("/api/health").status_code == 503
    with (
        pytest.raises(RuntimeError, match="Upgrade the DepScope database"),
        TestClient(create_app(Settings(database_path=db_path)), base_url=_BASE),
    ):
        pytest.fail("An incompatible schema should prevent startup")
